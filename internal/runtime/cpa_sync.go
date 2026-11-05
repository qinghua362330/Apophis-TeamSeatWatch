package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
)

// cpaSyncInterval is how often the credential inventory is refreshed. The sync is
// read-only against CPA, so a short interval is safe; a failure never blocks it.
const cpaSyncInterval = 2 * time.Minute

// cpaCredentialName is the selector CPA uses to address one auth file. The auth
// index is preferred because it advances when CPA re-registers a credential.
func cpaCredentialID(file cpacred.File) string {
	if index := strings.TrimSpace(file.AuthIndex); index != "" {
		return "name:" + file.Name + "#index:" + index
	}
	return "name:" + file.Name
}

// observedRevision commits to the non-secret attributes a credential had when it
// was observed. A regenerated credential therefore shows up as a new revision
// instead of silently inheriting the previous one's history.
func observedRevision(file cpacred.File) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		file.Name, file.AuthIndex, file.Provider, file.Status,
		boolToken(file.Disabled), file.Email,
	}, "\x00")))
	return hex.EncodeToString(digest[:])
}

func boolToken(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// syncCPACredentialInventory records what CPA currently serves. Credentials that
// disappear are marked absent rather than deleted, so a case that references one
// keeps a coherent history.
func (h *OwnerAuthHandler) syncCPACredentialInventory(ctx context.Context) (int, error) {
	if h.cpaCredentials == nil {
		return 0, cpacred.ErrNotConfigured
	}
	syncCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	files, err := h.cpaCredentials.List(syncCtx)
	if err != nil {
		return 0, err
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	runID := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO tsw_cpa_sync_runs(id) VALUES($1)`, runID); err != nil {
		return 0, err
	}
	seen := make([]string, 0, len(files))
	for _, file := range files {
		credentialID := cpaCredentialID(file)
		var emailHMAC []byte
		var keyVersion *uint16
		if email := strings.TrimSpace(file.Email); email != "" {
			_, version, fingerprint, fingerprintErr := identity.Fingerprint(h.keyRing, identity.TargetLogin, email)
			if fingerprintErr != nil {
				return 0, fingerprintErr
			}
			emailHMAC = fingerprint[:]
			keyVersion = &version
		}
		seen = append(seen, credentialID)
		if _, err = tx.Exec(ctx, `INSERT INTO tsw_cpa_credentials(credential_id,credential_name,provider,observed_revision,email_hmac,email_key_version,disabled,remote_status,present,last_observed_at,last_sync_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,now(),$9)
			ON CONFLICT(credential_id) DO UPDATE SET
				credential_name=EXCLUDED.credential_name,
				provider=EXCLUDED.provider,
				observed_revision=EXCLUDED.observed_revision,
				email_hmac=EXCLUDED.email_hmac,
				email_key_version=EXCLUDED.email_key_version,
				disabled=EXCLUDED.disabled,
				remote_status=EXCLUDED.remote_status,
				present=true,
				last_observed_at=now(),
				last_sync_id=EXCLUDED.last_sync_id`,
			credentialID, file.Name, file.Provider, observedRevision(file), emailHMAC, keyVersion, file.Disabled, nullableText(file.Status), runID); err != nil {
			return 0, err
		}
	}
	// Anything not in this snapshot is reported absent, never removed.
	if _, err = tx.Exec(ctx, `UPDATE tsw_cpa_credentials SET present=false,last_sync_id=$2,last_observed_at=last_observed_at
		WHERE present AND NOT (credential_id=ANY($1))`, seen, runID); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_cpa_sync_runs SET finished_at=now(),outcome='succeeded',credential_count=$2 WHERE id=$1`, runID, len(files)); err != nil {
		return 0, err
	}
	return len(files), tx.Commit(ctx)
}

// recordCPASyncFailure keeps a failed refresh visible without discarding the last
// good observation set.
func (h *OwnerAuthHandler) recordCPASyncFailure(ctx context.Context, err error) {
	if _, recordErr := h.pool.Exec(ctx, `INSERT INTO tsw_cpa_sync_runs(finished_at,outcome,error_code)
		VALUES(now(),'failed',$1)`, cpaSyncErrorCode(err)); recordErr != nil {
		slog.ErrorContext(ctx, "cpa_sync_failure_record_failed", "error", recordErr)
	}
}

func cpaSyncErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, cpacred.ErrNotConfigured):
		return "cpa_management_unconfigured"
	default:
		return "cpa_inventory_unavailable"
	}
}

// runCPASyncLoop refreshes the inventory on a fixed cadence until shutdown.
func (h *OwnerAuthHandler) runCPASyncLoop(ctx context.Context) {
	if h.cpaCredentials == nil {
		return
	}
	ticker := time.NewTicker(cpaSyncInterval)
	defer ticker.Stop()
	sync := func() {
		if _, err := h.syncCPACredentialInventory(ctx); err != nil {
			h.recordCPASyncFailure(ctx, err)
			slog.WarnContext(ctx, "cpa_inventory_sync_failed", "error", err)
			return
		}
		// 401 recovery is a separate durable queue. Enqueue only after the
		// inventory transaction commits, and never create a degradation case here.
		if h.cpaCredentials != nil {
			files, err := h.cpaCredentials.List(ctx)
			if err != nil {
				slog.WarnContext(ctx, "cpa_reauthorization_inventory_failed", "error", err)
			} else if err := h.enqueueCPAReauthorizations(ctx, files); err != nil {
				slog.WarnContext(ctx, "cpa_reauthorization_enqueue_failed", "error", err)
			}
		}
	}
	sync()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sync()
		}
	}
}

// lookupCPACredentialIdentity reports the observed CPA credential that carries the
// same identity fingerprint. It never returns a token, only the observation.
func lookupCPACredentialIdentity(ctx context.Context, tx pgx.Tx, keyVersion uint16, fingerprint []byte) (string, string, error) {
	var credentialID, provider string
	err := tx.QueryRow(ctx, `SELECT credential_id,provider FROM tsw_cpa_credentials
		WHERE email_key_version=$1 AND email_hmac=$2 AND present AND NOT disabled`, keyVersion, fingerprint).Scan(&credentialID, &provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	return credentialID, provider, err
}

func nullableText(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}
