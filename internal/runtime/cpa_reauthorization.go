package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
)

const cpaReauthorizationInterval = 30 * time.Second

var errCPAReauthorizationSuperseded = errors.New("CPA reauthorization source superseded")

type cpaCredentialIdentityReader interface {
	CredentialIdentity(context.Context, string) (cpacred.File, error)
}

func (h *OwnerAuthHandler) cpaRenewalIdentity(ctx context.Context, file cpacred.File) (cpacred.File, error) {
	reader, ok := h.cpaCredentials.(cpaCredentialIdentityReader)
	if !ok {
		return cpacred.File{}, cpacred.ErrNotConfigured
	}
	actual, err := reader.CredentialIdentity(ctx, file.Name)
	if err != nil {
		return cpacred.File{}, err
	}
	if actual.Provider != "codex" || actual.AccountID == "" || actual.Revision == "" || !strings.EqualFold(actual.Email, file.Email) {
		return cpacred.File{}, cpacred.ErrCredentialIdentityMismatch
	}
	return actual, nil
}

// Only authoritative credential failures on imported, enabled Codex accounts
// create renewal work. This queue has no membership mutation path.
func (h *OwnerAuthHandler) enqueueCPAReauthorizations(ctx context.Context, files []cpacred.File) error {
	for _, file := range files {
		if file.Provider != "codex" || file.Disabled || !file.Unauthorized() || file.Email == "" {
			continue
		}
		_, version, fp, err := identity.Fingerprint(h.keyRing, identity.TargetLogin, file.Email)
		if err != nil {
			return err
		}
		var target uuid.UUID
		var revision int64
		err = h.pool.QueryRow(ctx, `SELECT a.id,t.secret_revision FROM tsw_target_accounts a
   JOIN tsw_target_credentials t ON t.target_account_id=a.id AND t.materials_sealed AND t.material_status='complete'
   WHERE a.identifier_key_version=$1 AND a.identifier_hmac=$2 AND a.status='active'
   AND NOT EXISTS(SELECT 1 FROM tsw_cpa_rotation_deliveries d WHERE d.credential_name=$3 AND d.kind='quarantine')
   AND NOT EXISTS(SELECT 1 FROM tsw_cpa_reauthorizations r WHERE r.credential_name=$3 AND
     (r.status IN ('pending','running','failed') OR r.completed_at>now()-interval '10 minutes'))`, version, fp[:], file.Name).Scan(&target, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		actual, err := h.cpaRenewalIdentity(ctx, file)
		if err != nil {
			return err
		}
		_, err = h.pool.Exec(ctx, `INSERT INTO tsw_cpa_reauthorizations(credential_id,credential_name,remote_revision,workspace_id,target_account_id,source_secret_revision)
    VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(credential_name,remote_revision) DO NOTHING`, cpaCredentialID(file), file.Name, actual.Revision, actual.AccountID, target, revision)
		if err != nil {
			return err
		}
	}
	return nil
}

type cpaReauthorizationWork struct {
	ID, Target, Lease                             uuid.UUID
	CredentialID, Name, Workspace, RemoteRevision string
	Attempts                                      int
	SourceRevision                                int64
}

func (h *OwnerAuthHandler) claimCPAReauthorization(ctx context.Context) (cpaReauthorizationWork, bool, error) {
	var w cpaReauthorizationWork
	w.Lease = uuid.New()
	err := h.pool.QueryRow(ctx, `WITH candidate AS (
  SELECT id FROM tsw_cpa_reauthorizations WHERE attempts<3 AND
   ((status IN ('pending','failed') AND next_attempt_at<=now()) OR (status='running' AND lease_expires_at<now()))
  ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1
 ) UPDATE tsw_cpa_reauthorizations r SET status='running',lease_owner=$1,lease_expires_at=now()+interval '5 minutes',
  started_at=COALESCE(started_at,now()),attempts=attempts+1,updated_at=now()
 FROM candidate WHERE r.id=candidate.id
 RETURNING r.id,r.target_account_id,r.credential_id,r.credential_name,r.workspace_id,r.remote_revision,r.source_secret_revision,r.attempts`, w.Lease).Scan(&w.ID, &w.Target, &w.CredentialID, &w.Name, &w.Workspace, &w.RemoteRevision, &w.SourceRevision, &w.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, false, nil
	}
	return w, err == nil, err
}

func (h *OwnerAuthHandler) finishCPAReauthorization(ctx context.Context, w cpaReauthorizationWork, result error) {
	status, code := "succeeded", ""
	if errors.Is(result, errCPAReauthorizationSuperseded) {
		status = "superseded"
	} else if result != nil {
		status = "failed"
		code = "cpa_reauthorization_failed"
		if w.Attempts >= 3 {
			status = "blocked"
		}
	}
	backoff := time.Duration(1<<min(w.Attempts, 6)) * time.Minute
	_, err := h.pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET status=$3,lease_owner=NULL,lease_expires_at=NULL,
  completed_at=CASE WHEN $3 IN ('succeeded','superseded','blocked') THEN now() ELSE NULL END,
  next_attempt_at=now()+($4*interval '1 second'),last_error_code=$5,updated_at=now()
  WHERE id=$1 AND status='running' AND lease_owner=$2 AND lease_expires_at>clock_timestamp()`, w.ID, w.Lease, status, int(backoff.Seconds()), nullableText(code))
	if err != nil {
		slog.WarnContext(ctx, "cpa_reauthorization_commit_failed", "error", err)
	}
}

func (h *OwnerAuthHandler) checkCPAReauthorizationLease(ctx context.Context, w cpaReauthorizationWork) error {
	var valid bool
	err := h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_cpa_reauthorizations r
  JOIN tsw_target_accounts a ON a.id=r.target_account_id AND a.status='active'
  JOIN tsw_target_credentials t ON t.target_account_id=a.id AND t.secret_revision=r.source_secret_revision AND t.materials_sealed AND t.material_status='complete'
  WHERE r.id=$1 AND r.status='running' AND r.lease_owner=$2 AND r.lease_expires_at>clock_timestamp()
  AND NOT EXISTS(SELECT 1 FROM tsw_cpa_rotation_deliveries d WHERE d.credential_name=r.credential_name AND d.kind='quarantine'))`, w.ID, w.Lease).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return errCPAReauthorizationSuperseded
	}
	return nil
}

func (h *OwnerAuthHandler) processCPAReauthorization(ctx context.Context, w cpaReauthorizationWork) error {
	if h.cpaCredentials == nil || h.cpaOAuthIssuer == nil {
		return cpacred.ErrNotConfigured
	}
	if err := h.checkCPAReauthorizationLease(ctx, w); err != nil {
		return err
	}
	file, err := h.cpaCredentials.Lookup(ctx, w.Name)
	if err != nil {
		return err
	}
	if file.Disabled || file.Provider != "codex" {
		return errCPAReauthorizationSuperseded
	}
	var email string
	if err = h.pool.QueryRow(ctx, `SELECT identifier FROM tsw_target_accounts WHERE id=$1`, w.Target).Scan(&email); err != nil {
		return err
	}
	if !strings.EqualFold(email, file.Email) {
		return errCPAReauthorizationSuperseded
	}
	actual, err := h.cpaRenewalIdentity(ctx, file)
	if err != nil {
		return err
	}
	var sealed []byte
	var deliveryRevision *string
	if err = h.pool.QueryRow(ctx, `SELECT credential_payload,delivery_revision FROM tsw_cpa_reauthorizations WHERE id=$1 AND lease_owner=$2`, w.ID, w.Lease).Scan(&sealed, &deliveryRevision); err != nil {
		return err
	}
	// A retry after an accepted upload may see the new file even if its receipt
	// could not be recorded. Re-uploading the same checkpoint verifies it safely.
	if actual.Revision != w.RemoteRevision && (deliveryRevision == nil || actual.Revision != *deliveryRevision) {
		return errCPAReauthorizationSuperseded
	}
	// The queued observation already proved 401 for this exact material.
	// CPA cooldown expiry can clear its display status without renewing it.
	var credential cpacred.Credential
	if len(sealed) > 0 {
		raw, err := targetdomain.OpenMaterial(sealed, h.keyRing)
		if err != nil {
			return err
		}
		if json.Unmarshal([]byte(raw), &credential) != nil || deliveryRevision == nil || credential.Revision != *deliveryRevision || credential.Name != w.Name || !strings.EqualFold(credential.Email, email) {
			return cpacred.ErrCredentialIdentityMismatch
		}
	} else {
		credential, err = h.cpaOAuthIssuer(ctx, w.Target, w.Workspace, email, w.Name)
		if err != nil {
			return err
		}
		if h.cpaProxyAssignment != nil {
			credential, err = h.cpaProxyAssignment(ctx, credential)
			if err != nil {
				return err
			}
		}
		if credential.Name != w.Name || !strings.EqualFold(credential.Email, email) {
			return cpacred.ErrCredentialIdentityMismatch
		}
		if err = h.checkCPAReauthorizationLease(ctx, w); err != nil {
			return err
		}
		raw, err := json.Marshal(credential)
		if err != nil {
			return err
		}
		sealed, err = targetdomain.SealMaterial(string(raw), h.keyRing)
		if err != nil {
			return err
		}
		updated, err := h.pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET credential_payload=$3,delivery_revision=$4,updated_at=now()
    WHERE id=$1 AND lease_owner=$2 AND status='running' AND lease_expires_at>clock_timestamp() AND credential_payload IS NULL`, w.ID, w.Lease, sealed, credential.Revision)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return errCPAReauthorizationSuperseded
		}
	}
	if err = h.checkCPAReauthorizationLease(ctx, w); err != nil {
		return err
	}
	current, err := h.cpaCredentials.Lookup(ctx, w.Name)
	if err != nil {
		return err
	}
	if current.Disabled || !strings.EqualFold(current.Email, email) {
		return errCPAReauthorizationSuperseded
	}
	currentIdentity, err := h.cpaRenewalIdentity(ctx, current)
	if err != nil {
		return err
	}
	if currentIdentity.Revision != w.RemoteRevision && currentIdentity.Revision != credential.Revision {
		return errCPAReauthorizationSuperseded
	}
	if _, err = h.cpaCredentials.Upload(ctx, w.Name, credential.AuthFile); err != nil {
		return err
	}
	if verifier, ok := h.cpaCredentials.(interface {
		Verify(context.Context, string) error
	}); ok {
		if err = verifier.Verify(ctx, w.Name); err != nil {
			return err
		}
	}
	return h.checkCPAReauthorizationLease(ctx, w)
}

func (h *OwnerAuthHandler) runCPAReauthorizationLoop(ctx context.Context) {
	if h.cpaCredentials == nil {
		return
	}
	ticker := time.NewTicker(cpaReauthorizationInterval)
	defer ticker.Stop()
	run := func() {
		// Expired final leases must become visible as blocked, never remain running.
		_, _ = h.pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET status='blocked',lease_owner=NULL,lease_expires_at=NULL,
   completed_at=now(),last_error_code='cpa_reauthorization_lease_exhausted',updated_at=now()
   WHERE status='running' AND lease_expires_at<now() AND attempts>=3`)
		w, ok, err := h.claimCPAReauthorization(ctx)
		if err != nil {
			slog.WarnContext(ctx, "cpa_reauthorization_claim_failed", "error", err)
			return
		}
		if !ok {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 4*time.Minute)
		err = h.processCPAReauthorization(bounded, w)
		cancel()
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		h.finishCPAReauthorization(finish, w, err)
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
