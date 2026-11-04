package runtime

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

// cpaAutomaticSpareBatchID is deliberately stable. It gives imported accounts
// without an operator-created standby group a durable home while leaving every
// existing non-empty group untouched.
const cpaAutomaticSpareBatchID = "00000000-0000-0000-0000-00000000c0a5"

// ensureCPASparePoolTx enrolls imported, complete target accounts which are not
// active Team members and are not currently represented in CPA's inventory.
// Enrollment is local bookkeeping only: it never changes credentials, sessions,
// passwords, or a membership already assigned to another standby group.
func ensureCPASparePoolTx(ctx context.Context, tx pgx.Tx) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM tsw_cpa_automation_settings WHERE singleton`).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tsw_standby_child_batches(id,name)
		VALUES($1,'CPA automatic spare pool') ON CONFLICT (id) DO NOTHING`, cpaAutomaticSpareBatchID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE tsw_standby_child_memberships spare
		SET batch_id=$1,version=spare.version+1
		FROM tsw_target_accounts account
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=account.id
		WHERE spare.target_account_id=account.id AND spare.batch_id IS NULL
		AND account.status='active' AND credentials.material_status='complete' AND credentials.materials_sealed
		AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships active WHERE active.target_account_id=account.id AND active.state='active')
		AND NOT EXISTS (SELECT 1 FROM tsw_cpa_credentials remote WHERE remote.present AND remote.email_key_version=account.identifier_key_version AND remote.email_hmac=account.identifier_hmac)`, cpaAutomaticSpareBatchID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO tsw_standby_child_memberships(target_account_id,batch_id)
		SELECT account.id,$1
		FROM tsw_target_accounts account
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=account.id
		WHERE account.status='active' AND credentials.material_status='complete' AND credentials.materials_sealed
		AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships active_membership
			WHERE active_membership.target_account_id=account.id AND active_membership.state='active')
		AND NOT EXISTS (SELECT 1 FROM tsw_standby_child_memberships existing
			WHERE existing.target_account_id=account.id AND existing.batch_id IS NOT NULL)
		AND NOT EXISTS (SELECT 1 FROM tsw_cpa_credentials remote
			WHERE remote.present
			AND remote.email_key_version=account.identifier_key_version
			AND remote.email_hmac=account.identifier_hmac)
		ON CONFLICT(target_account_id) DO NOTHING`, cpaAutomaticSpareBatchID)
	return err
}

// ensureCPASparePool is intentionally small and transaction-scoped so callers
// can invoke it immediately before the existing reservation query.
func (h *OwnerAuthHandler) ensureCPASparePool(ctx context.Context) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = ensureCPASparePoolTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// prepareCPASpareOnce refreshes one imported spare's Personal session and
// records a real first-party usage probe. It deliberately does not mark an
// account available unless the fixed Personal endpoint returns verified usage.
func (h *OwnerAuthHandler) prepareCPASpareOnce(ctx context.Context) (bool, error) {
	prepareCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx = prepareCtx
	if err := h.ensureCPASparePool(ctx); err != nil {
		return false, err
	}
	var id uuid.UUID
	var revision int64
	err := h.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT account.id,credentials.secret_revision FROM tsw_target_accounts account
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=account.id
		JOIN tsw_standby_child_memberships spare ON spare.target_account_id=account.id
		WHERE account.status='active' AND credentials.material_status='complete' AND credentials.materials_sealed
        AND EXISTS(SELECT 1 FROM tsw_cpa_automation_settings WHERE singleton AND enabled)
        AND EXISTS(SELECT 1 FROM tsw_cpa_rotation_cases WHERE status IN ('pending_automation','awaiting_approval','waiting_evidence','waiting_replacement'))
        AND NOT EXISTS(SELECT 1 FROM tsw_cpa_credentials remote WHERE remote.present AND remote.email_key_version=account.identifier_key_version AND remote.email_hmac=account.identifier_hmac)
		AND (credentials.latest_probed_at IS NULL OR credentials.latest_probed_at<now()-interval '5 minutes')
		AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships active WHERE active.target_account_id=account.id AND active.state='active')
		ORDER BY credentials.latest_probed_at NULLS FIRST,account.created_at,account.id
		FOR UPDATE OF account,credentials SKIP LOCKED LIMIT 1
	)
	UPDATE tsw_target_credentials credentials SET latest_probed_at=now(),latest_probe_status='unknown',latest_probe_endpoint_key='account_usage',latest_probe_origin='worker',latest_probe_http_status=NULL,latest_probe_error_code='cpa_probe_pending',version=version+1
	FROM candidate WHERE credentials.target_account_id=candidate.id
	RETURNING candidate.id,candidate.secret_revision`).Scan(&id, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	result, ensureErr := (accountsession.Store{Pool: h.pool, KeyRing: h.keyRing}).Ensure(ctx, id, h.personalRefresh, false, nil)
	if ensureErr != nil {
		return true, ensureErr
	}
	if result.Status != "ready" {
		return true, recordSpareProbe(ctx, h.pool, id, revision, "", platform.PersonalUnknown, 0, "personal_session_unavailable")
	}
	if h.egress == nil {
		return true, recordSpareProbe(ctx, h.pool, id, revision, "", platform.PersonalNetworkError, 0, "egress_unavailable")
	}
	probe := SavedTargetPersonalProbe{Pool: h.pool, KeyRing: h.keyRing, Adapter: platform.PersonalUsageProbe{Client: func(probeCtx context.Context) (*http.Client, func(), error) {
		lease, leaseErr := h.egress.Acquire(egress.WithStableWindow(probeCtx, 2*time.Minute))
		if leaseErr != nil {
			return nil, nil, leaseErr
		}
		return lease.Client(), lease.Release, nil
	}}}
	evidence, probeErr := probe.ProbePersonal(ctx, id.String())
	if probeErr != nil {
		return true, recordSpareProbe(ctx, h.pool, id, revision, evidence.SessionGeneration, platform.PersonalUnknown, 0, "personal_probe_failed")
	}
	return true, recordSpareProbe(ctx, h.pool, id, revision, evidence.SessionGeneration, platform.ClassifyPersonalProbe(evidence), evidence.HTTPStatus, evidence.ErrorCode)
}

func recordSpareProbe(ctx context.Context, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, id uuid.UUID, revision int64, generation string, outcome platform.PersonalProbeOutcome, status int, code string) error {
	probeStatus := "unknown"
	switch outcome {
	case platform.PersonalAvailable:
		probeStatus = "available"
	case platform.PersonalCredentialInvalid:
		probeStatus = "credential_invalid"
	case platform.PersonalBanned:
		probeStatus = "definitely_unavailable"
	case platform.PersonalNetworkError:
		probeStatus = "transient_failure"
	}
	var httpStatus any
	if status >= 100 && status <= 599 {
		httpStatus = status
	}
	var errorCode any
	if len(code) > 0 && len(code) <= 128 {
		errorCode = code
	}
	_, err := pool.Exec(ctx, `UPDATE tsw_target_credentials SET latest_probe_status=$4,latest_probe_http_status=$5,latest_probe_error_code=$6,latest_probe_endpoint_key='account_usage',latest_probe_origin='worker',latest_probed_at=now(),last_verified_at=CASE WHEN $4='available' THEN now() ELSE last_verified_at END,version=version+1 WHERE target_account_id=$1 AND secret_revision=$2 AND ($3='' OR EXISTS (SELECT 1 FROM tsw_target_personal_sessions session WHERE session.target_account_id=$1 AND session.secret_revision=$2 AND session.generation::text=$3))`, id, revision, generation, probeStatus, httpStatus, errorCode)
	return err
}
