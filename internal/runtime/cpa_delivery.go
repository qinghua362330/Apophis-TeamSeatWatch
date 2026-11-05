package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
)

// cpaCredentialPort is the CPA management surface the rotation loop needs. Tests
// inject a fake; production injects *cpacred.Client. A nil port means the
// deployment has not attached CPA management, and every remote step is skipped.
type cpaCredentialPort interface {
	List(ctx context.Context) ([]cpacred.File, error)
	Lookup(ctx context.Context, selector string) (cpacred.File, error)
	SetDisabled(ctx context.Context, name string, disabled bool) (cpacred.Receipt, error)
	Upload(ctx context.Context, name string, authFile []byte) (cpacred.Receipt, error)
}

const (
	cpaDeliveryQuarantine  = "quarantine"
	cpaDeliveryReplacement = "delivery"
	// cpaDeliveryMaxAttempts bounds remote retries before a case blocks.
	cpaDeliveryMaxAttempts = 3
)

// cpaRotationAction is one remote CPA write the reconciler decided to perform.
// It is produced inside a transaction and applied after that transaction commits,
// so no network call ever holds a database lock.
type cpaRotationAction struct {
	DeliveryID uuid.UUID
	// CaseID is the rotation case primary key in its stored textual form.
	CaseID             string
	Kind               string
	CredentialName     string
	CredentialRevision string
	ClaimToken         uuid.UUID
	// Payload is the immutable credential version for delivery actions only.
	Payload []byte
	Email   string
}

// applyCPARotationAction performs the remote write and records its outcome. The
// result transaction only advances a case when the remote call was observed.
func (h *OwnerAuthHandler) applyCPARotationAction(ctx context.Context, action cpaRotationAction) {
	if h.cpaCredentials == nil {
		return
	}
	duration := 30 * time.Second
	if action.Kind == cpaDeliveryReplacement {
		duration = 2 * time.Minute
	}
	applyCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	var receipt cpacred.Receipt
	var applyErr error
	switch action.Kind {
	case cpaDeliveryQuarantine:
		receipt, applyErr = h.applyCPAQuarantine(applyCtx, action)
	case cpaDeliveryReplacement:
		receipt, applyErr = h.applyCPAReplacement(applyCtx, action)
	default:
		applyErr = errors.New("unknown CPA rotation action")
	}
	if err := h.finishCPARotationAction(ctx, action, receipt, applyErr); err != nil {
		slog.ErrorContext(ctx, "cpa_rotation_action_record_failed", "kind", action.Kind, "error", err)
	}
}

func (h *OwnerAuthHandler) applyCPAQuarantine(ctx context.Context, action cpaRotationAction) (cpacred.Receipt, error) {
	file, err := h.cpaCredentials.Lookup(ctx, action.CredentialName)
	if errors.Is(err, cpacred.ErrCredentialNotFound) {
		// The credential is already absent from CPA, which satisfies quarantine.
		return cpacred.Receipt{Operation: "absent", Name: action.CredentialName, VerifiedAt: time.Now().UTC()}, nil
	}
	if err != nil {
		return cpacred.Receipt{}, err
	}
	if file.Provider != "codex" || action.Email == "" || !strings.EqualFold(strings.TrimSpace(file.Email), strings.TrimSpace(action.Email)) {
		return cpacred.Receipt{}, errors.New("quarantine credential does not match the degraded member")
	}
	if file.Disabled {
		return cpacred.Receipt{Operation: "status", Name: file.Name, VerifiedAt: time.Now().UTC()}, nil
	}
	return h.cpaCredentials.SetDisabled(ctx, file.Name, true)
}

func (h *OwnerAuthHandler) applyCPAReplacement(ctx context.Context, action cpaRotationAction) (cpacred.Receipt, error) {
	credential, err := buildCPAReplacement(action.Payload, action.Email)
	if err != nil {
		return cpacred.Receipt{}, err
	}
	if credential.Name != action.CredentialName || credential.Revision != action.CredentialRevision {
		return cpacred.Receipt{}, errors.New("replacement credential changed after delivery was claimed")
	}
	if h.cpaProxyAssignment != nil {
		// Production CPA delivery pins its assigned proxy. The published OAuth
		// version remains the immutable source identity for this delivery.
		credential, err = h.cpaReplacementCredential(ctx, action, credential)
		if err != nil {
			return cpacred.Receipt{}, err
		}
	}
	receipt, err := h.cpaCredentials.Upload(ctx, credential.Name, credential.AuthFile)
	if err != nil {
		return cpacred.Receipt{}, err
	}
	if verifier, ok := h.cpaCredentials.(interface {
		Verify(context.Context, string) error
	}); ok {
		if err = verifier.Verify(ctx, credential.Name); err != nil {
			return cpacred.Receipt{}, err
		}
	}
	return receipt, nil
}

// finishCPARotationAction records the observed outcome and advances the case.
func (h *OwnerAuthHandler) finishCPARotationAction(ctx context.Context, action cpaRotationAction, receipt cpacred.Receipt, applyErr error) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if applyErr == nil {
		updated, updateErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_deliveries
			SET status='applied',claim_token=NULL,claimed_at=NULL,remote_status=$2,last_error_code=NULL,applied_at=now(),verified_at=$3,updated_at=now()
			WHERE id=$1 AND claim_token=$4`, action.DeliveryID, nullableInt(receipt.StatusCode), receipt.VerifiedAt, action.ClaimToken)
		if updateErr != nil {
			return updateErr
		}
		if updated.RowsAffected() != 1 {
			// Another worker already recorded this delivery; leave its outcome intact.
			return tx.Commit(ctx)
		}
		return errOrCommit(ctx, tx, h.advanceCPACaseAfterRemoteWrite(ctx, tx, action))
	}
	// A failed attempt stays retryable until the attempt budget is spent.
	var attempts int
	if err = tx.QueryRow(ctx, `UPDATE tsw_cpa_rotation_deliveries
		SET status=CASE WHEN attempts>= $2 THEN 'failed' ELSE 'pending' END,
			claim_token=NULL,claimed_at=NULL,last_error_code=$3,updated_at=now()
		WHERE id=$1 AND claim_token=$4 RETURNING attempts`, action.DeliveryID, cpaDeliveryMaxAttempts, cpaErrorCode(applyErr), action.ClaimToken).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tx.Commit(ctx)
		}
		return err
	}
	if attempts < cpaDeliveryMaxAttempts {
		_, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now()+interval '2 minutes',last_error_code=$2,updated_at=now(),version=version+1 WHERE id=$1`, action.CaseID, cpaErrorCode(applyErr))
		return errOrCommit(ctx, tx, err)
	}
	if err = blockCPAAutomationCaseTx(ctx, tx, action.CaseID, cpaErrorCode(applyErr), true); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *OwnerAuthHandler) advanceCPACaseAfterRemoteWrite(ctx context.Context, tx pgx.Tx, action cpaRotationAction) error {
	var item cpaAutomationCase
	// Credential identity is required by the evidence gates that run next; a case
	// reloaded without it silently counts zero detections.
	if err := tx.QueryRow(ctx, `SELECT id,event_id,credential_id,credential_revision,target_account_id,membership_id,workspace_id,source_batch_id,status,attempt_count,removal_operation_id,replacement_operation_id,replacement_account_id,replacement_standby_batch_id,replacement_batch_id
		FROM tsw_cpa_rotation_cases WHERE id=$1 FOR UPDATE`, action.CaseID).Scan(&item.ID, &item.EventID, &item.CredentialID, &item.CredentialRevision, &item.TargetAccountID, &item.MembershipID, &item.WorkspaceID, &item.SourceBatchID, &item.Status, &item.AttemptCount, &item.RemovalOperationID, &item.ReplacementOperationID, &item.ReplacementAccountID, &item.ReplacementStandbyBatchID, &item.ReplacementBatchID); err != nil {
		return err
	}
	switch action.Kind {
	case cpaDeliveryQuarantine:
		var minimumConfidence float64
		var consecutive int
		if err := tx.QueryRow(ctx, `SELECT minimum_confidence,consecutive_detections FROM tsw_cpa_automation_settings WHERE singleton`).Scan(&minimumConfidence, &consecutive); err != nil {
			return err
		}
		if err := h.queueCPAAutomaticRemovalTx(ctx, tx, item, minimumConfidence, consecutive); err != nil {
			return err
		}
	case cpaDeliveryReplacement:
		if _, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='completed',completed_at=now(),next_attempt_at=now(),last_error_code=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tsw_cpa_automation_settings SET failure_count=0,circuit_open_until=NULL,updated_at=now() WHERE singleton`); err != nil {
			return err
		}
	}
	// The caller owns the transaction boundary. Remote writes are completed
	// outside the transaction, while receipt advancement must compose with both
	// the normal finish path and recovery of an already-applied receipt.
	return nil
}

// beginCPAAutomaticQuarantineTx creates the durable quarantine receipt and moves
// the case into the remote-write stage.
func beginCPAAutomaticQuarantineTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase, credentialName string) error {
	digest := sha256.Sum256([]byte(cpaDeliveryQuarantine + "\x00" + item.ID + "\x00" + credentialName))
	if _, err := tx.Exec(ctx, `INSERT INTO tsw_cpa_rotation_deliveries(case_id,kind,credential_name,credential_revision,request_sha256)
		VALUES($1,'quarantine',$2,$3,$4) ON CONFLICT(case_id,kind) DO NOTHING`, item.ID, credentialName, item.CredentialRevision, digest[:]); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='quarantining',next_attempt_at=now(),last_error_code=NULL,started_at=COALESCE(started_at,now()),attempt_count=attempt_count+1,updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
	return err
}

// beginCPAAutomaticDeliveryTx stores the replacement receipt and moves the case
// into the delivery stage.
func beginCPAAutomaticDeliveryTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase, name, revision, email string) error {
	digest := sha256.Sum256([]byte(strings.Join([]string{name, revision, email}, "\x00")))
	if _, err := tx.Exec(ctx, `INSERT INTO tsw_cpa_rotation_deliveries(case_id,kind,credential_name,credential_revision,request_sha256)
		VALUES($1,'delivery',$2,$3,$4) ON CONFLICT(case_id,kind) DO UPDATE SET credential_name=EXCLUDED.credential_name,credential_revision=EXCLUDED.credential_revision WHERE tsw_cpa_rotation_deliveries.status<>'applied'`, item.ID, name, revision, digest[:]); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='delivering',next_attempt_at=now(),last_error_code=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
	return err
}

// claimCPARotationDelivery leases one pending delivery row for a remote write.
func claimCPARotationDelivery(ctx context.Context, tx pgx.Tx, caseID, kind string) (cpaRotationAction, bool, error) {
	var action cpaRotationAction
	var name, revision string
	err := tx.QueryRow(ctx, `UPDATE tsw_cpa_rotation_deliveries
		SET status='in_flight',claim_token=gen_random_uuid(),claimed_at=now(),attempts=attempts+1,updated_at=now()
		WHERE case_id=$1 AND kind=$2 AND status='pending'
		RETURNING id,claim_token,credential_name,credential_revision`, caseID, kind).Scan(&action.DeliveryID, &action.ClaimToken, &name, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return cpaRotationAction{}, false, nil
	}
	if err != nil {
		return cpaRotationAction{}, false, err
	}
	action.CaseID = caseID
	action.Kind = kind
	action.CredentialName = name
	action.CredentialRevision = revision
	return action, true, nil
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func errOrCommit(ctx context.Context, tx pgx.Tx, err error) error {
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// cpaErrorCode maps a remote failure to a bounded, non-secret code.
func cpaErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, cpacred.ErrCredentialNotFound):
		return "cpa_credential_not_found"
	case errors.Is(err, cpacred.ErrInvalidCredentialName):
		return "cpa_credential_name_invalid"
	case errors.Is(err, cpacred.ErrNotConfigured):
		return "cpa_management_unconfigured"
	default:
		return "cpa_remote_write_failed"
	}
}

// buildCPAReplacement binds the published material to the intended replacement
// account and workspace, before the remote write is attempted.
func buildCPAReplacement(raw []byte, email string) (cpacred.Credential, error) {
	payload, err := cpacred.ParseDeliveryPayload(raw)
	if err != nil {
		return cpacred.Credential{}, err
	}
	credential, err := cpacred.BuildCodexCredential(payload, email, time.Now())
	if err != nil {
		return cpacred.Credential{}, err
	}
	var metadata struct {
		AccountID string `json:"account_id"`
	}
	if json.Unmarshal(credential.AuthFile, &metadata) != nil || strings.TrimSpace(payload.WorkspaceID) == "" || metadata.AccountID != strings.TrimSpace(payload.WorkspaceID) || credential.Email != strings.ToLower(strings.TrimSpace(email)) {
		return cpacred.Credential{}, errors.New("replacement credential does not match the intended account and workspace")
	}
	return credential, nil
}
