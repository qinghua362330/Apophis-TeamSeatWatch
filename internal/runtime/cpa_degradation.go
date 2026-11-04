package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpaevent"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
)

const cpaEventBodyLimit = 64 << 10

var errCPAEventConflict = errors.New("CPA degradation event id conflict")

type cpaEventRow struct {
	ID, EventID, CredentialID, CredentialRevision, Email string
	ExpectedModel, DetectedModel, EventStatus            string
	MappingStatus, MappingMessage                        string
	Confidence                                           float64
	ObservedAt, ReceivedAt, UpdatedAt                    time.Time
	MappedAt, DismissedAt                                *time.Time
	TargetAccountID, MembershipID, WorkspaceID           *uuid.UUID
	RotationCaseID                                       *uuid.UUID
}

func (h *OwnerAuthHandler) receiveCPADegradationEvent(w http.ResponseWriter, r *http.Request) {
	if len(h.cpaWebhookSecret) < 16 {
		writeProblem(w, r, http.StatusServiceUnavailable, "integration_disabled", "Service Unavailable", "CPA degradation integration is not configured", 0)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, cpaEventBodyLimit+1))
	if err != nil || len(body) == 0 || len(body) > cpaEventBodyLimit {
		writeProblem(w, r, http.StatusBadRequest, "invalid_event", "Invalid Event", "Event payload is invalid", 0)
		return
	}
	payload, email, err := cpaevent.Verify(h.cpaWebhookSecret, r.Header, body, time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, cpaevent.ErrInvalidSignature):
			writeProblem(w, r, http.StatusUnauthorized, "invalid_signature", "Unauthorized", "Invalid event authentication", 0)
		case errors.Is(err, cpaevent.ErrExpiredSignature):
			writeProblem(w, r, http.StatusUnauthorized, "expired_signature", "Unauthorized", "Event signature expired", 0)
		default:
			writeProblem(w, r, http.StatusBadRequest, "invalid_event", "Invalid Event", "Event payload is invalid", 0)
		}
		return
	}
	payload.ObservedAt = payload.ObservedAt.UTC().Truncate(time.Microsecond)
	result, status, err := h.storeAndMapCPAEvent(r, payload, email)
	if err != nil {
		if errors.Is(err, errCPAEventConflict) {
			writeProblem(w, r, http.StatusConflict, "event_id_conflict", "Conflict", "Event ID is already associated with different content", 0)
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, "event_store_failed", "Internal Server Error", "Unable to store event", 0)
		return
	}
	writeJSON(w, status, result)
}

func (h *OwnerAuthHandler) storeAndMapCPAEvent(r *http.Request, payload cpaevent.Payload, email string) (ownerapi.CPADegradationEvent, int, error) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		return ownerapi.CPADegradationEvent{}, 0, err
	}
	defer tx.Rollback(r.Context())
	var inserted bool
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_cpa_degradation_events(event_id,credential_id,credential_revision,normalized_email,expected_model,detected_model,confidence,observed_at,event_status)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(event_id) DO NOTHING RETURNING true`, payload.EventID, payload.CredentialID, payload.CredentialRevision, email, payload.ExpectedModel, payload.DetectedModel, payload.Confidence, payload.ObservedAt, payload.Status).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		row, loadErr := loadCPAEventByEventID(r.Context(), tx, payload.EventID)
		if loadErr != nil {
			return ownerapi.CPADegradationEvent{}, 0, loadErr
		}
		if row.CredentialID != payload.CredentialID || row.CredentialRevision != payload.CredentialRevision || row.Email != email || row.ExpectedModel != payload.ExpectedModel || row.DetectedModel != payload.DetectedModel || row.EventStatus != payload.Status || row.Confidence != payload.Confidence || !row.ObservedAt.Equal(payload.ObservedAt) {
			return ownerapi.CPADegradationEvent{}, 0, errCPAEventConflict
		}
		return cpaEventDTO(row), http.StatusOK, tx.Commit(r.Context())
	}
	if err != nil {
		return ownerapi.CPADegradationEvent{}, 0, err
	}
	if err = h.mapCPAEventTx(r.Context(), tx, payload.EventID, email); err != nil {
		return ownerapi.CPADegradationEvent{}, 0, err
	}
	row, err := loadCPAEventByEventID(r.Context(), tx, payload.EventID)
	if err != nil {
		return ownerapi.CPADegradationEvent{}, 0, err
	}
	return cpaEventDTO(row), http.StatusAccepted, tx.Commit(r.Context())
}

func (h *OwnerAuthHandler) mapCPAEventTx(ctx context.Context, tx pgx.Tx, eventID uuid.UUID, email string) error {
	normalized, keyVersion, fingerprint, err := identity.Fingerprint(h.keyRing, identity.TargetLogin, email)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT account.id,membership.id,binding.workspace_id
		FROM tsw_target_accounts account
		JOIN tsw_batch_memberships membership ON membership.target_account_id=account.id AND membership.state='active'
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.ended_at IS NULL
		WHERE account.identifier_key_version=$1 AND account.identifier_hmac=$2 AND account.status='active'`, keyVersion, fingerprint[:])
	if err != nil {
		return err
	}
	defer rows.Close()
	type match struct{ account, membership, workspace uuid.UUID }
	matches := []match{}
	for rows.Next() {
		var item match
		if err = rows.Scan(&item.account, &item.membership, &item.workspace); err != nil {
			return err
		}
		matches = append(matches, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(matches) == 0 {
		accountID, membershipID, workspaceID, found, adoptErr := h.adoptCPAMemberTx(ctx, tx, normalized)
		if adoptErr != nil {
			return adoptErr
		}
		if found {
			matches = append(matches, match{accountID, membershipID, workspaceID})
		}
	}
	status, message := "not_found", "No active Team membership matched the credential email"
	var account, membership, workspace *uuid.UUID
	if len(matches) == 1 {
		status, message = "pending_rotation", "Unique active Team membership mapped; automatic rotation queued"
		account, membership, workspace = &matches[0].account, &matches[0].membership, &matches[0].workspace
	} else if len(matches) > 1 {
		status, message = "ambiguous", "Multiple active Team memberships matched the credential email"
	} else if credentialID, provider, lookupErr := lookupCPACredentialIdentity(ctx, tx, keyVersion, fingerprint[:]); lookupErr != nil {
		return lookupErr
	} else if credentialID != "" {
		status, message = "not_found", "CPA credential ("+provider+") awaits a unique ordinary Team member in fresh workspace management evidence"
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_cpa_degradation_events SET normalized_email=$2,mapping_status=$3,target_account_id=$4,membership_id=$5,workspace_id=$6,mapping_message=$7,mapped_at=now(),updated_at=now(),version=version+1 WHERE event_id=$1`, eventID, normalized, status, account, membership, workspace, message)
	if err != nil || len(matches) != 1 {
		return err
	}
	return h.ensureCPAAutomationCaseTx(ctx, tx, eventID, matches[0].account, matches[0].membership, matches[0].workspace)
}

func (h *OwnerAuthHandler) ensureCPAAutomationCaseTx(ctx context.Context, tx pgx.Tx, eventID, accountID, membershipID, workspaceID uuid.UUID) error {
	var eventRowID, credentialID, credentialRevision string
	var sourceBatchID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT event.id::text,event.credential_id,event.credential_revision,membership.batch_id
		FROM tsw_cpa_degradation_events event
		JOIN tsw_batch_memberships membership ON membership.id=$2 AND membership.state='active'
		WHERE event.event_id=$1 AND event.event_status='quarantined'`, eventID, membershipID).Scan(&eventRowID, &credentialID, &credentialRevision, &sourceBatchID); err != nil {
		return err
	}
	var caseID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM tsw_cpa_rotation_cases WHERE membership_id=$1 AND status NOT IN ('completed','failed','dismissed') FOR UPDATE`, membershipID).Scan(&caseID)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE tsw_cpa_degradation_events SET rotation_case_id=$2,mapping_message='Unique active Team membership mapped; existing automatic rotation retained',updated_at=now(),version=version+1 WHERE event_id=$1`, eventID, caseID)
		return err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	err = tx.QueryRow(ctx, `INSERT INTO tsw_cpa_rotation_cases(event_id,credential_id,credential_revision,target_account_id,membership_id,workspace_id,source_batch_id)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(event_id) DO UPDATE SET updated_at=now() RETURNING id`, eventRowID, credentialID, credentialRevision, accountID, membershipID, workspaceID, sourceBatchID).Scan(&caseID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_cpa_degradation_events SET rotation_case_id=$2,updated_at=now(),version=version+1 WHERE event_id=$1`, eventID, caseID)
	return err
}

type cpaAutomationCase struct {
	ID, CredentialID, CredentialRevision string
	EventID, TargetAccountID             uuid.UUID
	MembershipID, WorkspaceID            uuid.UUID
	SourceBatchID                        uuid.UUID
	Status                               string
	AttemptCount                         int
	RemovalOperationID                   *uuid.UUID
	ReplacementOperationID               *uuid.UUID
	ReplacementAccountID                 *uuid.UUID
	ReplacementStandbyBatchID            *uuid.UUID
	ReplacementBatchID                   *uuid.UUID
}

// reconcileCPAAutomationOnce advances one rotation case. Database state is
// committed before any CPA management call, so an interrupted process never
// holds a transaction open across the network and never loses a durable claim.
func (h *OwnerAuthHandler) reconcileCPAAutomationOnce(ctx context.Context) (bool, error) {
	processed, action, err := h.claimCPAAutomationWork(ctx)
	if err != nil || action == nil {
		return processed, err
	}
	h.applyCPARotationAction(ctx, *action)
	return true, nil
}

// claimCPAAutomationWork selects one runnable case and either advances local
// state or leases a remote write the caller must perform after commit.
func (h *OwnerAuthHandler) claimCPAAutomationWork(ctx context.Context) (bool, *cpaRotationAction, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return false, nil, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('tsw:cpa-automation'))`).Scan(&locked); err != nil || !locked {
		return false, nil, err
	}
	var enabled bool
	var minimumConfidence float64
	var consecutive int
	var circuitOpenUntil *time.Time
	if err = tx.QueryRow(ctx, `SELECT enabled,minimum_confidence,consecutive_detections,circuit_open_until FROM tsw_cpa_automation_settings WHERE singleton`).Scan(&enabled, &minimumConfidence, &consecutive, &circuitOpenUntil); err != nil {
		return false, nil, err
	}
	if !enabled || circuitOpenUntil != nil && circuitOpenUntil.After(time.Now()) {
		return false, nil, tx.Commit(ctx)
	}
	var item cpaAutomationCase
	err = tx.QueryRow(ctx, `SELECT c.id::text,c.event_id,c.credential_id,c.credential_revision,c.target_account_id,c.membership_id,c.workspace_id,c.source_batch_id,c.status,c.attempt_count,c.removal_operation_id,c.replacement_operation_id,c.replacement_account_id,c.replacement_standby_batch_id,c.replacement_batch_id
		FROM tsw_cpa_rotation_cases c
		WHERE c.status NOT IN ('completed','blocked','failed','dismissed') AND c.next_attempt_at<=now()
		ORDER BY CASE WHEN c.status='pending_automation' THEN 1 ELSE 0 END,c.created_at
		FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&item.ID, &item.EventID, &item.CredentialID, &item.CredentialRevision, &item.TargetAccountID, &item.MembershipID, &item.WorkspaceID, &item.SourceBatchID, &item.Status, &item.AttemptCount, &item.RemovalOperationID, &item.ReplacementOperationID, &item.ReplacementAccountID, &item.ReplacementStandbyBatchID, &item.ReplacementBatchID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, tx.Commit(ctx)
	}
	if err != nil {
		return false, nil, err
	}
	switch {
	case item.Status == "pending_automation" || item.Status == "awaiting_approval" || item.Status == "waiting_evidence" || item.Status == "waiting_replacement" && item.RemovalOperationID == nil:
		action, err := h.beginCPAAutomaticRemoval(ctx, tx, item, minimumConfidence, consecutive)
		return err == nil, action, errOrCommit(ctx, tx, err)
	case item.Status == "quarantining":
		action, err := h.leaseCPADelivery(ctx, tx, item.ID, cpaDeliveryQuarantine)
		return err == nil, action, errOrCommit(ctx, tx, err)
	case item.Status == "removal_verified" || item.Status == "waiting_replacement" && item.RemovalOperationID != nil:
		if err = h.queueCPAAutomaticReplacementTx(ctx, tx, item); err != nil {
			return false, nil, err
		}
	case item.Status == "replacement_queued" || item.Status == "replacement_running" || item.Status == "credentials_pending" || item.Status == "delivering":
		action, err := h.observeCPAAutomaticReplacementTx(ctx, tx, item)
		return err == nil, action, errOrCommit(ctx, tx, err)
	default:
		if err = h.observeCPAAutomaticRemovalTx(ctx, tx, item); err != nil {
			return false, nil, err
		}
	}
	return true, nil, tx.Commit(ctx)
}

// beginCPAAutomaticRemoval requires CPA management, validates evidence and
// reserves a replacement before quarantining the degraded credential.
func (h *OwnerAuthHandler) beginCPAAutomaticRemoval(ctx context.Context, tx pgx.Tx, item cpaAutomationCase, minimumConfidence float64, consecutive int) (*cpaRotationAction, error) {
	// The automatic contract starts by isolating the degraded credential in CPA.
	// Do not kick a member when the management attachment is unavailable: doing
	// so would leave the workspace without a usable credential or an auditable
	// quarantine receipt.
	if h.cpaCredentials == nil {
		_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='waiting_evidence',next_attempt_at=now()+interval '2 minutes',last_error_code='cpa_management_unconfigured',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return nil, err
	}
	ready, err := h.prepareCPAAutomaticRemovalTx(ctx, tx, item, minimumConfidence, consecutive)
	if err != nil {
		return nil, err
	}
	if !ready {
		// A case parked on stale or partial verification asks for a fresh read
		// rather than waiting for the next manual visit.
		return nil, h.refreshCPACaseEvidenceIfWaiting(ctx, tx, item)
	}
	return nil, beginCPAAutomaticQuarantineTx(ctx, tx, item, item.CredentialID)
}

// leaseCPADelivery reclaims a stale claim, then leases the pending row for the
// caller to apply. A case whose remote write completed after its claim was lost
// is parked rather than repeated blindly.
func (h *OwnerAuthHandler) leaseCPADelivery(ctx context.Context, tx pgx.Tx, caseID, kind string) (*cpaRotationAction, error) {
	if _, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_deliveries SET status='pending',claim_token=NULL,claimed_at=NULL,updated_at=now()
		WHERE case_id=$1 AND kind=$2 AND status='in_flight' AND claimed_at<now()-interval '5 minutes'`, caseID, kind); err != nil {
		return nil, err
	}
	action, claimed, err := claimCPARotationDelivery(ctx, tx, caseID, kind)
	if err != nil {
		return nil, err
	}
	if claimed && kind == cpaDeliveryQuarantine {
		if err := tx.QueryRow(ctx, `SELECT event.normalized_email FROM tsw_cpa_rotation_cases rotation JOIN tsw_cpa_degradation_events event ON event.id=rotation.event_id WHERE rotation.id=$1`, caseID).Scan(&action.Email); err != nil {
			return nil, err
		}
	}
	if claimed && kind == cpaDeliveryReplacement {
		// The delivery action needs the immutable credential version it publishes.
		// A missing version returns the claim so the next pass can re-evaluate.
		loadErr := tx.QueryRow(ctx, `SELECT delivery.payload,target.identifier
			FROM tsw_cpa_rotation_cases rotation
			JOIN tsw_batch_memberships membership ON membership.batch_id=rotation.replacement_batch_id
				AND membership.target_account_id=rotation.replacement_account_id AND membership.state='active'
			JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
			JOIN tsw_delivery_versions delivery ON delivery.id=asset.current_delivery_version_id AND delivery.oauth_asset_id=asset.id
			JOIN tsw_target_accounts target ON target.id=rotation.replacement_account_id
			WHERE rotation.id=$1`, caseID).Scan(&action.Payload, &action.Email)
		if loadErr != nil {
			if _, releaseErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_deliveries
				SET status='pending',claim_token=NULL,claimed_at=NULL,attempts=GREATEST(attempts-1,0),last_error_code='replacement_credentials_pending',updated_at=now()
				WHERE id=$1 AND claim_token=$2`, action.DeliveryID, action.ClaimToken); releaseErr != nil {
				return nil, releaseErr
			}
			if errors.Is(loadErr, pgx.ErrNoRows) {
				if _, parkErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='credentials_pending',next_attempt_at=now()+interval '30 seconds',last_error_code='replacement_credentials_pending',updated_at=now(),version=version+1 WHERE id=$1`, caseID); parkErr != nil {
					return nil, parkErr
				}
				return nil, nil
			}
			return nil, loadErr
		}
	}
	if !claimed {
		var deliveryStatus string
		if err = tx.QueryRow(ctx, `SELECT status FROM tsw_cpa_rotation_deliveries WHERE case_id=$1 AND kind=$2`, caseID, kind).Scan(&deliveryStatus); err != nil {
			return nil, err
		}
		// A prior worker may have completed the remote write before this
		// reconciler observed it. Advance from the durable receipt instead of
		// parking the case or issuing the write again.
		if deliveryStatus == "applied" {
			if err = h.advanceCPACaseAfterRemoteWrite(ctx, tx, cpaRotationAction{CaseID: caseID, Kind: kind}); err != nil {
				return nil, err
			}
			return nil, nil
		}
		caseStatus := "quarantining"
		if kind == cpaDeliveryReplacement {
			caseStatus = "delivering"
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status=$2,next_attempt_at=now()+interval '5 seconds',last_error_code='remote_write_claim_unavailable',updated_at=now(),version=version+1 WHERE id=$1`, caseID, caseStatus); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &action, nil
}

func (h *OwnerAuthHandler) queueCPAAutomaticRemovalTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase, minimumConfidence float64, consecutive int) error {
	ready, err := h.prepareCPAAutomaticRemovalTx(ctx, tx, item, minimumConfidence, consecutive)
	if err != nil || !ready {
		return err
	}
	return h.insertCPAAutomaticRemovalTx(ctx, tx, item)
}

// prepareCPAAutomaticRemovalTx applies the evidence gates, protects privileged
// members and reserves a replacement. It returns false when the case was parked
// or blocked instead of becoming runnable.
func (h *OwnerAuthHandler) prepareCPAAutomaticRemovalTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase, minimumConfidence float64, consecutive int) (bool, error) {
	var confidence float64
	var observedAt time.Time
	var eventStatus string
	if err := tx.QueryRow(ctx, `SELECT confidence,observed_at,event_status FROM tsw_cpa_degradation_events WHERE id=$1`, item.EventID).Scan(&confidence, &observedAt, &eventStatus); err != nil {
		return false, err
	}
	if eventStatus != "quarantined" || confidence < minimumConfidence || observedAt.Before(time.Now().Add(-30*time.Minute)) {
		return false, blockCPAAutomationCaseTx(ctx, tx, item.ID, "degradation_evidence_rejected", false)
	}
	var detections int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_degradation_events event
		JOIN tsw_cpa_degradation_events source ON source.id=$3
		WHERE event.credential_id=$1 AND event.credential_revision=source.credential_revision
		AND event.expected_model=source.expected_model AND event.event_status='quarantined'
		AND event.confidence>=$2 AND event.observed_at>=now()-interval '2 hours'`, item.CredentialID, minimumConfidence, item.EventID).Scan(&detections); err != nil {
		return false, err
	}
	if detections < consecutive {
		_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='waiting_evidence',next_attempt_at=now()+interval '5 minutes',last_error_code='consecutive_detection_pending',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return false, err
	}
	var workspaceEnabled bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT enabled FROM tsw_cpa_automation_workspace_settings WHERE workspace_id=$1),true)`, item.WorkspaceID).Scan(&workspaceEnabled); err != nil {
		return false, err
	}
	if !workspaceEnabled {
		return false, blockCPAAutomationCaseTx(ctx, tx, item.ID, "workspace_automation_disabled", false)
	}
	var ownerID uuid.UUID
	var platformMemberID, targetIdentifier, role string
	var verificationID int64
	err := tx.QueryRow(ctx, `SELECT operation.owner_id,membership.platform_member_id,target.identifier,COALESCE(member_entry.role,''),verification.id
		FROM tsw_batch_memberships membership
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id
		JOIN tsw_operation_targets joined_target ON joined_target.id=membership.join_operation_target_id
		JOIN tsw_operations operation ON operation.id=joined_target.operation_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id AND batch.id=$4
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.ended_at IS NULL
		JOIN LATERAL (
			SELECT v.id FROM tsw_workspace_verifications v
			WHERE v.workspace_id=binding.workspace_id AND v.mother_account_id=binding.mother_account_id
			AND v.outcome='verified' AND v.permission='manage' AND v.completeness='complete'
			AND v.expires_at>now() AND v.active_until>now()
			AND EXISTS(SELECT 1 FROM tsw_workspace_verification_entries owner_entry WHERE owner_entry.verification_id=v.id AND owner_entry.kind='member' AND lower(COALESCE(owner_entry.role,'')) IN ('owner','account-owner'))
			ORDER BY v.id DESC LIMIT 1
		) verification ON true
		JOIN tsw_workspace_verification_entries member_entry ON member_entry.verification_id=verification.id
			AND member_entry.kind='member' AND member_entry.identifier=target.identifier AND member_entry.platform_member_id=membership.platform_member_id
		WHERE membership.id=$1 AND membership.target_account_id=$2 AND binding.workspace_id=$3 AND membership.state='active' AND membership.seat_type='prolite'`, item.MembershipID, item.TargetAccountID, item.WorkspaceID, item.SourceBatchID).Scan(&ownerID, &platformMemberID, &targetIdentifier, &role, &verificationID)
	if errors.Is(err, pgx.ErrNoRows) {
		_, updateErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='waiting_evidence',next_attempt_at=now()+interval '2 minutes',last_error_code='fresh_member_evidence_missing',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return false, updateErr
	}
	if err != nil {
		return false, err
	}
	// A privileged or unlabeled member is never removed by automation. The
	// verified role has to be an ordinary member seat for the case to proceed.
	if strings.TrimSpace(role) != "member" && !strings.EqualFold(strings.TrimSpace(role), "standard-user") {
		return false, blockCPAAutomationCaseTx(ctx, tx, item.ID, "protected_member_role", false)
	}
	_ = platformMemberID
	_ = targetIdentifier
	_ = verificationID
	// Automatic rotation reserves the spare before removing the degraded seat.
	// This makes the callback flow all-or-nothing from the workspace's point of
	// view: no member is kicked unless a verified replacement is available.
	if item.ReplacementAccountID == nil || item.ReplacementStandbyBatchID == nil {
		reserved, reserveErr := reserveCPAAutomaticReplacementTx(ctx, tx, &item)
		if reserveErr != nil {
			return false, reserveErr
		}
		if !reserved {
			_, updateErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='waiting_replacement',next_attempt_at=now()+interval '5 minutes',last_error_code='prepared_replacement_unavailable',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
			return false, updateErr
		}
	}
	return true, nil
}

// insertCPAAutomaticRemovalTx creates the exact single-member removal operation
// and its task. The caller has already validated evidence and reserved a seat.
func (h *OwnerAuthHandler) insertCPAAutomaticRemovalTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase) error {
	var ownerID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT operation.owner_id
		FROM tsw_batch_memberships membership
		JOIN tsw_operation_targets joined_target ON joined_target.id=membership.join_operation_target_id
		JOIN tsw_operations operation ON operation.id=joined_target.operation_id
		WHERE membership.id=$1 AND membership.state='active'`, item.MembershipID).Scan(&ownerID); err != nil {
		return err
	}
	requestHash := sha256.Sum256([]byte("teamseatwatch:cpa-auto-remove:v1\x00" + item.ID + "\x00" + item.MembershipID.String()))
	manifest, _ := json.Marshal([]string{item.MembershipID.String()})
	correlationID := "cpa-rotation:" + item.ID
	var operationID, operationTargetID uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO tsw_operations(owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id,task_concurrency)
		VALUES($1,$2,$3,'remove',$4,$5,jsonb_build_object('workspace_id',$2::uuid::text,'batch_id',$3::uuid::text,'membership_ids',$6::jsonb,'automation_case_id',$7::text),$8,1)
		ON CONFLICT(owner_id,operation_type,idempotency_key) DO UPDATE SET updated_at=now() RETURNING id`, ownerID, item.WorkspaceID, item.SourceBatchID, "cpa-rm-"+item.ID, requestHash[:], string(manifest), item.ID, correlationID).Scan(&operationID)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `INSERT INTO tsw_operation_targets(operation_id,membership_id,ordinal) VALUES($1,$2,1)
		ON CONFLICT(operation_id,ordinal) DO UPDATE SET updated_at=now() RETURNING id`, operationID, item.MembershipID).Scan(&operationTargetID)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tsw_tasks(operation_target_id,membership_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		VALUES($1,$2,$3,'remove',$4,jsonb_build_object('operation_target_id',$1::uuid::text,'membership_id',$2::uuid::text,'workspace_id',$3::uuid::text,'automation_case_id',$5::text),$6,6)
		ON CONFLICT(task_type,dedupe_key) DO NOTHING`, operationTargetID, item.MembershipID, item.WorkspaceID, "remove:"+operationTargetID.String(), item.ID, correlationID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_batch_memberships SET removal_requested_at=COALESCE(removal_requested_at,now()),updated_at=now(),version=version+1 WHERE id=$1 AND state='active'`, item.MembershipID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_batches SET status='removing',blocking_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND status='serving'`, item.SourceBatchID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='removal_queued',removal_operation_id=$2,started_at=COALESCE(started_at,now()),attempt_count=attempt_count+1,next_attempt_at=now()+interval '5 seconds',last_error_code=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ID, operationID)
	return err
}

func reserveCPAAutomaticReplacementTx(ctx context.Context, tx pgx.Tx, item *cpaAutomationCase) (bool, error) {
	if err := ensureCPASparePoolTx(ctx, tx); err != nil {
		return false, err
	}
	var replacementAccountID, standbyBatchID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT account.id,standby.batch_id
			FROM tsw_standby_child_memberships standby
			JOIN tsw_standby_child_batches standby_batch ON standby_batch.id=standby.batch_id AND standby_batch.deleted_at IS NULL
			JOIN tsw_target_accounts account ON account.id=standby.target_account_id AND account.status='active'
			JOIN tsw_target_credentials credentials ON credentials.target_account_id=account.id AND credentials.material_status='complete' AND credentials.materials_sealed
			JOIN tsw_target_personal_access personal_access ON personal_access.target_account_id=account.id AND personal_access.secret_revision=credentials.secret_revision AND personal_access.status='ready'
			JOIN tsw_target_personal_sessions personal_session ON personal_session.target_account_id=account.id AND personal_session.secret_revision=credentials.secret_revision AND personal_session.attempt=personal_access.attempt AND personal_session.expires_at>now()+interval '5 minutes'
			WHERE credentials.latest_probe_status='available' AND credentials.latest_probed_at>now()-interval '24 hours'
			AND NOT EXISTS(SELECT 1 FROM tsw_batch_memberships membership WHERE membership.target_account_id=account.id AND membership.state='active')
            AND NOT EXISTS(SELECT 1 FROM tsw_cpa_credentials remote WHERE remote.present AND remote.email_key_version=account.identifier_key_version AND remote.email_hmac=account.identifier_hmac)
			AND NOT EXISTS(SELECT 1 FROM tsw_rotation_effective_protections protection WHERE protection.target_account_id=account.id AND protection.status<>'none')
			AND NOT EXISTS(SELECT 1 FROM tsw_batch_memberships membership JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id JOIN tsw_delivery_versions delivered ON delivered.oauth_asset_id=asset.id WHERE membership.target_account_id=account.id)
			AND NOT EXISTS(SELECT 1 FROM tsw_cpa_rotation_cases active_case WHERE active_case.replacement_account_id=account.id AND active_case.id<>$1 AND active_case.status NOT IN ('completed','failed','dismissed'))
			AND NOT EXISTS(SELECT 1 FROM tsw_operation_targets target JOIN tsw_operations operation ON operation.id=target.operation_id WHERE target.target_account_id=account.id AND operation.operation_type='join' AND operation.status IN ('queued','running','awaiting_login','blocked'))
			ORDER BY credentials.latest_probed_at DESC,account.created_at,account.id
			FOR UPDATE OF standby,account,credentials,personal_access,personal_session SKIP LOCKED LIMIT 1`, item.ID).Scan(&replacementAccountID, &standbyBatchID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET replacement_account_id=$2,replacement_standby_batch_id=$3,last_error_code=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ID, replacementAccountID, standbyBatchID); err != nil {
		return false, err
	}
	item.ReplacementAccountID = &replacementAccountID
	item.ReplacementStandbyBatchID = &standbyBatchID
	return true, nil
}

func (h *OwnerAuthHandler) observeCPAAutomaticRemovalTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase) error {
	if item.RemovalOperationID == nil {
		return blockCPAAutomationCaseTx(ctx, tx, item.ID, "removal_operation_missing", true)
	}
	var operationStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM tsw_operations WHERE id=$1 AND operation_type='remove'`, item.RemovalOperationID).Scan(&operationStatus); err != nil {
		return err
	}
	switch operationStatus {
	case "queued", "running":
		_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='removal_running',next_attempt_at=now()+interval '5 seconds',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return err
	case "succeeded":
		_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='removal_verified',next_attempt_at=now(),last_error_code=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return err
	case "blocked", "failed":
		return blockCPAAutomationCaseTx(ctx, tx, item.ID, "automatic_removal_failed", true)
	default:
		return blockCPAAutomationCaseTx(ctx, tx, item.ID, "automatic_removal_unknown", true)
	}
}

func (h *OwnerAuthHandler) queueCPAAutomaticReplacementTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase) error {
	if item.ReplacementAccountID == nil || item.ReplacementStandbyBatchID == nil {
		reserved, err := reserveCPAAutomaticReplacementTx(ctx, tx, &item)
		if err != nil {
			return err
		}
		if !reserved {
			_, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='waiting_replacement',next_attempt_at=now()+interval '1 minute',last_error_code='prepared_replacement_unavailable_after_removal',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
			return err
		}
	}
	var ownerID, bindingID uuid.UUID
	var verificationID int64
	var standbyName string
	err := tx.QueryRow(ctx, `SELECT operation.owner_id,binding.id,verification.id,standby.name
		FROM tsw_batches source_batch
		JOIN tsw_mother_workspace_bindings binding ON binding.id=source_batch.binding_id AND binding.workspace_id=$2 AND binding.ended_at IS NULL
		JOIN tsw_operation_targets joined_target ON joined_target.id=(SELECT membership.join_operation_target_id FROM tsw_batch_memberships membership WHERE membership.id=$3)
		JOIN tsw_operations operation ON operation.id=joined_target.operation_id
		JOIN tsw_standby_child_memberships standby_membership ON standby_membership.target_account_id=$4 AND standby_membership.batch_id=$5
		JOIN tsw_standby_child_batches standby ON standby.id=standby_membership.batch_id AND standby.deleted_at IS NULL
		JOIN LATERAL (SELECT v.id FROM tsw_workspace_verifications v WHERE v.workspace_id=binding.workspace_id AND v.mother_account_id=binding.mother_account_id AND v.outcome='verified' AND v.permission='manage' AND v.completeness='complete' AND v.expires_at>now() AND v.active_until>now() ORDER BY v.id DESC LIMIT 1) verification ON true
		JOIN tsw_target_accounts account ON account.id=$4 AND account.status='active'
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=account.id AND credentials.material_status='complete' AND credentials.materials_sealed AND credentials.latest_probe_status='available' AND credentials.latest_probed_at>now()-interval '24 hours'
		JOIN tsw_target_personal_access personal_access ON personal_access.target_account_id=account.id AND personal_access.secret_revision=credentials.secret_revision AND personal_access.status='ready'
		JOIN tsw_target_personal_sessions personal_session ON personal_session.target_account_id=account.id AND personal_session.secret_revision=credentials.secret_revision AND personal_session.attempt=personal_access.attempt AND personal_session.expires_at>now()+interval '5 minutes'
		WHERE source_batch.id=$1 AND NOT EXISTS(SELECT 1 FROM tsw_batch_memberships membership WHERE membership.target_account_id=account.id AND membership.state='active')
            AND NOT EXISTS(SELECT 1 FROM tsw_cpa_credentials remote WHERE remote.present AND remote.email_key_version=account.identifier_key_version AND remote.email_hmac=account.identifier_hmac)
		FOR UPDATE OF binding`, item.SourceBatchID, item.WorkspaceID, item.MembershipID, item.ReplacementAccountID, item.ReplacementStandbyBatchID).Scan(&ownerID, &bindingID, &verificationID, &standbyName)
	if errors.Is(err, pgx.ErrNoRows) {
		_, updateErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='waiting_replacement',replacement_account_id=NULL,replacement_standby_batch_id=NULL,next_attempt_at=now()+interval '1 minute',last_error_code='replacement_reservation_stale',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return updateErr
	}
	if err != nil {
		return err
	}
	var replacementBatchID uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO tsw_batches(binding_id,sequence_no,status,planned_at,source_standby_batch_id,source_batch_name)
		SELECT $1,COALESCE(max(sequence_no),0)+1,'joining',now(),$2,$3 FROM tsw_batches WHERE binding_id=$1 RETURNING id`, bindingID, item.ReplacementStandbyBatchID, standbyName).Scan(&replacementBatchID)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tsw_batch_targets(batch_id,target_account_id,ordinal) VALUES($1,$2,1)`, replacementBatchID, item.ReplacementAccountID); err != nil {
		return err
	}
	requestHash := sha256.Sum256([]byte("teamseatwatch:cpa-auto-join:v1\x00" + item.ID + "\x00" + item.ReplacementAccountID.String()))
	correlationID := "cpa-rotation:" + item.ID
	var operationID, operationTargetID uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO tsw_operations(owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id,task_concurrency)
		VALUES($1,$2,$3,'join',$4,$5,jsonb_build_object('workspace_id',$2::uuid::text,'batch_id',$3::uuid::text,'target_account_ids',jsonb_build_array($6::text),'seat_type','prolite','verification_id',$7::bigint,'automation_case_id',$8::text),$9,1) RETURNING id`, ownerID, item.WorkspaceID, replacementBatchID, "cpa-jn-"+item.ID, requestHash[:], item.ReplacementAccountID, verificationID, item.ID, correlationID).Scan(&operationID)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `INSERT INTO tsw_operation_targets(operation_id,target_account_id,ordinal) VALUES($1,$2,1) RETURNING id`, operationID, item.ReplacementAccountID).Scan(&operationTargetID)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		VALUES($1,$2,$3,'join',$4,jsonb_build_object('operation_target_id',$1::uuid::text,'workspace_id',$2::uuid::text,'target_account_id',$3::uuid::text,'automation_case_id',$5::text),$6,3)`, operationTargetID, item.WorkspaceID, item.ReplacementAccountID, "join:"+operationTargetID.String(), item.ID, correlationID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='replacement_queued',replacement_operation_id=$2,replacement_batch_id=$3,next_attempt_at=now()+interval '5 seconds',last_error_code=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ID, operationID, replacementBatchID)
	return err
}

// observeCPAAutomaticReplacementTx advances the replacement half of a case. It
// returns a delivery action when the published credential still has to be
// registered in CPA; the case only reaches "completed" after that write is
// observed, never on the strength of an internal OAuth version alone.
func (h *OwnerAuthHandler) observeCPAAutomaticReplacementTx(ctx context.Context, tx pgx.Tx, item cpaAutomationCase) (*cpaRotationAction, error) {
	if item.ReplacementOperationID == nil || item.ReplacementBatchID == nil || item.ReplacementAccountID == nil {
		return nil, blockCPAAutomationCaseTx(ctx, tx, item.ID, "replacement_operation_missing", true)
	}
	if item.Status == "delivering" {
		return h.leaseCPADelivery(ctx, tx, item.ID, cpaDeliveryReplacement)
	}
	var operationStatus string
	var invited bool
	if err := tx.QueryRow(ctx, `SELECT operation.status,EXISTS(SELECT 1 FROM tsw_operation_targets target WHERE target.operation_id=operation.id AND target.invitation_confirmed_at IS NOT NULL) FROM tsw_operations operation WHERE operation.id=$1 AND operation.operation_type='join'`, item.ReplacementOperationID).Scan(&operationStatus, &invited); err != nil {
		return nil, err
	}
	if operationStatus == "awaiting_login" && invited {
		idempotencyKey := "cpa-login-" + item.ID
		if _, err := tx.Exec(ctx, `UPDATE tsw_batches SET login_started_at=COALESCE(login_started_at,now()),login_task_concurrency=1,updated_at=now(),version=version+1 WHERE id=$1`, item.ReplacementBatchID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
			SELECT target.id,$2,target.target_account_id,'join','workspace-oauth:'||target.id::text||':'||$3,jsonb_build_object('operation_target_id',target.id::text,'workspace_id',$2::uuid::text,'target_account_id',target.target_account_id::text,'automation_case_id',$4::text),$5,3
			FROM tsw_operation_targets target WHERE target.operation_id=$1 AND target.invitation_confirmed_at IS NOT NULL AND target.membership_id IS NULL
			AND NOT EXISTS(SELECT 1 FROM tsw_tasks active WHERE active.operation_target_id=target.id AND active.status IN ('queued','retry_wait','running')) ON CONFLICT(task_type,dedupe_key) DO NOTHING`, item.ReplacementOperationID, item.WorkspaceID, idempotencyKey, item.ID, "cpa-rotation:"+item.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='queued',completed_at=NULL,updated_at=now(),version=version+1 WHERE operation_id=$1 AND invitation_confirmed_at IS NOT NULL AND membership_id IS NULL`, item.ReplacementOperationID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE tsw_operations SET status='queued',completed_at=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.ReplacementOperationID); err != nil {
			return nil, err
		}
		_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='replacement_running',next_attempt_at=now()+interval '5 seconds',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return nil, err
	}
	switch operationStatus {
	case "queued", "running", "awaiting_login":
		_, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='replacement_running',next_attempt_at=now()+interval '5 seconds',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
		return nil, err
	case "succeeded":
		var payload []byte
		var email string
		err := tx.QueryRow(ctx, `SELECT delivery.payload,target.identifier
			FROM tsw_batch_memberships membership
			JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
			JOIN tsw_delivery_versions delivery ON delivery.id=asset.current_delivery_version_id AND delivery.oauth_asset_id=asset.id
			JOIN tsw_target_accounts target ON target.id=membership.target_account_id
			WHERE membership.batch_id=$1 AND membership.target_account_id=$2 AND membership.state='active' AND asset.status='ready'`, item.ReplacementBatchID, item.ReplacementAccountID).Scan(&payload, &email)
		if errors.Is(err, pgx.ErrNoRows) {
			_, updateErr := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='credentials_pending',next_attempt_at=now()+interval '5 seconds',last_error_code='replacement_credentials_pending',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
			return nil, updateErr
		}
		if err != nil {
			return nil, err
		}
		if h.cpaCredentials == nil {
			// Without a management attachment the credential is generated but
			// never registered, so the case must not claim completion.
			_, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='credentials_pending',next_attempt_at=now()+interval '10 minutes',last_error_code='cpa_delivery_unconfigured',updated_at=now(),version=version+1 WHERE id=$1`, item.ID)
			return nil, err
		}
		credential, err := buildCPAReplacement(payload, email)
		if err != nil {
			return nil, blockCPAAutomationCaseTx(ctx, tx, item.ID, "replacement_credential_payload_invalid", true)
		}
		if err = beginCPAAutomaticDeliveryTx(ctx, tx, item, credential.Name, credential.Revision, email); err != nil {
			return nil, err
		}
		return h.leaseCPADelivery(ctx, tx, item.ID, cpaDeliveryReplacement)
	case "blocked", "failed":
		return nil, blockCPAAutomationCaseTx(ctx, tx, item.ID, "automatic_replacement_failed", true)
	default:
		return nil, blockCPAAutomationCaseTx(ctx, tx, item.ID, "automatic_replacement_unknown", true)
	}
}

func blockCPAAutomationCaseTx(ctx context.Context, tx pgx.Tx, caseID, code string, tripCircuit bool) error {
	if _, err := tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='blocked',last_error_code=$2,completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, caseID, code); err != nil {
		return err
	}
	if !tripCircuit {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE tsw_cpa_automation_settings SET failure_count=failure_count+1,circuit_open_until=CASE WHEN failure_count+1>=3 THEN now()+interval '30 minutes' ELSE circuit_open_until END,updated_at=now() WHERE singleton`)
	return err
}

func (h *OwnerAuthHandler) runCPAAutomationLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if refreshed, refreshErr := h.refreshCPAEvidenceOnce(ctx); refreshErr != nil {
				slog.WarnContext(ctx, "cpa_evidence_refresh_failed", "refreshed", refreshed, "error", refreshErr)
			}
			if _, retryErr := h.retryUnmappedCPAEvent(ctx); retryErr != nil {
				slog.WarnContext(ctx, "cpa_event_remap_failed", "error", retryErr)
			}
			if _, prepareErr := h.prepareCPASpareOnce(ctx); prepareErr != nil {
				slog.WarnContext(ctx, "cpa_spare_preparation_failed", "error", prepareErr)
			}
			processed, err := h.reconcileCPAAutomationOnce(ctx)
			if err != nil {
				slog.ErrorContext(ctx, "cpa_automatic_rotation_reconcile_failed", "error", err)
			} else if processed {
				slog.DebugContext(ctx, "cpa_automatic_rotation_reconciled")
			}
		}
	}
}

func loadCPAEventByEventID(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, eventID uuid.UUID) (cpaEventRow, error) {
	return scanCPAEvent(query.QueryRow(ctx, cpaEventSelect+` WHERE event.event_id=$1`, eventID))
}

const cpaEventSelect = `SELECT event.id::text,event.event_id::text,event.credential_id,event.credential_revision,event.normalized_email,event.expected_model,event.detected_model,event.confidence,event.observed_at,event.event_status,event.mapping_status,event.mapping_message,event.received_at,event.mapped_at,event.dismissed_at,event.updated_at,event.target_account_id,event.membership_id,event.workspace_id,event.rotation_case_id FROM tsw_cpa_degradation_events event`

func scanCPAEvent(row pgx.Row) (cpaEventRow, error) {
	var item cpaEventRow
	err := row.Scan(&item.ID, &item.EventID, &item.CredentialID, &item.CredentialRevision, &item.Email, &item.ExpectedModel, &item.DetectedModel, &item.Confidence, &item.ObservedAt, &item.EventStatus, &item.MappingStatus, &item.MappingMessage, &item.ReceivedAt, &item.MappedAt, &item.DismissedAt, &item.UpdatedAt, &item.TargetAccountID, &item.MembershipID, &item.WorkspaceID, &item.RotationCaseID)
	return item, err
}

func cpaEventDTO(item cpaEventRow) ownerapi.CPADegradationEvent {
	dto := ownerapi.CPADegradationEvent{Id: uuid.MustParse(item.ID), EventId: uuid.MustParse(item.EventID), CredentialId: item.CredentialID, CredentialRevision: item.CredentialRevision, Email: openapi_types.Email(item.Email), ExpectedModel: item.ExpectedModel, DetectedModel: item.DetectedModel, Confidence: float32(item.Confidence), ObservedAt: item.ObservedAt, EventStatus: ownerapi.CPADegradationEventStatus(item.EventStatus), MappingStatus: ownerapi.CPADegradationMappingStatus(item.MappingStatus), MappingMessage: item.MappingMessage, ReceivedAt: item.ReceivedAt, UpdatedAt: item.UpdatedAt}
	if item.MappedAt != nil {
		dto.MappedAt = item.MappedAt
	}
	if item.DismissedAt != nil {
		dto.DismissedAt = item.DismissedAt
	}
	if item.TargetAccountID != nil {
		value := openapi_types.UUID(*item.TargetAccountID)
		dto.TargetAccountId = &value
	}
	if item.MembershipID != nil {
		value := openapi_types.UUID(*item.MembershipID)
		dto.MembershipId = &value
	}
	if item.WorkspaceID != nil {
		value := openapi_types.UUID(*item.WorkspaceID)
		dto.WorkspaceId = &value
	}
	if item.RotationCaseID != nil {
		value := openapi_types.UUID(*item.RotationCaseID)
		dto.RotationCaseId = &value
	}
	return dto
}

func (h *OwnerAuthHandler) ListCPADegradationEvents(w http.ResponseWriter, r *http.Request, params ownerapi.ListCPADegradationEventsParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.Page, params.PageSize)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, "invalid_pagination", "Invalid Pagination", "Pagination is invalid", 0)
		return
	}
	where, args := "", []any{}
	if params.Status != nil {
		where, args = " WHERE event.mapping_status=$1", append(args, string(*params.Status))
	}
	var total int
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_cpa_degradation_events event`+where, args...).Scan(&total); err != nil {
		writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query events", 0)
		return
	}
	args = append(args, size, (page-1)*size)
	rows, err := h.pool.Query(r.Context(), cpaEventSelect+where+` ORDER BY event.received_at DESC,event.id DESC LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query events", 0)
		return
	}
	defer rows.Close()
	items := []ownerapi.CPADegradationEvent{}
	for rows.Next() {
		item, err := scanCPAEvent(rows)
		if err != nil {
			writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query events", 0)
			return
		}
		items = append(items, cpaEventDTO(item))
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query events", 0)
		return
	}
	writeJSON(w, http.StatusOK, ownerapi.CPADegradationEventList{Items: items, Page: page, PageSize: size, Total: total})
}

func (h *OwnerAuthHandler) GetCPADegradationEvent(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	item, err := scanCPAEvent(h.pool.QueryRow(r.Context(), cpaEventSelect+` WHERE event.id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "event_not_found", "Not Found", "Event not found", 0)
		return
	}
	if err != nil {
		writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query event", 0)
		return
	}
	writeJSON(w, http.StatusOK, cpaEventDTO(item))
}

func (h *OwnerAuthHandler) RetryMapCPADegradationEvent(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, _ ownerapi.RetryMapCPADegradationEventParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	defer tx.Rollback(r.Context())
	var eventID uuid.UUID
	var email, status string
	if err = tx.QueryRow(r.Context(), `SELECT event_id,normalized_email,mapping_status FROM tsw_cpa_degradation_events WHERE id=$1 FOR UPDATE`, id).Scan(&eventID, &email, &status); errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "event_not_found", "Not Found", "Event not found", 0)
		return
	} else if err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	if status == "dismissed" {
		writeProblem(w, r, 409, "event_dismissed", "Conflict", "Dismissed events cannot be remapped", 0)
		return
	}
	if err = h.mapCPAEventTx(r.Context(), tx, eventID, email); err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	item, err := scanCPAEvent(tx.QueryRow(r.Context(), cpaEventSelect+` WHERE event.id=$1`, id))
	if err != nil || tx.Commit(r.Context()) != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	writeJSON(w, http.StatusOK, cpaEventDTO(item))
}

func (h *OwnerAuthHandler) DismissCPADegradationEvent(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, _ ownerapi.DismissCPADegradationEventParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	defer tx.Rollback(r.Context())
	var mappingStatus string
	var rotationCaseID *uuid.UUID
	dismissLinkedEvents := false
	if err = tx.QueryRow(r.Context(), `SELECT mapping_status,rotation_case_id FROM tsw_cpa_degradation_events WHERE id=$1 FOR UPDATE`, id).Scan(&mappingStatus, &rotationCaseID); errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "event_not_found", "Not Found", "Event not found", 0)
		return
	} else if err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	if mappingStatus == "dismissed" {
		writeProblem(w, r, 404, "event_not_found", "Not Found", "Event not found or already dismissed", 0)
		return
	}
	if rotationCaseID != nil {
		var caseStatus string
		if err = tx.QueryRow(r.Context(), `SELECT status FROM tsw_cpa_rotation_cases WHERE id=$1 FOR UPDATE`, rotationCaseID).Scan(&caseStatus); err != nil {
			writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
			return
		}
		switch caseStatus {
		case "pending_automation", "waiting_evidence", "waiting_replacement":
			if _, err = tx.Exec(r.Context(), `UPDATE tsw_cpa_rotation_cases SET status='dismissed',replacement_account_id=NULL,replacement_standby_batch_id=NULL,last_error_code='dismissed_by_owner',completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, rotationCaseID); err != nil {
				writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
				return
			}
			dismissLinkedEvents = true
		case "completed", "blocked", "failed", "dismissed":
			// Terminal cases are retained as immutable automation audit records.
		default:
			writeProblem(w, r, 409, "rotation_already_started", "Conflict", "Automatic rotation has already started and cannot be dismissed", 0)
			return
		}
	}
	if _, err = tx.Exec(r.Context(), `UPDATE tsw_cpa_degradation_events SET mapping_status='dismissed',target_account_id=NULL,membership_id=NULL,workspace_id=NULL,rotation_case_id=NULL,mapping_message='Dismissed by owner',dismissed_at=now(),updated_at=now(),version=version+1 WHERE id=$1 OR ($2 AND rotation_case_id=$3)`, id, dismissLinkedEvents, rotationCaseID); err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	item, err := scanCPAEvent(tx.QueryRow(r.Context(), cpaEventSelect+` WHERE event.id=$1`, id))
	if err != nil {
		writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query event", 0)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	writeJSON(w, http.StatusOK, cpaEventDTO(item))
}
