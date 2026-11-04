package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
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
	status, message := "not_found", "No active Team membership matched the credential email"
	var account, membership, workspace *uuid.UUID
	if len(matches) == 1 {
		status, message = "pending_rotation", "Unique active Team membership mapped; awaiting manual review"
		account, membership, workspace = &matches[0].account, &matches[0].membership, &matches[0].workspace
	} else if len(matches) > 1 {
		status, message = "ambiguous", "Multiple active Team memberships matched the credential email"
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_cpa_degradation_events SET normalized_email=$2,mapping_status=$3,target_account_id=$4,membership_id=$5,workspace_id=$6,mapping_message=$7,mapped_at=now(),updated_at=now(),version=version+1 WHERE event_id=$1`, eventID, normalized, status, account, membership, workspace, message)
	return err
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
	result, err := h.pool.Exec(r.Context(), `UPDATE tsw_cpa_degradation_events SET mapping_status='dismissed',target_account_id=NULL,membership_id=NULL,workspace_id=NULL,rotation_case_id=NULL,mapping_message='Dismissed by owner',dismissed_at=now(),updated_at=now(),version=version+1 WHERE id=$1 AND mapping_status<>'dismissed'`, id)
	if err != nil {
		writeProblem(w, r, 500, "event_update_failed", "Internal Server Error", "Unable to update event", 0)
		return
	}
	if result.RowsAffected() == 0 {
		writeProblem(w, r, 404, "event_not_found", "Not Found", "Event not found or already dismissed", 0)
		return
	}
	item, err := scanCPAEvent(h.pool.QueryRow(r.Context(), cpaEventSelect+` WHERE event.id=$1`, id))
	if err != nil {
		writeProblem(w, r, 500, "event_query_failed", "Internal Server Error", "Unable to query event", 0)
		return
	}
	writeJSON(w, http.StatusOK, cpaEventDTO(item))
}
