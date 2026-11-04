package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
)

const cpaDecisionBodyLimit = 4 << 10

type cpaRotationCaseRow struct {
	ID                   string
	EventID, WorkspaceID string
	MembershipID         *string
	CredentialID, Status string
	AttemptCount         int
	LastErrorCode        *string
	NextAttemptAt        time.Time
	RemovalOperationID   *string
	ReplacementOperation *string
	ReplacementAccount   *string
	CompletedAt          *time.Time
	CreatedAt, UpdatedAt time.Time
	Version              int64
}

const cpaRotationCaseSelect = `SELECT rotation.id::text,event.event_id::text,rotation.workspace_id::text,rotation.membership_id::text,
	rotation.credential_id,rotation.status,rotation.attempt_count,rotation.last_error_code,rotation.next_attempt_at,
	rotation.removal_operation_id::text,rotation.replacement_operation_id::text,rotation.replacement_account_id::text,
	rotation.completed_at,rotation.created_at,rotation.updated_at,rotation.version
	FROM tsw_cpa_rotation_cases rotation
	JOIN tsw_cpa_degradation_events event ON event.id=rotation.event_id`

func scanCPARotationCase(row pgx.Row) (cpaRotationCaseRow, error) {
	var item cpaRotationCaseRow
	err := row.Scan(&item.ID, &item.EventID, &item.WorkspaceID, &item.MembershipID, &item.CredentialID, &item.Status,
		&item.AttemptCount, &item.LastErrorCode, &item.NextAttemptAt, &item.RemovalOperationID, &item.ReplacementOperation,
		&item.ReplacementAccount, &item.CompletedAt, &item.CreatedAt, &item.UpdatedAt, &item.Version)
	return item, err
}

func cpaRotationCaseDTO(item cpaRotationCaseRow) ownerapi.CPARotationCase {
	status := item.Status
	if status == "awaiting_approval" {
		// Rows created before automatic execution are exposed using the current
		// contract while the reconciler migrates them on its next pass.
		status = "pending_automation"
	}
	dto := ownerapi.CPARotationCase{
		Id:            uuid.MustParse(item.ID),
		EventId:       uuid.MustParse(item.EventID),
		CredentialId:  item.CredentialID,
		Status:        ownerapi.CPARotationCaseStatus(status),
		AttemptCount:  item.AttemptCount,
		NextAttemptAt: item.NextAttemptAt,
		CreatedAt:     item.CreatedAt,
		UpdatedAt:     item.UpdatedAt,
		Version:       int(item.Version),
	}
	if item.LastErrorCode != nil {
		dto.LastErrorCode = item.LastErrorCode
	}
	if item.MembershipID != nil {
		value := openapi_types.UUID(uuid.MustParse(*item.MembershipID))
		dto.MembershipId = &value
	}
	if item.WorkspaceID != "" {
		value := openapi_types.UUID(uuid.MustParse(item.WorkspaceID))
		dto.WorkspaceId = &value
	}
	if item.RemovalOperationID != nil {
		value := openapi_types.UUID(uuid.MustParse(*item.RemovalOperationID))
		dto.RemovalOperationId = &value
	}
	if item.ReplacementOperation != nil {
		value := openapi_types.UUID(uuid.MustParse(*item.ReplacementOperation))
		dto.ReplacementOperationId = &value
	}
	if item.ReplacementAccount != nil {
		value := openapi_types.UUID(uuid.MustParse(*item.ReplacementAccount))
		dto.ReplacementAccountId = &value
	}
	if item.CompletedAt != nil {
		dto.CompletedAt = item.CompletedAt
	}
	return dto
}

// ListCPARotationCases reports every case with its current stage. It is read only:
// no case advances because it was listed.
func (h *OwnerAuthHandler) ListCPARotationCases(w http.ResponseWriter, r *http.Request, params ownerapi.ListCPARotationCasesParams) {
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
		where, args = " WHERE rotation.status=$1", append(args, string(*params.Status))
	}
	var total int
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_cpa_rotation_cases rotation`+where, args...).Scan(&total); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_query_failed", "Internal Server Error", "Unable to query rotation cases", 0)
		return
	}
	args = append(args, size, (page-1)*size)
	rows, err := h.pool.Query(r.Context(), cpaRotationCaseSelect+where+
		fmt.Sprintf(` ORDER BY rotation.created_at DESC,rotation.id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_query_failed", "Internal Server Error", "Unable to query rotation cases", 0)
		return
	}
	defer rows.Close()
	items := []ownerapi.CPARotationCase{}
	for rows.Next() {
		item, scanErr := scanCPARotationCase(rows)
		if scanErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "rotation_query_failed", "Internal Server Error", "Unable to query rotation cases", 0)
			return
		}
		items = append(items, cpaRotationCaseDTO(item))
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_query_failed", "Internal Server Error", "Unable to query rotation cases", 0)
		return
	}
	writeJSON(w, http.StatusOK, ownerapi.CPARotationCaseList{Items: items, Page: page, PageSize: size, Total: total})
}

// CancelCPARotationCase terminates a case before it has any remote effect.
func (h *OwnerAuthHandler) CancelCPARotationCase(w http.ResponseWriter, r *http.Request, caseID openapi_types.UUID, _ ownerapi.CancelCPARotationCaseParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	reason, ok := decodeCPARotationDecision(w, r)
	if !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_update_failed", "Internal Server Error", "Unable to update rotation case", 0)
		return
	}
	defer tx.Rollback(r.Context())
	var status, workspaceID string
	var version int64
	if err = tx.QueryRow(r.Context(), `SELECT status,workspace_id::text,version FROM tsw_cpa_rotation_cases WHERE id=$1 FOR UPDATE`, caseID).Scan(&status, &workspaceID, &version); errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "rotation_case_not_found", "Not Found", "Rotation case not found", 0)
		return
	} else if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_update_failed", "Internal Server Error", "Unable to update rotation case", 0)
		return
	}
	if status == "completed" || status == "blocked" || status == "failed" || status == "dismissed" || !cpaCaseCancellable(status) {
		writeProblem(w, r, http.StatusConflict, "rotation_already_started", "Conflict", "Rotation case has already started or ended", 0)
		return
	}
	var updated int64
	if err = tx.QueryRow(r.Context(), `UPDATE tsw_cpa_rotation_cases SET status='dismissed',completed_at=now(),last_error_code='cancelled_by_owner',updated_at=now(),version=version+1 WHERE id=$1 RETURNING version`, caseID).Scan(&updated); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_update_failed", "Internal Server Error", "Unable to update rotation case", 0)
		return
	}
	digest := sha256.Sum256([]byte("cancelled\x00" + caseID.String() + "\x00" + fmt.Sprint(updated)))
	if _, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.CPARotationCancelled, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID, EntityType: "cpa_rotation", EntityID: caseID.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.CPARotationDecisionDetails{Action: "cancelled", Result: "cancelled", Reason: reason, CaseVersion: updated}, IdempotencyKey: caseID.String() + ":cancelled:" + hex.EncodeToString(digest[:8])}); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_update_failed", "Internal Server Error", "Unable to record cancellation", 0)
		return
	}
	item, err := scanCPARotationCase(tx.QueryRow(r.Context(), cpaRotationCaseSelect+` WHERE rotation.id=$1`, caseID))
	if err != nil || tx.Commit(r.Context()) != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rotation_update_failed", "Internal Server Error", "Unable to update rotation case", 0)
		return
	}
	writeJSON(w, http.StatusOK, cpaRotationCaseDTO(item))
}

// cpaCaseCancellable lists the stages in which cancelling has no remote effect.
// Every stage from quarantining onward already has a CPA write or a queued Team
// operation behind it, so cancelling there would orphan that effect.
func cpaCaseCancellable(status string) bool {
	switch status {
	case "pending_automation", "waiting_evidence":
		return true
	default:
		return false
	}
}

func decodeCPARotationDecision(w http.ResponseWriter, r *http.Request) (string, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, cpaDecisionBodyLimit+1))
	if err != nil || len(body) == 0 || len(body) > cpaDecisionBodyLimit {
		writeProblem(w, r, http.StatusBadRequest, "invalid_decision", "Invalid Decision", "Decision payload is invalid", 0)
		return "", false
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var payload ownerapi.CPARotationDecision
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF {
		writeProblem(w, r, http.StatusBadRequest, "invalid_decision", "Invalid Decision", "Decision payload is invalid", 0)
		return "", false
	}
	reason := strings.TrimSpace(payload.Reason)
	if reason == "" || len([]rune(reason)) > 500 {
		writeProblem(w, r, http.StatusBadRequest, "invalid_decision", "Invalid Decision", "A bounded reason is required", 0)
		return "", false
	}
	return reason, true
}

// refreshCPACaseEvidenceIfWaiting is intentionally side-effect free inside the
// automation transaction. Selected-workspace verification performs network I/O
// and is claimed by refreshCPAEvidenceOnce outside this transaction.
func (h *OwnerAuthHandler) refreshCPACaseEvidenceIfWaiting(ctx context.Context, tx pgx.Tx, item cpaAutomationCase) error {
	return nil
}
