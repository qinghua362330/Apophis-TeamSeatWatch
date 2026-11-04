package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
)

type removalQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type removalSnapshotEntry struct {
	Identifier string
	Role       string
}

func (h *OwnerAuthHandler) getBatchRemovalPreview(w http.ResponseWriter, r *http.Request, params ownerapi.GetBatchRemovalPreviewParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, valid := pagination(params.TargetPage, params.TargetPageSize)
	if !valid {
		writeProblem(w, r, 400, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	tx, err := h.pool.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	batch, err := batchByIDTx(r, tx, r.PathValue("batchId"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "removal_batch_not_found", "Not Found", "The current batch was not found", 0)
		return
	}
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	preview, err := removalPreview(r.Context(), tx, batch)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	// Authorization always checks the complete frozen scope. Only the requested
	// member page and a bounded difference sample cross the Owner API boundary.
	preview.TargetTotal = int64(len(preview.Targets))
	preview.TargetPage = page
	preview.TargetPageSize = size
	preview.DifferenceTotal = len(preview.Differences)
	start := min((page-1)*size, len(preview.Targets))
	end := min(start+size, len(preview.Targets))
	preview.Targets = preview.Targets[start:end]
	preview.Differences = preview.Differences[:min(20, len(preview.Differences))]
	if err = tx.Commit(r.Context()); err != nil {
		h.removalFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func removalPreview(ctx context.Context, query removalQuerier, batch ownerapi.Batch) (ownerapi.RemovalPreview, error) {
	preview := ownerapi.RemovalPreview{Batch: batch, Targets: []ownerapi.RemovalPreviewTarget{}, Differences: []ownerapi.RemovalDifference{}, Blockers: []ownerapi.PreviewBlocker{}, SnapshotCompleteness: "unknown"}
	var operationalState, ownerIdentifier string
	var evidenceExpiresAt, snapshotExpiresAt *time.Time
	var snapshotID, snapshotSource *string
	var snapshotObserved *time.Time
	var declaredCount *int
	err := query.QueryRow(ctx, `SELECT projection.operational_state,projection.evidence_expires_at,projection.latest_snapshot_id::text,
		snapshot.observed_at,snapshot.expires_at,snapshot.source_endpoint,snapshot.declared_member_count,credentials.login_identifier,
		COALESCE(snapshot.completeness,'unknown')
		FROM tsw_batches batch
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.ended_at IS NULL
		JOIN tsw_workspace_projections projection ON projection.workspace_id=binding.workspace_id
		JOIN tsw_mother_account_credentials credentials ON credentials.mother_account_id=binding.mother_account_id
		LEFT JOIN tsw_workspace_member_snapshots snapshot ON snapshot.id=projection.latest_snapshot_id
		WHERE batch.id=$1`, batch.Id).Scan(&operationalState, &evidenceExpiresAt, &snapshotID,
		&snapshotObserved, &snapshotExpiresAt, &snapshotSource, &declaredCount, &ownerIdentifier, &preview.SnapshotCompleteness)
	if err != nil {
		return preview, err
	}
	preview.SnapshotObservedAt, preview.SnapshotSource, preview.DeclaredMemberCount = snapshotObserved, snapshotSource, declaredCount

	targetRows, err := query.Query(ctx, `SELECT membership.id::text,membership.target_account_id::text,target.display_label,target.identifier,membership.state,membership.joined_at,membership.removed_at
		FROM tsw_batch_memberships membership
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id
		WHERE membership.batch_id=$1 ORDER BY membership.joined_at,membership.id`, batch.Id)
	if err != nil {
		return preview, err
	}
	targetIdentifiers := map[string]bool{}
	for targetRows.Next() {
		var membershipID, targetID, displayLabel, identifier, state string
		var joinedAt time.Time
		var removedAt *time.Time
		if err := targetRows.Scan(&membershipID, &targetID, &displayLabel, &identifier, &state, &joinedAt, &removedAt); err != nil {
			targetRows.Close()
			return preview, err
		}
		membershipUUID, membershipErr := uuid.Parse(membershipID)
		targetUUID, targetErr := uuid.Parse(targetID)
		if membershipErr != nil || targetErr != nil {
			targetRows.Close()
			return preview, errors.New("invalid removal target identity")
		}
		preview.Targets = append(preview.Targets, ownerapi.RemovalPreviewTarget{MembershipId: membershipUUID, TargetAccountId: targetUUID, DisplayLabel: displayLabel, Identifier: identifier, JoinedAt: &joinedAt, RemovedAt: removedAt, State: ownerapi.RemovalPreviewTargetStateAbsent})
		targetIdentifiers[strings.ToLower(strings.TrimSpace(identifier))] = true
		if state == "removed" {
			preview.Targets[len(preview.Targets)-1].State = ownerapi.RemovalPreviewTargetStateRemoved
		}
	}
	targetRows.Close()
	if err := targetRows.Err(); err != nil {
		return preview, err
	}

	entries := []removalSnapshotEntry{}
	if snapshotID != nil {
		rows, err := query.Query(ctx, `SELECT member_identifier,COALESCE(platform_role,'') FROM tsw_workspace_member_snapshot_entries WHERE snapshot_id=$1 AND entry_kind='member' ORDER BY member_identifier`, *snapshotID)
		if err != nil {
			return preview, err
		}
		for rows.Next() {
			var entry removalSnapshotEntry
			if err := rows.Scan(&entry.Identifier, &entry.Role); err != nil {
				rows.Close()
				return preview, err
			}
			entries = append(entries, entry)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return preview, err
		}
	}

	otherBatchIdentifiers := map[string]bool{}
	otherRows, err := query.Query(ctx, `SELECT target.identifier FROM tsw_batch_memberships membership
		JOIN tsw_batches other_batch ON other_batch.id=membership.batch_id
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id
		WHERE other_batch.binding_id=$1 AND other_batch.id<>$2 AND membership.state='active'`, batch.BindingId, batch.Id)
	if err != nil {
		return preview, err
	}
	for otherRows.Next() {
		var identifier string
		if err := otherRows.Scan(&identifier); err != nil {
			otherRows.Close()
			return preview, err
		}
		otherBatchIdentifiers[strings.ToLower(strings.TrimSpace(identifier))] = true
	}
	otherRows.Close()
	if err := otherRows.Err(); err != nil {
		return preview, err
	}

	entryByIdentifier := map[string][]removalSnapshotEntry{}
	ownerPresent := false
	for _, entry := range entries {
		identity := strings.ToLower(strings.TrimSpace(entry.Identifier))
		entryByIdentifier[identity] = append(entryByIdentifier[identity], entry)
		if identity == strings.ToLower(strings.TrimSpace(ownerIdentifier)) && removalOwnerRole(entry.Role) {
			ownerPresent = true
		}
		if targetIdentifiers[identity] {
			continue
		}
		reason := ownerapi.UnknownMember
		if removalOwnerRole(entry.Role) {
			reason = ownerapi.WorkspaceOwner
		} else if otherBatchIdentifiers[identity] {
			reason = ownerapi.OtherBatchMember
		}
		preview.Differences = append(preview.Differences, ownerapi.RemovalDifference{Identifier: entry.Identifier, Role: entry.Role, Reason: reason})
	}

	exact := snapshotID != nil && preview.SnapshotCompleteness == "complete" && declaredCount != nil && *declaredCount == len(entries) &&
		evidenceExpiresAt != nil && evidenceExpiresAt.After(time.Now()) && snapshotExpiresAt != nil && snapshotExpiresAt.After(time.Now())
	if len(preview.Targets) == 0 {
		addRemovalBlocker(&preview, "removal_targets_empty", "当前批没有已确认的成员关系")
	}
	if batch.Status != ownerapi.BatchStatusServing {
		addRemovalBlocker(&preview, "batch_not_serving", "只有当前服务中的批次可以确认移除")
	}
	if batch.PlannedAt.After(time.Now()) {
		addRemovalBlocker(&preview, "planned_time_not_reached", "计划处理时间尚未到达")
	}
	if operationalState != "operational" {
		addRemovalBlocker(&preview, "workspace_not_operational", "团队空间当前没有明确可运营证据")
	}
	if !exact {
		addRemovalBlocker(&preview, "member_snapshot_incomplete", "成员快照没有达到 100% 完整覆盖且证据仍在有效期内")
	}
	if !ownerPresent {
		addRemovalBlocker(&preview, "workspace_owner_missing", "完整快照未确认当前管理员账号仍为 Owner")
	}
	for index := range preview.Targets {
		if preview.Targets[index].State == ownerapi.RemovalPreviewTargetStateRemoved {
			continue
		}
		matches := entryByIdentifier[strings.ToLower(strings.TrimSpace(preview.Targets[index].Identifier))]
		switch {
		case len(matches) > 1:
			preview.Targets[index].State = ownerapi.RemovalPreviewTargetStateAmbiguous
			addRemovalBlocker(&preview, "target_identity_ambiguous", "至少一个批次关系无法唯一对应平台成员")
		case len(matches) == 1 && removalOwnerRole(matches[0].Role):
			preview.Targets[index].State = ownerapi.RemovalPreviewTargetStateProtectedOwner
			addRemovalBlocker(&preview, "target_is_owner", "Owner 不能进入移除目标")
		case len(matches) == 1:
			preview.Targets[index].State = ownerapi.RemovalPreviewTargetStatePresent
		default:
			preview.Targets[index].State = ownerapi.RemovalPreviewTargetStateAbsent
		}
	}
	preview.CanProceed = len(preview.Blockers) == 0
	return preview, nil
}

func addRemovalBlocker(preview *ownerapi.RemovalPreview, code, message string) {
	for _, existing := range preview.Blockers {
		if existing.Code == code {
			return
		}
	}
	preview.Blockers = append(preview.Blockers, ownerapi.PreviewBlocker{Code: code, Message: message})
}

func (h *OwnerAuthHandler) createRemovalOperation(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateRemovalOperationJSONRequestBody
	if !decodeJSON(w, r, &request) || !bool(request.Confirm) || !validConcurrency(request.Concurrency) {
		h.rejectOwnerMutation(w, r, owner, "remove.create", "remove_confirmation_required", http.StatusUnprocessableEntity, "remove_confirmation_required", "Confirmation Required", "Explicit Owner confirmation is required")
		return
	}
	batchID := r.PathValue("batchId")
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var lockedBatchID string
	if err = tx.QueryRow(r.Context(), `SELECT id FROM tsw_batches WHERE id=$1 FOR UPDATE`, batchID).Scan(&lockedBatchID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.rejectOwnerMutation(w, r, owner, "remove.create", "batch_not_found", http.StatusNotFound, "removal_batch_not_found", "Not Found", "The current batch was not found")
			return
		}
		h.removalFailure(w, r, err)
		return
	}
	batch, err := batchByIDTx(r, tx, batchID)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	preview, err := removalPreview(r.Context(), tx, batch)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	membershipIDs := make([]string, 0, len(preview.Targets))
	for _, target := range preview.Targets {
		membershipIDs = append(membershipIDs, target.MembershipId.String())
	}
	sort.Strings(membershipIDs)
	requestHash := sha256.Sum256([]byte("teamseatwatch:remove:v1\x00" + batchID + "\x00" + strings.Join(membershipIDs, "\x00")))
	var priorLimit int
	priorErr := tx.QueryRow(r.Context(), `SELECT task_concurrency FROM tsw_operations WHERE owner_id=$1 AND operation_type='remove' AND idempotency_key=$2`, owner.OwnerID, request.IdempotencyKey).Scan(&priorLimit)
	if priorErr == nil && priorLimit != selectedConcurrency(request.Concurrency) {
		writeProblem(w, r, 409, "idempotency_conflict", "Conflict", "The original task concurrency must be preserved", 0)
		return
	}
	if priorErr != nil && !errors.Is(priorErr, pgx.ErrNoRows) {
		h.removalFailure(w, r, priorErr)
		return
	}
	if _, _, handled := h.existingRemovalTx(w, r, tx, owner, request.IdempotencyKey, requestHash[:]); handled {
		return
	}
	if !preview.CanProceed {
		h.rejectOwnerMutation(w, r, owner, "remove.create", "remove_not_ready", http.StatusConflict, "remove_not_ready", "Removal Not Ready", "Current batch, Workspace, Owner, or member facts are not sufficient")
		return
	}
	membershipUUIDs := make([]uuid.UUID, 0, len(membershipIDs))
	for _, membershipID := range membershipIDs {
		membershipUUIDs = append(membershipUUIDs, uuid.MustParse(membershipID))
	}
	manifestJSON, err := json.Marshal(membershipIDs)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	var operationID string
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_operations(owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id,task_concurrency)
		VALUES ($1,$2::uuid,$3::uuid,'remove',$4,$5,jsonb_build_object('workspace_id',$2::uuid::text,'batch_id',$3::uuid::text,'membership_ids',$6::jsonb),$7,$8) RETURNING id`, owner.OwnerID, batch.WorkspaceId, batch.Id, request.IdempotencyKey, requestHash[:], string(manifestJSON), correlation(r), selectedConcurrency(request.Concurrency)).Scan(&operationID)
	if err == nil {
		for ordinal, membershipID := range membershipIDs {
			var operationTargetID string
			err = tx.QueryRow(r.Context(), `INSERT INTO tsw_operation_targets(operation_id,membership_id,ordinal) VALUES ($1,$2,$3) RETURNING id`, operationID, membershipID, ordinal+1).Scan(&operationTargetID)
			if err != nil {
				break
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO tsw_tasks(operation_target_id,membership_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
				VALUES ($1::uuid,$2::uuid,$3::uuid,'remove',$4,jsonb_build_object('operation_target_id',$1::uuid::text,'membership_id',$2::uuid::text,'workspace_id',$3::uuid::text),$5,6)`, operationTargetID, membershipID, batch.WorkspaceId, "remove:"+operationTargetID, correlation(r))
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tsw_batch_memberships SET removal_requested_at=COALESCE(removal_requested_at,now()),updated_at=now(),version=version+1 WHERE id=ANY($1::uuid[]) AND batch_id=$2`, membershipUUIDs, batch.Id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tsw_batches SET status='removing',blocking_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1`, batch.Id)
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.RemoveOperationAuthorized, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: batch.WorkspaceId.String(), EntityType: "operation", EntityID: operationID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.OperationDetails{Operation: "remove", Result: "authorized"}, IdempotencyKey: operationID + ":authorized"})
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			_ = tx.Rollback(r.Context())
			if h.writeExistingRemoval(w, r, owner, request.IdempotencyKey, requestHash[:]) {
				return
			}
			h.rejectOwnerMutation(w, r, owner, "remove.create", "conflict", http.StatusConflict, "removal_conflict", "Conflict", "This Workspace already has an active member operation")
			return
		}
		h.removalFailure(w, r, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		h.removalFailure(w, r, err)
		return
	}
	item, err := h.removalOperationByID(r, operationID, 1, 100)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (h *OwnerAuthHandler) existingRemovalTx(w http.ResponseWriter, r *http.Request, tx pgx.Tx, owner ownerContext, idempotencyKey string, requestHash []byte) (string, bool, bool) {
	var operationID string
	var storedHash []byte
	err := tx.QueryRow(r.Context(), `SELECT id,request_hash FROM tsw_operations WHERE owner_id=$1 AND operation_type='remove' AND idempotency_key=$2 FOR UPDATE`, owner.OwnerID, idempotencyKey).Scan(&operationID, &storedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, false
	}
	if err != nil {
		h.removalFailure(w, r, err)
		return "", false, true
	}
	if !bytes.Equal(storedHash, requestHash) {
		h.rejectOwnerMutation(w, r, owner, "remove.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The idempotency key belongs to a different batch")
		return "", true, true
	}
	if err = tx.Commit(r.Context()); err != nil {
		h.removalFailure(w, r, err)
		return "", true, true
	}
	item, err := h.removalOperationByID(r, operationID, 1, 100)
	if err != nil {
		h.removalFailure(w, r, err)
		return "", true, true
	}
	writeJSON(w, http.StatusAccepted, item)
	return operationID, true, true
}

func (h *OwnerAuthHandler) writeExistingRemoval(w http.ResponseWriter, r *http.Request, owner ownerContext, idempotencyKey string, requestHash []byte) bool {
	var operationID string
	var storedHash []byte
	err := h.pool.QueryRow(r.Context(), `SELECT id,request_hash FROM tsw_operations WHERE owner_id=$1 AND operation_type='remove' AND idempotency_key=$2`, owner.OwnerID, idempotencyKey).Scan(&operationID, &storedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		h.removalFailure(w, r, err)
		return true
	}
	if !bytes.Equal(storedHash, requestHash) {
		h.rejectOwnerMutation(w, r, owner, "remove.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The idempotency key belongs to a different batch")
		return true
	}
	item, err := h.removalOperationByID(r, operationID, 1, 100)
	if err != nil {
		h.removalFailure(w, r, err)
		return true
	}
	writeJSON(w, http.StatusAccepted, item)
	return true
}

func (h *OwnerAuthHandler) createRemovalReconciliation(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateRemovalReconciliationJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLength(request.IdempotencyKey, 8, 64) {
		h.rejectOwnerMutation(w, r, owner, "remove.reconcile", "invalid_request", http.StatusUnprocessableEntity, "invalid_idempotency_key", "Invalid Request", "A stable idempotency key is required")
		return
	}
	if _, err := h.workspaceTasks.EnqueueRemovalReconciliation(r.Context(), r.PathValue("batchId"), request.IdempotencyKey, correlation(r)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.rejectOwnerMutation(w, r, owner, "remove.reconcile", "conflict", http.StatusConflict, "removal_reconciliation_not_available", "Conflict", "This removal operation does not currently require reconciliation")
			return
		}
		h.removalFailure(w, r, err)
		return
	}
	item, err := h.removalOperationByBatch(r, r.PathValue("batchId"), 1, 100)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (h *OwnerAuthHandler) getRemovalOperation(w http.ResponseWriter, r *http.Request, params ownerapi.GetRemovalOperationParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.TargetPage, params.TargetPageSize)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	item, err := h.removalOperationByBatch(r, r.PathValue("batchId"), page, size)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "removal_operation_not_found", "Not Found", "The removal operation was not found", 0)
		return
	}
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *OwnerAuthHandler) listRemovalOperationsNeedingAttention(w http.ResponseWriter, r *http.Request, params ownerapi.ListRemovalOperationsNeedingAttentionParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.Page, params.PageSize)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), removalOperationSelect+`,count(*) OVER() FROM tsw_operations operation WHERE operation.operation_type=$1 AND operation.status='blocked' ORDER BY operation.updated_at DESC LIMIT $4 OFFSET $5`, "remove", 100, 0, size, (page-1)*size)
	if err != nil {
		h.removalFailure(w, r, err)
		return
	}
	defer rows.Close()
	response := ownerapi.RemovalOperationList{Items: []ownerapi.RemovalOperation{}, Page: page, PageSize: size}
	for rows.Next() {
		var total int64
		item, err := scanRemovalOperation(rowWithTotal{Rows: rows, total: &total}, 1, 100)
		if err != nil {
			h.removalFailure(w, r, err)
			return
		}
		response.Total = total
		response.Items = append(response.Items, item)
	}
	if rows.Err() != nil {
		h.removalFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

const removalOperationSelect = `SELECT operation.id,operation.batch_id,operation.workspace_id,operation.status,operation.authorized_at,operation.completed_at,operation.correlation_id,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id',page.id,'membershipId',page.membership_id,'targetAccountId',page.membership_target_account_id,'displayLabel',page.display_label,'identifier',page.identifier,'status',page.status,'outcomeCode',page.outcome_code,'diagnosticCode',page.diagnostic_code,'attemptCount',page.remove_attempt_count,'lastAttemptAt',page.last_attempt_at,'completedAt',page.completed_at) ORDER BY page.ordinal) FROM (SELECT target_result.*,membership.target_account_id AS membership_target_account_id,target.display_label,target.identifier FROM tsw_operation_targets target_result JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id JOIN tsw_target_accounts target ON target.id=membership.target_account_id WHERE target_result.operation_id=operation.id ORDER BY target_result.ordinal LIMIT $2 OFFSET $3) page),'[]'::jsonb),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status='succeeded'),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status IN ('failed','blocked','unknown')),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status NOT IN ('succeeded','failed','blocked','unknown'))`

func scanRemovalOperation(scanner interface{ Scan(...any) error }, page, size int) (ownerapi.RemovalOperation, error) {
	var item ownerapi.RemovalOperation
	var targets []byte
	err := scanner.Scan(&item.Id, &item.BatchId, &item.WorkspaceId, &item.Status, &item.AuthorizedAt, &item.CompletedAt, &item.CorrelationId, &targets, &item.TargetTotal, &item.SucceededCount, &item.BlockedCount, &item.PendingCount)
	if err != nil {
		return item, err
	}
	item.TargetPage, item.TargetPageSize = page, size
	return item, json.Unmarshal(targets, &item.Targets)
}

func (h *OwnerAuthHandler) removalOperationByID(r *http.Request, operationID string, page, size int) (ownerapi.RemovalOperation, error) {
	return scanRemovalOperation(h.pool.QueryRow(r.Context(), removalOperationSelect+` FROM tsw_operations operation WHERE operation.id=$1 AND operation.operation_type='remove'`, operationID, size, (page-1)*size), page, size)
}

func (h *OwnerAuthHandler) removalOperationByBatch(r *http.Request, batchID string, page, size int) (ownerapi.RemovalOperation, error) {
	return scanRemovalOperation(h.pool.QueryRow(r.Context(), removalOperationSelect+` FROM tsw_operations operation WHERE operation.batch_id=$1 AND operation.operation_type='remove' ORDER BY operation.created_at DESC LIMIT 1`, batchID, size, (page-1)*size), page, size)
}

func removalOwnerRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner", "account-owner", "account_owner", "workspace-owner", "workspace_owner":
		return true
	default:
		return false
	}
}

// removalFailure 把底层错误记入服务端日志（带 request_id），对外只写固定 5xx problem。
func (h *OwnerAuthHandler) removalFailure(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("removal_data_unavailable", "request_id", RequestIDFromContext(r.Context()), "error", err)
	writeProblem(w, r, http.StatusInternalServerError, "removal_unavailable", "Internal Server Error", "Removal data is temporarily unavailable", 0)
}
