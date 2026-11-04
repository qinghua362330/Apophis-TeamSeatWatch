package task

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/mothersecret"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

const maximumRemovalSideEffects = 3

type RemovalManifestEntry struct {
	MembershipID string
	Identifier   string
	Ordinal      int
}

type RemovalTarget struct {
	OperationID                   string
	BatchID                       string
	WorkspaceID                   string
	MembershipID                  string
	TargetAccountID               string
	TargetIdentifier              string
	PlatformWorkspace             string
	OwnerIdentifier               string
	OwnerPassword                 string
	Ordinal                       int
	PlatformRequestMayHaveReached bool
	RemoveAttemptCount            int
	Manifest                      []RemovalManifestEntry
}

type removalSnapshotPublisher func(context.Context, pgx.Tx, string) error

func (s *Store) ClaimRemoval(ctx context.Context, worker string, duration time.Duration, route AttemptRoute) (Task, error) {
	return s.claim(ctx, worker, duration, "remove", route)
}

func (s *Store) ClaimRemovalReconciliation(ctx context.Context, worker string, duration time.Duration, route AttemptRoute) (Task, error) {
	return s.claim(ctx, worker, duration, "remove_reconcile", route)
}

func (s *Store) RemovalTarget(ctx context.Context, item Task) (RemovalTarget, error) {
	var target RemovalTarget
	var ownerPassword []byte
	var motherID uuid.UUID
	var revision int64
	err := s.pool.QueryRow(ctx, `SELECT operation.id,operation.batch_id,operation.workspace_id,task.membership_id,
		membership.target_account_id,target.identifier,workspace.platform_workspace_id,
		credentials.login_identifier,credentials.password_secret,credentials.mother_account_id,credentials.secret_revision,operation_target.ordinal,
		operation_target.platform_request_may_have_reached,operation_target.remove_attempt_count
		FROM tsw_tasks task
		JOIN tsw_operation_targets operation_target ON operation_target.id=task.operation_target_id
		JOIN tsw_operations operation ON operation.id=operation_target.operation_id AND operation.operation_type='remove'
		JOIN tsw_batch_memberships membership ON membership.id=task.membership_id AND membership.id=operation_target.membership_id
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id
		JOIN tsw_batches batch ON batch.id=operation.batch_id AND batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.workspace_id=operation.workspace_id AND binding.ended_at IS NULL
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_mother_accounts mother ON mother.id=binding.mother_account_id AND mother.status='active'
		JOIN tsw_mother_account_credentials credentials ON credentials.mother_account_id=mother.id
		WHERE task.id=$1 AND task.task_type IN ('remove','remove_reconcile')`, item.ID).Scan(
		&target.OperationID, &target.BatchID, &target.WorkspaceID, &target.MembershipID,
		&target.TargetAccountID, &target.TargetIdentifier, &target.PlatformWorkspace,
		&target.OwnerIdentifier, &ownerPassword, &motherID, &revision, &target.Ordinal,
		&target.PlatformRequestMayHaveReached, &target.RemoveAttemptCount)
	if err != nil {
		return RemovalTarget{}, err
	}
	plaintext, err := mothersecret.Open(s.keyRing, motherID, revision, mothersecret.Password, ownerPassword)
	clear(ownerPassword)
	if err != nil {
		return RemovalTarget{}, err
	}
	target.OwnerPassword = string(plaintext)
	clear(plaintext)
	rows, err := s.pool.Query(ctx, `SELECT operation_target.membership_id,membership_target.identifier,operation_target.ordinal
		FROM tsw_operation_targets operation_target
		JOIN tsw_batch_memberships membership ON membership.id=operation_target.membership_id
		JOIN tsw_target_accounts membership_target ON membership_target.id=membership.target_account_id
		WHERE operation_target.operation_id=$1 ORDER BY operation_target.ordinal`, target.OperationID)
	if err != nil {
		return RemovalTarget{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry RemovalManifestEntry
		if err := rows.Scan(&entry.MembershipID, &entry.Identifier, &entry.Ordinal); err != nil {
			return RemovalTarget{}, err
		}
		target.Manifest = append(target.Manifest, entry)
	}
	if err := rows.Err(); err != nil {
		return RemovalTarget{}, err
	}
	if len(target.Manifest) == 0 {
		return RemovalTarget{}, errors.New("removal manifest is empty")
	}
	return target, nil
}

// RecoverExpiredRemoval makes a possibly delivered DELETE facts-first. The
// same durable task is retried, but its next attempt can only reconcile while
// platform_request_may_have_reached remains true.
func (s *Store) RecoverExpiredRemoval(ctx context.Context) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var item Task
	var operationID, batchID string
	var mayHaveReached bool
	var maxAttempts int
	err = tx.QueryRow(ctx, `SELECT task.id,task.workspace_id,task.membership_id,task.operation_target_id,task.correlation_id,
		task.attempt_count,task.max_attempts,operation_target.operation_id,operation.batch_id,
		operation_target.platform_request_may_have_reached
		FROM tsw_tasks task
		JOIN tsw_operation_targets operation_target ON operation_target.id=task.operation_target_id
		JOIN tsw_operations operation ON operation.id=operation_target.operation_id
		WHERE task.task_type='remove' AND task.status='running' AND task.lease_expires_at<=now()
		ORDER BY task.lease_expires_at,task.created_at FOR UPDATE OF task,operation_target SKIP LOCKED LIMIT 1`).Scan(
		&item.ID, &item.WorkspaceID, &item.MembershipID, &item.OperationTargetID, &item.CorrelationID,
		&item.AttemptNo, &maxAttempts, &operationID, &batchID, &mayHaveReached)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	taskStatus, targetStatus, diagnostic := "retry_wait", "queued", "lease_lost"
	var finishedAt any
	if mayHaveReached {
		targetStatus = "unknown"
	}
	if item.AttemptNo >= maxAttempts {
		taskStatus, targetStatus, diagnostic, finishedAt = "interrupted", "blocked", "remove_attempts_exhausted", time.Now().UTC()
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_tasks SET status=$2,available_at=now(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=$3,updated_at=now(),version=version+1 WHERE id=$1`, item.ID, taskStatus, finishedAt); err != nil {
		return false, err
	}
	completed := targetStatus == "unknown" || targetStatus == "blocked"
	if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status=$2,outcome_code=CASE WHEN $3 THEN 'platform_unknown' ELSE 'remove_retry_scheduled' END,diagnostic_code=$4,completed_at=CASE WHEN $3 THEN now() ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, targetStatus, completed, diagnostic); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_operations SET workspace_mutation_lease_owner=NULL,workspace_mutation_lease_token=NULL,workspace_mutation_lease_expires_at=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND workspace_mutation_lease_owner=$2`, operationID, item.ID); err != nil {
		return false, err
	}
	if _, err = settleRemovalAggregate(ctx, tx, operationID, batchID); err != nil {
		return false, err
	}
	eventType := audit.RemoveTargetBlocked
	status := "blocked"
	if mayHaveReached && taskStatus == "retry_wait" {
		eventType, status = audit.RemoveTargetUnknown, "unknown"
	}
	if !mayHaveReached && taskStatus == "retry_wait" {
		eventType, status = audit.RemoveTargetBlocked, "queued"
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: eventType, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: audit.OutcomeFailed, CorrelationID: item.CorrelationID, Details: audit.RemovalTargetDetails{Status: status, Result: diagnostic, Stage: "crash_recovery", AttemptNo: item.AttemptNo}, IdempotencyKey: item.ID + ":remove.recovered:" + strconv.Itoa(item.AttemptNo)}); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *Store) MarkRemovalSideEffectStarted(ctx context.Context, item Task, liveMemberID string) error {
	if liveMemberID == "" {
		return errors.New("live member id is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockRemovalTask(ctx, tx, item); err != nil {
		return err
	}
	var operationID string
	var ordinal, removeAttempts int
	err = tx.QueryRow(ctx, `SELECT operation_target.operation_id,operation_target.ordinal,operation_target.remove_attempt_count
		FROM tsw_operation_targets operation_target WHERE operation_target.id=$1
		AND (operation_target.ordinal=1 OR EXISTS (
			SELECT 1 FROM tsw_operation_targets canary
			WHERE canary.operation_id=operation_target.operation_id AND canary.ordinal=1 AND canary.status='succeeded'
		)) FOR UPDATE`, item.OperationTargetID).Scan(&operationID, &ordinal, &removeAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	_ = ordinal
	if removeAttempts >= maximumRemovalSideEffects {
		return errors.New("remove side-effect attempts exhausted")
	}
	lease, err := tx.Exec(ctx, `UPDATE tsw_operations SET workspace_mutation_lease_owner=$2,workspace_mutation_lease_token=$3,workspace_mutation_lease_expires_at=now()+interval '10 minutes',status='running',completed_at=NULL,updated_at=now(),version=version+1
		WHERE id=$1 AND (workspace_mutation_lease_token IS NULL OR workspace_mutation_lease_expires_at<=now() OR workspace_mutation_lease_token=$3)`, operationID, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if lease.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	updated, err := tx.Exec(ctx, `UPDATE tsw_operation_targets SET platform_request_may_have_reached=true,platform_request_stage='remove_member',platform_request_started_at=now(),removal_live_member_id=$2,remove_attempt_count=remove_attempt_count+1,status='running',outcome_code=NULL,diagnostic_code=NULL,last_attempt_at=now(),completed_at=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND remove_attempt_count<$3`, item.OperationTargetID, liveMemberID, maximumRemovalSideEffects)
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: audit.RemoveTargetAttempted, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.RemovalTargetDetails{Status: "running", Result: "delete_started", Stage: "remove_member", AttemptNo: removeAttempts + 1}, IdempotencyKey: item.ID + ":remove.started:" + strconv.Itoa(removeAttempts+1)})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishRemovalConfirmed(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, stage string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockRemovalTask(ctx, tx, item); err != nil {
		return err
	}
	if publisher != nil {
		if err := publisher(ctx, tx, target.WorkspaceID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_batch_memberships SET state='removed',removed_at=COALESCE(removed_at,now()),service_ended_at=COALESCE(service_ended_at,now()),retention_due_at=COALESCE(retention_due_at,now()+interval '7 days'),updated_at=now(),version=version+1 WHERE id=$1`, target.MembershipID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='succeeded',outcome_code='remove_confirmed',diagnostic_code=NULL,platform_request_may_have_reached=false,platform_request_stage=NULL,platform_request_started_at=NULL,completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID); err != nil {
		return err
	}
	ended, err := settleRemovalAggregate(ctx, tx, target.OperationID, target.BatchID)
	if err != nil {
		return err
	}
	if err = releaseRemovalOperationLease(ctx, tx, target.OperationID, item); err != nil {
		return err
	}
	if err = settleRemovalTask(ctx, tx, item, "succeeded", false); err != nil {
		return err
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.RemoveTargetConfirmed, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.RemovalTargetDetails{Status: "succeeded", Result: "remove_confirmed", Stage: stage, AttemptNo: item.AttemptNo}, IdempotencyKey: item.ID + ":remove.confirmed"}); err != nil {
		return err
	}
	if ended {
		if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.BatchServiceEnded, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "batch", EntityID: target.BatchID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.BatchDetails{Result: "service_ended"}, IdempotencyKey: target.BatchID + ":service-ended"}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishRemovalRetry(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, diagnostic, stage string) error {
	return s.finishRemovalUnconfirmed(ctx, item, target, publisher, "queued", "remove_retry_scheduled", diagnostic, stage, true, true)
}

func (s *Store) FinishRemovalUnknown(ctx context.Context, item Task, target RemovalTarget, diagnostic, stage string) error {
	return s.finishRemovalUnconfirmed(ctx, item, target, nil, "unknown", "platform_unknown", diagnostic, stage, true, false)
}

func (s *Store) FinishRemovalBlocked(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, diagnostic, stage string) error {
	return s.finishRemovalUnconfirmed(ctx, item, target, publisher, "blocked", "remove_blocked", diagnostic, stage, false, false)
}

func (s *Store) FinishRemovalReconciliation(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, present bool) error {
	if !present {
		return s.FinishRemovalConfirmed(ctx, item, target, publisher, "reconciliation")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockRemovalTask(ctx, tx, item); err != nil {
		return err
	}
	if publisher != nil {
		if err := publisher(ctx, tx, target.WorkspaceID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='queued',outcome_code='remove_retry_scheduled',diagnostic_code='reconciled_present',platform_request_may_have_reached=false,platform_request_stage=NULL,platform_request_started_at=NULL,completed_at=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID); err != nil {
		return err
	}
	if item.TaskType == "remove_reconcile" {
		if target.RemoveAttemptCount < maximumRemovalSideEffects {
			_, err = tx.Exec(ctx, `INSERT INTO tsw_tasks(operation_target_id,membership_id,workspace_id,parent_task_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts) VALUES ($1,$2,$3,$4,'remove',$5,jsonb_build_object('operation_target_id',$1::text,'membership_id',$2::text,'workspace_id',$3::text),$6,6) ON CONFLICT (task_type,dedupe_key) DO NOTHING`, item.OperationTargetID, target.MembershipID, target.WorkspaceID, item.ID, "remove-resume:"+item.OperationTargetID+":"+item.ID, item.CorrelationID)
		}
		if err == nil {
			err = settleRemovalTask(ctx, tx, item, "succeeded", false)
		}
	} else {
		err = settleRemovalTask(ctx, tx, item, "retry_wait", true)
	}
	if err != nil {
		return err
	}
	if _, err = settleRemovalAggregate(ctx, tx, target.OperationID, target.BatchID); err != nil {
		return err
	}
	if err = releaseRemovalOperationLease(ctx, tx, target.OperationID, item); err != nil {
		return err
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: audit.RemoveReconciliationDone, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeFailed, CorrelationID: item.CorrelationID, Details: audit.RemovalTargetDetails{Status: "queued", Result: "reconciled_present", Stage: "reconciliation", AttemptNo: item.AttemptNo}, IdempotencyKey: item.ID + ":remove.reconciled:" + strconv.Itoa(item.AttemptNo)})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) finishRemovalUnconfirmed(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, targetStatus, outcomeCode, diagnostic, stage string, retry, clearUncertainty bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockRemovalTask(ctx, tx, item); err != nil {
		return err
	}
	if publisher != nil {
		if err := publisher(ctx, tx, target.WorkspaceID); err != nil {
			return err
		}
	}
	taskStatus := "failed"
	if retry {
		taskStatus = "retry_wait"
	}
	completed := targetStatus == "blocked" || targetStatus == "unknown"
	if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status=$2,outcome_code=$3,diagnostic_code=$4,
		platform_request_may_have_reached=CASE WHEN $5 THEN false ELSE platform_request_may_have_reached END,
		platform_request_stage=CASE WHEN $5 THEN NULL ELSE platform_request_stage END,
		platform_request_started_at=CASE WHEN $5 THEN NULL ELSE platform_request_started_at END,
		completed_at=CASE WHEN $6 THEN now() ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, targetStatus, outcomeCode, platform.NormalizeDiagnostic(diagnostic), clearUncertainty, completed); err != nil {
		return err
	}
	if err = settleRemovalTask(ctx, tx, item, taskStatus, retry); err != nil {
		return err
	}
	if err = releaseRemovalOperationLease(ctx, tx, target.OperationID, item); err != nil {
		return err
	}
	if _, err = settleRemovalAggregate(ctx, tx, target.OperationID, target.BatchID); err != nil {
		return err
	}
	eventType := audit.RemoveTargetBlocked
	if targetStatus == "unknown" {
		eventType = audit.RemoveTargetUnknown
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: eventType, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: audit.OutcomeFailed, CorrelationID: item.CorrelationID, Details: audit.RemovalTargetDetails{Status: targetStatus, Result: outcomeCode, Stage: stage, AttemptNo: item.AttemptNo}, IdempotencyKey: item.ID + ":remove.unconfirmed:" + strconv.Itoa(item.AttemptNo)})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func settleRemovalTask(ctx context.Context, tx pgx.Tx, item Task, status string, retry bool) error {
	result, err := tx.Exec(ctx, `UPDATE tsw_tasks SET status=$3,available_at=CASE WHEN $4 THEN now()+interval '5 seconds' ELSE available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=CASE WHEN $4 THEN NULL ELSE now() END,updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken, status, retry)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

func releaseRemovalOperationLease(ctx context.Context, tx pgx.Tx, operationID string, item Task) error {
	_, err := tx.Exec(ctx, `UPDATE tsw_operations SET workspace_mutation_lease_owner=NULL,workspace_mutation_lease_token=NULL,workspace_mutation_lease_expires_at=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND (workspace_mutation_lease_token IS NULL OR workspace_mutation_lease_token=$2)`, operationID, item.LeaseToken)
	return err
}

func settleRemovalAggregate(ctx context.Context, tx pgx.Tx, operationID, batchID string) (bool, error) {
	var operationStatus string
	err := tx.QueryRow(ctx, `UPDATE tsw_operations SET status=CASE
		WHEN NOT EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status<>'succeeded') THEN 'succeeded'
		WHEN EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status IN ('blocked','unknown','failed')) THEN 'blocked'
		ELSE 'running' END,
		completed_at=CASE
		WHEN NOT EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status<>'succeeded') THEN now()
		WHEN EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status IN ('blocked','unknown','failed')) THEN now()
		ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1 RETURNING status`, operationID).Scan(&operationStatus)
	if err != nil {
		return false, err
	}
	var ended bool
	err = tx.QueryRow(ctx, `UPDATE tsw_batches SET status=CASE WHEN $2='succeeded' AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships WHERE batch_id=$1 AND state<>'removed') THEN 'ended' WHEN $2='succeeded' THEN 'serving' ELSE 'removing' END,
		service_ended_at=CASE WHEN $2='succeeded' AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships WHERE batch_id=$1 AND state<>'removed') THEN COALESCE(service_ended_at,now()) ELSE service_ended_at END,
		blocking_reason=CASE WHEN $2='blocked' THEN 'remove_target_unresolved' ELSE NULL END,updated_at=now(),version=version+1
		WHERE id=$1 RETURNING status='ended'`, batchID, operationStatus).Scan(&ended)
	if err != nil || !ended {
		return ended, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts attempt SET state='superseded',outcome_code='service_ended',finished_at=now()
		FROM tsw_tasks task,tsw_batch_memberships membership
		WHERE attempt.task_id=task.id AND task.membership_id=membership.id AND membership.batch_id=$1 AND attempt.state='running'`, batchID); err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_tasks task SET status='interrupted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=task.version+1
		FROM tsw_batch_memberships membership
		WHERE task.membership_id=membership.id AND membership.batch_id=$1
		AND task.task_type IN ('oauth_generate','oauth_probe','oauth_reclaim') AND task.status IN ('queued','running','retry_wait')`, batchID)
	return true, err
}

func (s *Store) EnqueueRemovalReconciliation(ctx context.Context, batchID, idempotencyKey, correlationID string) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var operationID string
	if err = tx.QueryRow(ctx, `SELECT id FROM tsw_operations WHERE batch_id=$1 AND operation_type='remove' AND status='blocked' ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, batchID).Scan(&operationID); err != nil {
		return 0, err
	}
	result, err := tx.Exec(ctx, `INSERT INTO tsw_tasks(operation_target_id,membership_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		SELECT target_result.id,target_result.membership_id,operation.workspace_id,'remove_reconcile',
			'remove-reconcile:'||target_result.id::text||':'||$2,
			jsonb_build_object('operation_target_id',target_result.id::text,'membership_id',target_result.membership_id::text,'workspace_id',operation.workspace_id::text),$3,3
		FROM tsw_operation_targets target_result
		JOIN tsw_operations operation ON operation.id=target_result.operation_id
		WHERE target_result.operation_id=$1 AND target_result.status IN ('blocked','unknown')
		ON CONFLICT (task_type,dedupe_key) DO NOTHING`, operationID, idempotencyKey, correlationID)
	if err != nil {
		return 0, err
	}
	if result.RowsAffected() == 0 {
		return 0, pgx.ErrNoRows
	}
	return result.RowsAffected(), tx.Commit(ctx)
}

func lockRemovalTask(ctx context.Context, tx pgx.Tx, item Task) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM tsw_tasks WHERE id=$1 AND task_type IN ('remove','remove_reconcile') AND status='running' AND lease_token=$2 AND lease_expires_at>now() FOR UPDATE`, item.ID, item.LeaseToken).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	return err
}
