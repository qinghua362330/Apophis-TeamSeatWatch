package task

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

// TargetRoutes is the worker-facing account route boundary. Bind consumes the
// already acquired outer lease; implementations must not acquire a second
// capacity lease.
type TargetRoutes interface {
	Enabled(context.Context) (bool, error)
	Bind(context.Context, uuid.UUID, *egress.Lease) (*egress.Lease, error)
}

var errAccountRouteTargetMissing = errors.New("account route target missing")

func (w *Worker) bindAccountRoute(ctx context.Context, item Task, outer *egress.Lease) (context.Context, *egress.Lease, error) {
	if w.TargetRoutes == nil {
		return ctx, outer, nil
	}
	switch item.TaskType {
	case "target_account_probe", "oauth_generate", "oauth_probe", "oauth_reclaim":
		// Account-scoped work only. Workspace reads and all mother/removal
		// operations deliberately retain their existing route behavior.
	case "join":
		// The initial invitation is a mother/workspace operation. Only the
		// subsequent OAuth authorization leg may use the target account route.
		target, targetErr := w.Store.JoinTarget(ctx, item)
		if targetErr != nil {
			return ctx, outer, targetErr
		}
		if !joinUsesAccountRoute(target) {
			return ctx, outer, nil
		}
	default:
		return ctx, outer, nil
	}
	enabled, err := w.TargetRoutes.Enabled(ctx)
	if err != nil || !enabled {
		return ctx, outer, err
	}
	targetID, err := w.accountRouteTarget(ctx, item)
	if err != nil {
		return ctx, outer, err
	}
	bound, err := w.TargetRoutes.Bind(ctx, targetID, outer)
	if err != nil {
		return ctx, outer, err
	}
	if bound == nil {
		return ctx, outer, errors.New("account route bind returned nil lease")
	}
	if err := w.recordBoundRoute(ctx, item, bound); err != nil {
		return ctx, outer, err
	}
	return egress.WithBorrowedLease(ctx, targetID.String(), bound), bound, nil
}

func joinUsesAccountRoute(target JoinTarget) bool {
	return target.OAuthAuthorized && target.InvitationConfirmed
}

// recordBoundRoute appends the route-bound fact only while the claiming task
// still owns its running lease. Attempts remain append-only; the audit fact is
// the authoritative correction from the generic admission route to the pinned
// account route.
func (w *Worker) recordBoundRoute(ctx context.Context, item Task, lease *egress.Lease) error {
	tx, err := w.Store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var status string
	var token uuid.UUID
	var attempt int
	var expires time.Time
	if err = tx.QueryRow(ctx, `SELECT status,lease_token,attempt_count,lease_expires_at FROM tsw_tasks WHERE id=$1 FOR SHARE`, item.ID).Scan(&status, &token, &attempt, &expires); err != nil {
		return err
	}
	if status != "running" || token != item.LeaseToken || attempt != item.AttemptNo || !expires.After(time.Now()) {
		return ErrLeaseLost
	}
	fingerprint := lease.Fingerprint()
	scheme, keyVersion := lease.Scheme(), lease.KeyVersion()
	verified := lease.VerifiedAt()
	mode := string(lease.Mode())
	scope := item.WorkspaceID
	eventType := audit.TaskRouteBound
	if item.TaskType == "target_account_probe" {
		scope = item.TargetAccountID
		eventType = audit.TargetProbeRouteBound
	}
	if _, err = audit.Write(ctx, tx, audit.Event{
		Type: eventType, Actor: audit.ActorSystem, RetentionScopeID: scope,
		EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeSucceeded,
		CorrelationID: item.CorrelationID, SourceFingerprint: fingerprint[:],
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: "bound", Stage: "route_bound", RouteMode: mode, ProxyScheme: scheme, EgressKeyVersion: keyVersion, ProxyVerifiedAt: verified.UTC().Format(time.RFC3339Nano)},
		IdempotencyKey: item.ID + ":route_bound:" + strconv.Itoa(item.AttemptNo),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *Worker) accountRouteTarget(ctx context.Context, item Task) (uuid.UUID, error) {
	if id, err := uuid.Parse(item.TargetAccountID); err == nil {
		return id, nil
	}
	switch item.TaskType {
	case "join", "join_reconcile":
		target, err := w.Store.JoinTarget(ctx, item)
		if err == nil {
			if id, parseErr := uuid.Parse(target.TargetID); parseErr == nil {
				return id, nil
			}
		}
	case "oauth_generate", "oauth_probe", "oauth_reclaim":
		var targetID string
		err := w.Store.pool.QueryRow(ctx, `SELECT membership.target_account_id::text FROM tsw_tasks task JOIN tsw_batch_memberships membership ON membership.id=task.membership_id WHERE task.id=$1`, item.ID).Scan(&targetID)
		if err == nil {
			if id, parseErr := uuid.Parse(targetID); parseErr == nil {
				return id, nil
			}
		}
	case "target_account_probe":
		// A probe without a target id is malformed and must not reach the
		// platform; the parse failure below records the interruption.
	}
	return uuid.Nil, errAccountRouteTargetMissing
}

func (w *Worker) finishAccountRouteFailure(ctx context.Context, item Task) error {
	const code = "account_route_unavailable"
	switch item.TaskType {
	case "target_account_probe":
		return w.Store.RejectTargetProbe(ctx, item, code, "account_route_bind", func(context.Context, pgx.Tx, string) error { return nil })
	case "join", "join_reconcile":
		target, err := w.Store.JoinTarget(ctx, item)
		if err != nil {
			return err
		}
		if item.TaskType == "join_reconcile" {
			if err = w.Store.FinishJoinReconciliation(ctx, item, target, platform.MembershipResult{ErrorCode: code}); err != nil {
				return err
			}
			return ErrAttemptFailed
		}
		return w.finishJoin(ctx, item, target, "blocked", code, code, "account_route_bind", nil)
	default:
		return w.fail(ctx, item, "task.rejected", code, "account_route_bind")
	}
}
