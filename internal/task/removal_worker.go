package task

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

func (w *Worker) runRemoval(ctx context.Context, item Task, lease *egress.Lease) error {
	target, err := w.Store.RemovalTarget(ctx, item)
	if err != nil {
		return err
	}
	if (w.Remover == nil && w.OperationRemover == nil) || w.Facts == nil {
		return w.finishRemovalBlocked(ctx, item, target, nil, "platform_configuration_invalid", "prepare")
	}
	var remover platform.Remover
	if w.OperationRemover != nil {
		remover, err = w.OperationRemover(ctx, lease.Client(), target)
	} else {
		// Legacy callers (including isolated task tests) may still provide the
		// password-based factory. Production wires OperationRemover instead.
		remover, err = w.Remover(lease.Client(), platform.Credentials{LoginIdentifier: target.OwnerIdentifier, Password: target.OwnerPassword})
	}
	if err != nil {
		return w.finishRemovalBlocked(ctx, item, target, nil, "platform_configuration_invalid", "prepare")
	}
	before, err := remover.SnapshotMembers(ctx, target.PlatformWorkspace)
	if err != nil {
		if target.PlatformRequestMayHaveReached || item.TaskType == "remove_reconcile" {
			return w.finishRemovalUnknown(ctx, item, target, "membership_snapshot_incomplete", "before_delete_snapshot")
		}
		return w.finishRemovalRetry(ctx, item, target, nil, "membership_snapshot_incomplete", "before_delete_snapshot")
	}
	liveMemberID, present, diagnostic := resolveRemovalTarget(target, before)
	publisher := w.removalSnapshotPublisher(before)
	if diagnostic != "" {
		return w.finishRemovalBlocked(ctx, item, target, publisher, diagnostic, "before_delete_snapshot")
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishRemovalUnknown(ctx, item, target, "proxy_egress_drift", "before_delete_remeasure")
	}
	if !present {
		return w.Store.FinishRemovalConfirmed(ctx, item, target, publisher, "before_delete_snapshot")
	}
	// An earlier DELETE may have reached the platform. This attempt is strictly
	// read-only and only schedules a later mutation after exact presence is known.
	if target.PlatformRequestMayHaveReached || item.TaskType == "remove_reconcile" {
		if err := w.Store.FinishRemovalReconciliation(ctx, item, target, publisher, true); err != nil {
			return err
		}
		return ErrAttemptFailed
	}
	if target.RemoveAttemptCount >= maximumRemovalSideEffects {
		return w.finishRemovalBlocked(ctx, item, target, publisher, "remove_attempts_exhausted", "before_delete_snapshot")
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	if err := w.Store.MarkRemovalSideEffectStarted(ctx, item, liveMemberID); err != nil {
		return err
	}
	result, removeErr := remover.RemoveMember(ctx, target.PlatformWorkspace, liveMemberID)
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishRemovalUnknown(ctx, item, target, "proxy_egress_drift", "after_delete_remeasure")
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	after, snapshotErr := remover.SnapshotMembers(ctx, target.PlatformWorkspace)
	if snapshotErr != nil {
		diagnostic := "membership_snapshot_incomplete"
		if removeErr != nil {
			diagnostic = "remove_transport_unknown"
		}
		return w.finishRemovalUnknown(ctx, item, target, diagnostic, "after_delete_snapshot")
	}
	_, stillPresent, diagnostic := resolveRemovalTarget(target, after)
	afterPublisher := w.removalSnapshotPublisher(after)
	if diagnostic != "" {
		return w.finishRemovalUnknown(ctx, item, target, diagnostic, "after_delete_snapshot")
	}
	if !stillPresent {
		return w.Store.FinishRemovalConfirmed(ctx, item, target, afterPublisher, "after_delete_snapshot")
	}
	if removeErr != nil || result.Retryable || result.RequestMayHaveEffect {
		return w.finishRemovalRetry(ctx, item, target, afterPublisher, removalDiagnostic(result, removeErr), "after_delete_snapshot")
	}
	return w.finishRemovalBlocked(ctx, item, target, afterPublisher, removalDiagnostic(result, removeErr), "after_delete_snapshot")
}

func (w *Worker) removalSnapshotPublisher(snapshot platform.ExactMemberSnapshot) removalSnapshotPublisher {
	return func(ctx context.Context, tx pgx.Tx, workspaceID string) error {
		return w.Facts.PublishReadTx(ctx, tx, workspaceID, []platform.Result{snapshot.Fact})
	}
}

func resolveRemovalTarget(target RemovalTarget, snapshot platform.ExactMemberSnapshot) (string, bool, string) {
	membersByIdentifier := make(map[string][]platform.Member, len(snapshot.Fact.Members))
	expectedOwner := strings.ToLower(strings.TrimSpace(target.OwnerIdentifier))
	ownerPresent := false
	for _, member := range snapshot.Fact.Members {
		if member.Kind != "member" {
			continue
		}
		identity := strings.ToLower(strings.TrimSpace(member.Identifier))
		membersByIdentifier[identity] = append(membersByIdentifier[identity], member)
		if identity == expectedOwner && removalOwnerRole(member.Role) {
			ownerPresent = true
		}
	}
	if !ownerPresent {
		return "", false, "owner_missing"
	}
	for _, entry := range target.Manifest {
		matches := membersByIdentifier[strings.ToLower(strings.TrimSpace(entry.Identifier))]
		if len(matches) > 1 {
			return "", false, "target_identity_ambiguous"
		}
		if len(matches) == 1 && removalOwnerRole(matches[0].Role) {
			return "", false, "target_is_owner"
		}
	}
	matches := membersByIdentifier[strings.ToLower(strings.TrimSpace(target.TargetIdentifier))]
	if len(matches) == 0 {
		return "", false, ""
	}
	return matches[0].PlatformMemberID, true, ""
}

func removalOwnerRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner", "account-owner", "account_owner", "workspace-owner", "workspace_owner":
		return true
	default:
		return false
	}
}

func removalDiagnostic(result platform.RemoveMemberResult, err error) string {
	if err != nil {
		return "remove_transport_unknown"
	}
	if result.ErrorCode != "" {
		return platform.NormalizeDiagnostic(result.ErrorCode)
	}
	if result.Accepted {
		return "remove_retry_scheduled"
	}
	return "remove_rejected"
}

func (w *Worker) finishRemovalRetry(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, diagnostic, stage string) error {
	if err := w.Store.FinishRemovalRetry(ctx, item, target, publisher, diagnostic, stage); err != nil {
		return err
	}
	return ErrAttemptFailed
}

func (w *Worker) finishRemovalUnknown(ctx context.Context, item Task, target RemovalTarget, diagnostic, stage string) error {
	if err := w.Store.FinishRemovalUnknown(ctx, item, target, diagnostic, stage); err != nil {
		return err
	}
	return ErrAttemptFailed
}

func (w *Worker) finishRemovalBlocked(ctx context.Context, item Task, target RemovalTarget, publisher removalSnapshotPublisher, diagnostic, stage string) error {
	if err := w.Store.FinishRemovalBlocked(ctx, item, target, publisher, diagnostic, stage); err != nil {
		return err
	}
	return ErrAttemptFailed
}
