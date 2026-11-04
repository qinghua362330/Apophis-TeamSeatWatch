package task

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/workspace"
)

var ErrAttemptFailed = errors.New("task attempt failed")

type ReaderFactory func(*http.Client, platform.Credentials) (platform.Reader, error)
type TargetProberFactory func(*http.Client, platform.Credentials) (*platform.HTTPReader, error)
type JoinerFactory func(context.Context, *http.Client, JoinTarget) (platform.Joiner, error)
type RemoverFactory func(*http.Client, platform.Credentials) (platform.Remover, error)

// OperationRemoverFactory builds a remover from the durable operation target.
// Unlike the legacy factory it does not expose owner passwords; implementations
// can revalidate the selected Workspace authority before each mutation.
type OperationRemoverFactory func(context.Context, *http.Client, RemovalTarget) (platform.Remover, error)
type DeliveryAdapterFactory func(*http.Client, platform.Credentials) (platform.DeliveryAdapter, error)
type DeliveryProbeFactory func(*http.Client) (platform.DeliveryAdapter, error)
type DeliveryRefreshFunc func(context.Context, *http.Client, string) (platform.DeliveryCredentialSet, error)

type Worker struct {
	Store   *Store
	Facts   *workspace.Service
	Targets *targetdomain.Service
	// Egress is the narrow lease boundary; the Owner can swap the pool at
	// runtime behind this interface without re-wiring the worker.
	Egress           egress.LeaseProvider
	Reader           ReaderFactory
	TargetProber     TargetProberFactory
	PersonalProber   PersonalProbeProvider
	Joiner           JoinerFactory
	Remover          RemoverFactory
	OperationRemover OperationRemoverFactory
	DeliveryAdapter  DeliveryAdapterFactory
	DeliveryProbe    DeliveryProbeFactory
	DeliveryRefresh  DeliveryRefreshFunc
	ID               string
	LeaseTime        time.Duration
	lastCleanup      time.Time
}

// RunOnce reuses the Ticket 04 durable queue, lease fence, egress lease and
// terminal audit boundary for both Workspace reads and target-account probes.
func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	if open, err := w.Store.RecoveryOpen(ctx); err != nil {
		return false, err
	} else if !open {
		return false, nil
	}
	if recovered, err := w.Store.RecoverExpiredJoin(ctx); err != nil || recovered {
		return recovered, err
	}
	if recovered, err := w.Store.RecoverExpiredRemoval(ctx); err != nil || recovered {
		return recovered, err
	}
	if settled, err := w.Store.SettleExhausted(ctx); err != nil || settled {
		return settled, err
	}
	if w.cleanupDue() {
		retention, retentionErr := w.Store.ClaimRetentionCleanup(ctx, w.ID, w.leaseDuration())
		if retentionErr == nil {
			completionErr := w.Store.CompleteRetentionCleanup(ctx, retention, func(ctx context.Context, tx pgx.Tx) error {
				return w.Facts.RunRetentionTx(ctx, tx, retention.DedupeKey, 100)
			})
			w.lastCleanup = time.Now()
			return true, completionErr
		}
		if !errors.Is(retentionErr, pgx.ErrNoRows) {
			return false, retentionErr
		}
		cleanup, err := w.Store.ClaimCleanup(ctx, w.ID, w.leaseDuration())
		w.lastCleanup = time.Now()
		if err == nil {
			err = w.Store.CompleteCleanup(ctx, cleanup, func(ctx context.Context, tx pgx.Tx, workspaceID string) error {
				return w.Facts.DeleteExpiredWorkspaceTx(ctx, tx, workspaceID)
			})
			if err != nil {
				_ = w.Store.RecordInterruption(ctx, cleanup, "cleanup_fenced", "retention_cleanup")
			}
			return true, err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
	}

	personalProcessed := false
	// Personal jobs never obtain an egress lease or preempt the existing network
	// queue. Bounded slices make large filtered scopes progress without starvation.
	for i := 0; i < 10; i++ {
		processed, personalErr := w.Store.ProcessPersonalProbes(ctx, w.PersonalProber)
		if personalErr != nil {
			return personalProcessed || processed, personalErr
		}
		if !processed {
			break
		}
		personalProcessed = true
	}
	taskType, err := w.Store.NextNetworkTaskType(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return personalProcessed, nil
	}
	if err != nil {
		return false, err
	}
	leaseContext := ctx
	if taskType == "join" || taskType == "oauth_generate" || taskType == "oauth_reclaim" {
		leaseContext = egress.WithStableWindow(ctx, 2*time.Minute)
	}
	lease, err := w.Egress.Acquire(leaseContext)
	if err != nil {
		return w.rejectForEgress(ctx, taskType, err)
	}
	defer lease.Release()

	route := AttemptRoute{Mode: string(lease.Mode())}
	if lease.Mode() == egress.ModeRequired {
		scheme, keyVersion, stage := lease.Scheme(), lease.KeyVersion(), "remeasured"
		verified := lease.VerifiedAt()
		fingerprint := lease.Fingerprint()
		route.Scheme = &scheme
		route.KeyVersion = &keyVersion
		route.Stage = &stage
		route.VerifiedAt = &verified
		route.Fingerprint = fingerprint[:]
	}
	var item Task
	if taskType == "target_account_probe" {
		item, err = w.Store.ClaimTargetProbe(ctx, w.ID, w.leaseDuration(), route)
	} else if taskType == "join" {
		item, err = w.Store.ClaimJoin(ctx, w.ID, w.leaseDuration(), route)
	} else if taskType == "join_reconcile" {
		item, err = w.Store.ClaimJoinReconcile(ctx, w.ID, w.leaseDuration(), route)
	} else if taskType == "remove" {
		item, err = w.Store.ClaimRemoval(ctx, w.ID, w.leaseDuration(), route)
	} else if taskType == "remove_reconcile" {
		item, err = w.Store.ClaimRemovalReconciliation(ctx, w.ID, w.leaseDuration(), route)
	} else if taskType == "oauth_generate" || taskType == "oauth_probe" || taskType == "oauth_reclaim" {
		item, err = w.Store.ClaimDelivery(ctx, w.ID, w.leaseDuration(), taskType, route)
	} else {
		item, err = w.Store.Claim(ctx, w.ID, w.leaseDuration(), route)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch item.TaskType {
	case "target_account_probe":
		return true, w.runTargetProbe(ctx, item, lease)
	case "join":
		return true, w.runJoin(ctx, item, lease)
	case "join_reconcile":
		return true, w.runJoinReconcile(ctx, item, lease)
	case "remove", "remove_reconcile":
		return true, w.runRemoval(ctx, item, lease)
	case "oauth_generate":
		return true, w.runDeliveryGeneration(ctx, item, lease)
	case "oauth_probe":
		return true, w.runDeliveryProbe(ctx, item, lease)
	case "oauth_reclaim":
		return true, w.runDeliveryReclaim(ctx, item, lease)
	default:
		return true, w.runWorkspaceRead(ctx, item, lease)
	}
}

func (w *Worker) rejectForEgress(ctx context.Context, taskType string, acquireErr error) (bool, error) {
	if !errors.Is(acquireErr, egress.ErrLeaseExhausted) && !errors.Is(acquireErr, egress.ErrEgressDrift) {
		return false, acquireErr
	}
	resultCode := "proxy_capacity_exhausted"
	if errors.Is(acquireErr, egress.ErrEgressDrift) {
		resultCode = "proxy_egress_drift"
	}
	var item Task
	var err error
	if taskType == "target_account_probe" {
		item, err = w.Store.ClaimRejectedTargetProbe(ctx, w.ID, w.leaseDuration())
	} else {
		item, err = w.Store.ClaimRejectedNetwork(ctx, w.ID, w.leaseDuration(), taskType)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if item.TaskType == "remove" || item.TaskType == "remove_reconcile" {
		target, targetErr := w.Store.RemovalTarget(ctx, item)
		if targetErr != nil {
			return true, targetErr
		}
		err = w.Store.FinishRemovalUnknown(ctx, item, target, resultCode, "egress_admission")
		if err != nil {
			return true, err
		}
		return true, ErrAttemptFailed
	}
	if item.TaskType == "join" || item.TaskType == "join_reconcile" {
		target, targetErr := w.Store.JoinTarget(ctx, item)
		if targetErr != nil {
			return true, targetErr
		}
		if item.TaskType == "join_reconcile" {
			err = w.Store.FinishJoinReconciliation(ctx, item, target, platform.MembershipResult{ErrorCode: resultCode})
		} else if target.PlatformRequestMayHaveReached {
			err = w.Store.FinishJoin(ctx, item, target, "unknown", "platform_unknown", resultCode, "reconcile_egress_admission", nil)
		} else {
			err = w.Store.FinishJoin(ctx, item, target, "blocked", resultCode, resultCode, "egress_admission", nil)
		}
		if err != nil {
			return true, err
		}
		return true, ErrAttemptFailed
	}
	if item.TaskType == "target_account_probe" {
		probe := platform.TargetProbeResult{
			Status: platform.TargetUnknown, Endpoint: "account_usage", Origin: "worker",
			ErrorCode: resultCode, ObservedAt: time.Now().UTC(),
		}
		err = w.Store.RejectTargetProbe(ctx, item, resultCode, "egress_admission", func(ctx context.Context, tx pgx.Tx, targetID string) error {
			return w.Targets.PublishProbeTx(ctx, tx, targetID, probe, item.CorrelationID, targetProbeAuditKey(item))
		})
		if err != nil {
			return true, err
		}
		return true, ErrAttemptFailed
	}
	return true, w.fail(ctx, item, "task.rejected", resultCode, "egress_admission")
}

func (w *Worker) runTargetProbe(ctx context.Context, item Task, lease *egress.Lease) error {
	target, err := w.Store.TargetProbeTarget(ctx, item.TargetAccountID)
	if err != nil {
		return w.rejectTargetProbe(ctx, item, "platform_credential_unavailable", "credential_resolution")
	}
	prober, err := w.TargetProber(lease.Client(), platform.Credentials{
		LoginIdentifier: target.LoginIdentifier,
		Password:        target.Password,
	})
	if err != nil {
		return w.rejectTargetProbe(ctx, item, "platform_configuration_invalid", "prepare")
	}
	result, probeErr := prober.ProbeTarget(ctx)
	var egressErr *egress.ConfigError
	if errors.As(probeErr, &egressErr) {
		result.Status = platform.TargetUnknown
		result.ErrorCode = egressErr.Code()
	}
	if result.Status == "" {
		result.Status = platform.TargetUnknown
	}
	if result.Endpoint == "" {
		result.Endpoint = "account_usage"
	}
	if result.Origin == "" {
		result.Origin = "worker"
	}
	if err := w.Store.CompleteTargetProbe(ctx, item, func(ctx context.Context, tx pgx.Tx, targetID string) error {
		return w.Targets.PublishProbeTx(ctx, tx, targetID, result, item.CorrelationID, targetProbeAuditKey(item))
	}); err != nil {
		_ = w.Store.RecordInterruption(ctx, item, "publication_fenced", "publish")
		return err
	}
	return nil
}

func (w *Worker) rejectTargetProbe(ctx context.Context, item Task, resultCode, stage string) error {
	probe := platform.TargetProbeResult{
		Status: platform.TargetUnknown, Endpoint: "account_usage", Origin: "worker",
		ErrorCode: resultCode, ObservedAt: time.Now().UTC(),
	}
	if err := w.Store.RejectTargetProbe(ctx, item, resultCode, stage, func(ctx context.Context, tx pgx.Tx, targetID string) error {
		return w.Targets.PublishProbeTx(ctx, tx, targetID, probe, item.CorrelationID, targetProbeAuditKey(item))
	}); err != nil {
		return err
	}
	return ErrAttemptFailed
}

func (w *Worker) runWorkspaceRead(ctx context.Context, item Task, lease *egress.Lease) error {
	if w.Reader == nil {
		return w.fail(ctx, item, "task.rejected", "management_protocol_unavailable", "prepare")
	}
	target, err := w.Store.WorkspaceReadTarget(ctx, item.WorkspaceID)
	if err != nil {
		return w.fail(ctx, item, "task.rejected", "platform_credential_unavailable", "credential_resolution")
	}
	reader, err := w.Reader(lease.Client(), platform.Credentials{
		LoginIdentifier: target.LoginIdentifier,
		Password:        target.Password,
	})
	if err != nil {
		return w.fail(ctx, item, "task.rejected", "platform_configuration_invalid", "prepare")
	}
	reads := []func(context.Context, string) (platform.Result, error){
		reader.ReadExchange, reader.ReadSubscription, reader.ReadCapacity,
		reader.ReadJoin, reader.ReadMembers, reader.ReadPendingInvites,
	}
	results := make([]platform.Result, 0, len(reads))
	for index, read := range reads {
		if index > 0 {
			if err := lease.Remeasure(ctx); err != nil {
				return w.fail(ctx, item, "task.interrupted", "proxy_egress_drift", "remeasure")
			}
		}
		result, readErr := read(ctx, target.PlatformWorkspaceID)
		if readErr != nil {
			result.ObservedAt = time.Now().UTC()
			result.Outcome = platform.Classify(0, "", readErr)
		}
		results = append(results, result)
		if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
			_ = w.Store.RecordInterruption(ctx, item, "lease_lost", "renew")
			return err
		}
	}
	if err := w.Store.CompleteWorkspaceRead(ctx, item, func(ctx context.Context, tx pgx.Tx, workspaceID string) error {
		return w.Facts.PublishReadTx(ctx, tx, workspaceID, results)
	}); err != nil {
		_ = w.Store.RecordInterruption(ctx, item, "publication_fenced", "publish")
		return err
	}
	return nil
}

func targetProbeAuditKey(item Task) string {
	return item.ID + ":target-account.probed:" + strconv.Itoa(item.AttemptNo)
}

func (w *Worker) fail(ctx context.Context, item Task, eventType, result, stage string) error {
	if err := w.Store.Settle(ctx, item, "failed", eventType, "failed", result, stage); err != nil {
		return err
	}
	return ErrAttemptFailed
}

func (w *Worker) cleanupDue() bool {
	return w.lastCleanup.IsZero() || time.Since(w.lastCleanup) >= 5*time.Second
}

func (w *Worker) leaseDuration() time.Duration {
	if w.LeaseTime <= 0 {
		return 30 * time.Second
	}
	return w.LeaseTime
}
