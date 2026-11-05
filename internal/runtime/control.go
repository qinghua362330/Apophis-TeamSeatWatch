package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/internalapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/task"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/workspace"
)

// ControlConfig contains immutable startup dependencies for the control role.
type ControlConfig struct {
	Context             context.Context
	DatabaseURL         string
	DatabasePingTimeout time.Duration
	StaticDir           string
	PlatformClients     egress.PlatformClients
	Egress              *egress.Manager
	PlatformBaseURL     string
	TOTPKeyRingFile     string
	OwnerOrigins        auth.OriginPolicy
	CPAWebhookSecret    string
	// CPAManagementURL and CPAManagementKey attach the CPA management API. Both
	// empty keeps every remote CPA stage disabled; the webhook path still records
	// events so an operator can review them.
	CPAManagementURL string
	CPAManagementKey string
}

// ControlHandlers separates the public Owner surface from private health and metrics.
type ControlHandlers struct {
	Public          http.Handler
	Private         http.Handler
	PlatformClients egress.PlatformClients
	Close           func()
}

// NewControlHandlers loads security material before exposing the Owner API.
func NewControlHandlers(config ControlConfig) (ControlHandlers, error) {
	if config.Context == nil || config.PlatformClients == nil || config.Egress == nil {
		return ControlHandlers{}, errors.New("platform client boundary is required")
	}
	platformConfig, err := platform.NewHTTPConfig(config.PlatformBaseURL)
	if err != nil {
		return ControlHandlers{}, err
	}
	metrics := NewMetrics(config.Egress.Status())
	health, closeHealth, err := NewControlHealthHandler(HealthConfig{
		DatabaseURL:         config.DatabaseURL,
		DatabasePingTimeout: config.DatabasePingTimeout,
		Metrics:             metrics,
	})
	if err != nil {
		return ControlHandlers{}, err
	}
	staticHandler, err := newStaticHandler(config.StaticDir, ownerRoute)
	if err != nil {
		closeHealth()
		return ControlHandlers{}, err
	}
	// Keyring loading is fail-closed so deployment-held secret material is never accepted without its key.
	keyRing, err := auth.LoadKeyRingFile(config.TOTPKeyRingFile)
	if err != nil {
		closeHealth()
		return ControlHandlers{}, fmt.Errorf("invalid TOTP key ring: %w", err)
	}
	// Each explicit Owner action acquires its own admitted route; startup performs no login or discovery.
	leaseClient := func(ctx context.Context) (*http.Client, func(), error) {
		if target := egress.Target(ctx); target != "" {
			if borrowed, ok := egress.BorrowedLease(ctx, target); ok {
				return borrowed.Client(), func() {}, nil
			}
		}
		lease, err := config.Egress.Acquire(ctx)
		if err != nil {
			return nil, nil, err
		}
		return lease.Client(), lease.Release, nil
	}
	ownerAuth, closeOwnerAuth, err := NewOwnerAuthHandler(OwnerAuthConfig{
		Context:                 config.Context,
		DatabaseURL:             config.DatabaseURL,
		KeyRing:                 keyRing,
		Origins:                 config.OwnerOrigins,
		Egress:                  config.Egress,
		Discovery:               platform.AccountsCheckDiscovery{Client: leaseClient},
		PersonalRefresh:         platform.PersonalWebRefresher{Client: leaseClient, Browser: platform.NewPersonalBrowser},
		SelectedWorkspaceReader: platform.OfficialSelectedWorkspaceReader{Client: leaseClient},
		WorkspaceTokenExchanger: leasedWorkspaceTokenExchanger{egress: config.Egress},
		WorkspaceMemberRemover:  platform.OfficialWorkspaceMemberRemover{Client: leaseClient},
		CPAWebhookSecret:        config.CPAWebhookSecret,
		CPAManagementURL:        config.CPAManagementURL,
		CPAManagementKey:        config.CPAManagementKey,
	})
	if err != nil {
		closeHealth()
		return ControlHandlers{}, err
	}
	workerPool, err := pgxpool.New(config.Context, config.DatabaseURL)
	if err != nil {
		closeOwnerAuth()
		closeHealth()
		return ControlHandlers{}, err
	}
	workspaceWorker := &task.Worker{
		Store: task.NewStore(workerPool, keyRing), Facts: workspace.NewService(workerPool, keyRing), Targets: targetdomain.NewService(),
		TargetRoutes: ownerAuth.TargetRoutes, AccountRoutes: ownerAuth.TargetRoutes, Egress: config.Egress, ID: "workspace-reader-1", PersonalProber: SavedTargetPersonalProbe{Pool: workerPool, KeyRing: keyRing, Routes: ownerAuth.TargetRoutes, Adapter: platform.PersonalUsageProbe{Client: leaseClient}},
		TargetProber: func(client *http.Client, credentials platform.Credentials) (*platform.HTTPReader, error) {
			return platformConfig.Reader(client, credentials)
		},
		Joiner:           ownerAuth.Joiner,
		OperationRemover: ownerAuth.OperationRemover,
		Remover: func(client *http.Client, credentials platform.Credentials) (platform.Remover, error) {
			return platformConfig.Reader(client, credentials)
		},
		DeliveryAdapter: func(client *http.Client, credentials platform.Credentials) (platform.DeliveryAdapter, error) {
			return platformConfig.Reader(client, credentials)
		},
		DeliveryProbe: func(client *http.Client) (platform.DeliveryAdapter, error) {
			return platformConfig.OAuthReader(client)
		},
	}
	workerContext, cancelWorker := context.WithCancel(config.Context)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		runWorkspaceWorker(workerContext, workerPool, workspaceWorker, metrics)
	}()
	var closeOnce sync.Once

	public := http.NewServeMux()
	public.Handle("/api/owner/", ownerAuth)
	public.Handle("/internal/v1/cpa/degradation-events", ownerAuth)
	public.Handle("/owner/", staticHandler)
	private := http.NewServeMux()
	private.Handle(livePath, health)
	private.Handle(readyPath, health)
	private.Handle(metricsPath, metrics.Handler())
	publicRedeem := &recoveryGateAPI{PublicRedeemHandler: NewPublicRedeemHandler(workerPool, keyRing, health)}
	internalapi.HandlerFromMux(publicRedeem, private)
	return ControlHandlers{
		Public:          metrics.CountRequests(public),
		Private:         metrics.CountRequests(private),
		PlatformClients: config.PlatformClients,
		Close: func() {
			closeOnce.Do(func() {
				// Stop and join the worker before closing the pool it owns.
				cancelWorker()
				<-workerDone
				closeOwnerAuth()
				workerPool.Close()
				config.PlatformClients.CloseIdleConnections()
				closeHealth()
			})
		},
	}, nil
}

func runWorkspaceWorker(ctx context.Context, pool *pgxpool.Pool, worker *task.Worker, metrics *Metrics) {
	workers := make([]*task.Worker, 100)
	for i := range workers {
		clone := *worker
		clone.ID = fmt.Sprintf("%s-%d", worker.ID, i+1)
		workers[i] = &clone
	}
	busy := make([]bool, 100)
	done := make(chan int, 100)
	var group sync.WaitGroup
	defer group.Wait()
	ticker := time.NewTicker(time.Second)
	cleanupTicker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case index := <-done:
			busy[index] = false
		case <-ticker.C:
			queued, running, expired := int64(0), int64(0), int64(0)
			_ = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status IN ('queued','retry_wait')), count(*) FILTER (WHERE status='running' AND lease_expires_at>now()), count(*) FILTER(WHERE status='running' AND lease_expires_at<=now()) FROM tsw_tasks`).Scan(&queued, &running, &expired)
			metrics.SetTaskCounts(queued, running, int64(worker.Egress.ActiveCount()))
			var personalQueued int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_personal_probe_items WHERE status='queued' OR status='running' AND started_at<now()-interval '5 minutes'`).Scan(&personalQueued)
			if queued == 0 && personalQueued == 0 && expired == 0 {
				continue
			}
			limit := 1
			if manager, ok := worker.Egress.(interface{ Concurrency() int }); ok {
				limit = manager.Concurrency()
			}
			for index := 0; index < limit; index++ {
				if busy[index] {
					continue
				}
				busy[index] = true
				group.Add(1)
				go func(index int) {
					defer group.Done()
					didWork, err := workers[index].RunOnce(ctx)
					if err != nil {
						metrics.IncTaskResult(false)
					} else if didWork {
						metrics.IncTaskResult(true)
					}
					select {
					case done <- index:
					case <-ctx.Done():
					}
				}(index)
			}
		case now := <-cleanupTicker.C:
			period := now.UTC().Format("20060102T1504")
			if _, err := worker.Store.EnqueueRetentionCleanup(ctx, period); err != nil {
				metrics.IncRetentionScheduleFailure()
			}
			if _, err := worker.Store.EnqueueExpiredCleanups(ctx, 100, period); err != nil {
				metrics.IncRetentionScheduleFailure()
			}
			if _, err := worker.Store.EnqueueDeliveryProbes(ctx, "", "scheduler:"+period, period); err != nil {
				metrics.IncTaskResult(false)
			}
		}
	}
}
