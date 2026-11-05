package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/proxyprovider"
)

const proxyFetchLimit = 4 << 20

type subscriptionStatusError struct{ status int }

func (e subscriptionStatusError) Error() string {
	return "proxy subscription returned non-success status"
}

var (
	errInvalidProxySource   = errors.New("invalid_proxy_source")
	errInvalidProxyNodes    = errors.New("invalid_proxy_nodes")
	errInvalidProxyNode     = errors.New("invalid_proxy_node")
	errInvalidProxySettings = errors.New("invalid_proxy_settings")
)

type proxyControl struct {
	pool      *pgxpool.Pool
	ring      auth.KeyRing
	egress    *egress.Manager
	refresh   sync.Mutex
	wake      chan struct{}
	force     atomic.Bool
	refilling atomic.Bool
}

func newProxyControl(pool *pgxpool.Pool, ring auth.KeyRing, manager *egress.Manager) *proxyControl {
	p := &proxyControl{pool: pool, ring: ring, egress: manager, wake: make(chan struct{}, 1)}
	if manager != nil {
		manager.SetRefillSignal(p.notify)
	}
	return p
}
func (p *proxyControl) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *proxyControl) restoreSettings(ctx context.Context) error {
	if p == nil || p.egress == nil {
		return nil
	}
	var task, probe int
	var mode string
	if err := p.pool.QueryRow(ctx, `SELECT task_concurrency,probe_concurrency,routing_mode FROM tsw_proxy_pool_settings WHERE id=true`).Scan(&task, &probe, &mode); err != nil {
		return err
	}
	p.egress.SetConcurrency(task)
	p.egress.SetProbeConcurrency(probe)
	if mode == "direct" {
		p.egress.SetMode(egress.ModeDirect)
	} else {
		p.egress.SetMode(egress.ModeRequired)
	}
	return nil
}
func (p *proxyControl) loop(ctx context.Context) {
	_, _ = p.maintain(ctx)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = p.maintain(ctx)
		case <-p.wake:
			_, _ = p.maintain(ctx)
		}
	}
}
func (p *proxyControl) maintain(ctx context.Context) (ownerapi.ProxyPool, error) {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	return p.maintainLocked(ctx, p.force.Swap(false))
}
func (p *proxyControl) synchronize(ctx context.Context) (ownerapi.ProxyPool, error) {
	p.force.Store(true)
	p.notify()
	return p.view(ctx)
}

// Maintenance only probes pending or due records. It never extends session lifetimes.
func (p *proxyControl) maintainLocked(ctx context.Context, force bool) (ownerapi.ProxyPool, error) {
	if err := p.retireLocked(ctx); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	var accountRoutesEnabled bool
	if err := p.pool.QueryRow(ctx, `SELECT enabled FROM public.tsw_account_route_settings WHERE id=true`).Scan(&accountRoutesEnabled); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	if p.egress != nil && p.egress.Status().Policy == egress.ModeDirect && !accountRoutesEnabled {
		return p.view(ctx)
	}
	if _, err := p.verifyLocked(ctx, false, ""); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	sources, err := p.readSources(ctx)
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	var source *savedProxySource
	for i := range sources {
		if sources[i].enabled {
			source = &sources[i]
			break
		}
	}
	if source == nil {
		return p.view(ctx)
	}
	now := time.Now()
	if !force && source.retryAt != nil && source.retryAt.After(now) {
		return p.view(ctx)
	}
	if len(source.secret) == 0 {
		return p.view(ctx)
	}
	if source.settings.Kind == "subscription" {
		if force || source.lastSynced == nil || time.Since(*source.lastSynced) >= time.Duration(source.settings.UpdateSeconds)*time.Second {
			if err := p.syncSubscription(ctx, *source); err != nil {
				if _, saveErr := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_sources SET last_error=$2,retry_at=now()+interval '1 minute' WHERE id=$1`, source.id, err.Error()); saveErr != nil {
					return ownerapi.ProxyPool{}, saveErr
				}
			} else {
				if _, err := p.verifyLocked(ctx, false, ""); err != nil {
					return ownerapi.ProxyPool{}, err
				}
			}
		}
		return p.view(ctx)
	}
	view, err := p.view(ctx)
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	deficit := max(0, view.TargetHealthy-view.HealthyCount)
	if deficit == 0 {
		return view, nil
	}
	if source.settings.SessionType != "sticky" {
		_, err = p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_sources SET last_error='动态换 IP 无法用于需要稳定出口的业务任务',retry_at=now()+interval '5 minutes' WHERE id=$1`, source.id)
		return p.viewAfter(ctx, err)
	}
	var credentials proxyprovider.Credentials
	if err := json.Unmarshal(source.secret, &credentials); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	p.refilling.Store(true)
	defer p.refilling.Store(false)
	generated := 0
	before := view.HealthyCount
	// Each refill has a bounded budget, even when a supplier returns duplicate or blocked exits.
	for round := 0; round < 2 && deficit > 0; round++ {
		count := min(deficit, 50)
		err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
			for i := 0; i < count; i++ {
				key, err := proxyprovider.SessionKey()
				if err != nil {
					return err
				}
				raw, err := proxyprovider.Endpoint(source.settings, credentials, key)
				if err != nil {
					return err
				}
				scheme, host, err := parseManagedProxy(raw)
				if err != nil {
					return err
				}
				until := time.Now().UTC().Add(time.Duration(source.settings.SessionMinutes) * time.Minute)
				region := strings.Join(nonempty(source.settings.Country, source.settings.State, source.settings.City), " / ")
				if err = p.saveNode(ctx, tx, source.id, raw, scheme, host, key[:8], region, &until, source.settings.SessionType); err != nil {
					return err
				}
				generated++
			}
			return nil
		})
		if err != nil {
			return ownerapi.ProxyPool{}, err
		}
		view, err = p.verifyLocked(ctx, false, "")
		if err != nil {
			return ownerapi.ProxyPool{}, err
		}
		deficit = max(0, view.TargetHealthy-view.HealthyCount)
	}
	succeeded := max(0, view.HealthyCount-before)
	if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_settings SET refill_requested=$1,refill_generated=$2,refill_succeeded=$3,last_refill_at=now() WHERE id=true`, max(0, view.TargetHealthy-before), generated, succeeded); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	message := ""
	var retry *time.Time
	if deficit > 0 {
		message = fmt.Sprintf("补齐未达标：成功 %d，仍缺 %d；稍后自动重试", succeeded, deficit)
		value := time.Now().Add(time.Minute)
		retry = &value
	}
	if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_sources SET last_synced_at=now(),last_error=$2,retry_at=$3 WHERE id=$1`, source.id, message, retry); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	return p.view(ctx)
}
func nonempty(values ...string) []string {
	out := []string{}
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
func (p *proxyControl) viewAfter(ctx context.Context, err error) (ownerapi.ProxyPool, error) {
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	return p.view(ctx)
}

func (p *proxyControl) saveNode(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, raw, scheme, host, key, region string, until *time.Time, sessionType string) error {
	version, nonce, ciphertext, err := auth.EncryptSecret([]byte(raw), p.ring)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(raw))
	var source any
	if sourceID != uuid.Nil {
		source = sourceID
	}
	_, err = tx.Exec(ctx, `INSERT INTO tsw_proxy_pool_nodes(id,source_id,endpoint_key_version,endpoint_nonce,endpoint_ciphertext,endpoint_digest,scheme,display_host,state,session_key,region,stable_until,session_type) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11,$12) ON CONFLICT(endpoint_digest) DO UPDATE SET source_id=CASE WHEN tsw_proxy_pool_nodes.source_id IS NULL THEN NULL ELSE excluded.source_id END,retired=false,state=CASE WHEN tsw_proxy_pool_nodes.retired THEN 'pending' ELSE tsw_proxy_pool_nodes.state END,updated_at=now()`, uuid.New(), source, version, nonce, ciphertext, digest[:], scheme, host, key, region, until, sessionType)
	return err
}
func (p *proxyControl) importNodes(ctx context.Context, request ownerapi.ProxyNodeImportRequest) (ownerapi.ProxyPool, error) {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	if len(request.Proxies) == 0 || len(request.Proxies) > 1000 {
		return ownerapi.ProxyPool{}, errInvalidProxyNodes
	}
	type imported struct{ raw, scheme, host string }
	nodes := make([]imported, 0, len(request.Proxies))
	for _, value := range request.Proxies {
		raw := egress.NormalizeEndpointURL(value)
		scheme, host, err := parseManagedProxy(raw)
		if err != nil {
			return ownerapi.ProxyPool{}, errInvalidProxyNode
		}
		nodes = append(nodes, imported{raw, scheme, host})
	}
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		for _, node := range nodes {
			if err := p.saveNode(ctx, tx, uuid.Nil, node.raw, node.scheme, node.host, "", "", nil, "sticky"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	return p.verifyLocked(ctx, false, "")
}
func (p *proxyControl) probe(ctx context.Context) (ownerapi.ProxyPool, error) {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	return p.verifyLocked(ctx, true, "")
}
func (p *proxyControl) probeNode(ctx context.Context, id uuid.UUID) (ownerapi.ProxyPool, error) {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	var available bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_proxy_pool_nodes n LEFT JOIN tsw_proxy_pool_sources s ON s.id=n.source_id WHERE n.id=$1 AND NOT n.retired AND (n.stable_until IS NULL OR n.stable_until>now()+interval '2 minutes') AND (n.source_id IS NULL OR s.enabled))`, id).Scan(&available)
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	if !available {
		return ownerapi.ProxyPool{}, errInvalidProxyNode
	}
	return p.verifyLocked(ctx, false, id.String())
}

func (p *proxyControl) verifyLocked(ctx context.Context, all bool, selected string) (ownerapi.ProxyPool, error) {
	if p.egress == nil {
		return p.view(ctx)
	}
	rows, err := p.pool.Query(ctx, `SELECT n.id,n.endpoint_key_version,n.endpoint_nonce,n.endpoint_ciphertext,n.stable_until,n.session_type,n.state,n.checked_at FROM tsw_proxy_pool_nodes n LEFT JOIN tsw_proxy_pool_sources s ON s.id=n.source_id WHERE NOT n.retired AND (n.stable_until IS NULL OR n.stable_until>now()+interval '2 minutes') AND (n.source_id IS NULL OR s.enabled) ORDER BY n.created_at,n.id`)
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	endpoints := []egress.Endpoint{}
	refresh := map[string]bool{}
	secretsFailed := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var version int
		var nonce, ciphertext []byte
		var until, checked *time.Time
		var sessionType, state string
		if err := rows.Scan(&id, &version, &nonce, &ciphertext, &until, &sessionType, &state, &checked); err != nil {
			rows.Close()
			return ownerapi.ProxyPool{}, err
		}
		due := all || id.String() == selected || ((state == "pending" || state == "isolated") && (checked == nil || time.Since(*checked) >= time.Minute)) || (state == "healthy" && (checked == nil || time.Since(*checked) >= 5*time.Minute))
		if !due && state != "healthy" {
			continue
		}
		secret, err := auth.DecryptSecret(uint16(version), nonce, ciphertext, p.ring)
		if err != nil {
			secretsFailed = append(secretsFailed, id)
			continue
		}
		endpoint := egress.Endpoint{ID: id.String(), URL: string(secret), Rotating: sessionType == "rotating"}
		if until != nil {
			endpoint.StableUntil = *until
		}
		endpoints = append(endpoints, endpoint)
		if due {
			refresh[id.String()] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	admission, reloadErr := p.egress.ReloadSelected(ctx, endpoints, refresh)
	if ctx.Err() != nil {
		return ownerapi.ProxyPool{}, ctx.Err()
	}
	if reloadErr != nil && egress.ErrorCode(reloadErr) != "proxy_capacity_exhausted" {
		return ownerapi.ProxyPool{}, reloadErr
	}
	for _, candidate := range admission.Candidates {
		diagnostics, _ := json.Marshal(candidate.Diagnostics)
		if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_nodes SET state='healthy',failure_reason='',checked_at=$2,healthy_at=$2,diagnostics=$3 WHERE id=$1`, candidate.ID, candidate.VerifiedAt, diagnostics); err != nil {
			return ownerapi.ProxyPool{}, err
		}
	}
	verification := ownerapi.ProxyVerification{Diagnostics: []ownerapi.ProxyDiagnosticStep{}}
	for _, failure := range admission.Failures {
		diagnostics, _ := json.Marshal(failure.Diagnostics)
		remove := permanentlyUnusableProxy(failure.Code, failure.Diagnostics)
		if remove {
			verification.RemovedCount++
		} else {
			verification.RetryCount++
		}
		if len(verification.Diagnostics) == 0 {
			verification.Diagnostics = proxyDiagnostic(failure.Diagnostics, false).Steps
		}
		if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_nodes SET state=CASE WHEN $4 THEN 'isolated' ELSE 'pending' END,retired=$4,failure_reason=$2,checked_at=now(),diagnostics=$3 WHERE id=$1`, failure.ID, failure.Code, diagnostics, remove); err != nil {
			return ownerapi.ProxyPool{}, err
		}
	}
	for _, id := range secretsFailed {
		if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_nodes SET state='isolated',retired=true,failure_reason='secret_unavailable',checked_at=now() WHERE id=$1`, id); err != nil {
			return ownerapi.ProxyPool{}, err
		}
	}
	verification.RemovedCount += len(secretsFailed)
	if err := p.retireLocked(ctx); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	view, err := p.view(ctx)
	if verification.RemovedCount+verification.RetryCount > 0 {
		view.Verification = &verification
	}
	return view, err
}

// Retire before removal; active leases retain their original endpoint until release.
func (p *proxyControl) retireLocked(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_nodes SET retired=true WHERE state='isolated' AND failure_reason IN ('proxy_auth_rejected','egress_endpoint_invalid','egress_duplicate_exit','proxy_ip_echo_invalid','proxy_ip_echo_non_public','proxy_session_unstable','secret_unavailable')`); err != nil {
		return err
	}
	rejected, err := p.pool.Query(ctx, `SELECT id,diagnostics FROM tsw_proxy_pool_nodes WHERE NOT retired AND state='isolated' AND failure_reason='proxy_target_http_rejected'`)
	if err != nil {
		return err
	}
	rejectedIDs := []uuid.UUID{}
	for rejected.Next() {
		var id uuid.UUID
		var diagnostic []byte
		if err := rejected.Scan(&id, &diagnostic); err != nil {
			rejected.Close()
			return err
		}
		var steps []egress.ProbeStep
		if json.Unmarshal(diagnostic, &steps) == nil && permanentlyUnusableProxy("proxy_target_http_rejected", steps) {
			rejectedIDs = append(rejectedIDs, id)
		}
	}
	err = rejected.Err()
	rejected.Close()
	if err != nil {
		return err
	}
	if len(rejectedIDs) > 0 {
		if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_nodes SET retired=true WHERE id=ANY($1)`, rejectedIDs); err != nil {
			return err
		}
	}
	if _, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_nodes SET retired=true,state='isolated',failure_reason='proxy_session_expired' WHERE NOT retired AND stable_until<=now()+interval '2 minutes'`); err != nil {
		return err
	}
	// A route binding is durable account state. Retiring its node pauses the
	// account and deliberately keeps the node row for audit/reconciliation.
	if _, err := p.pool.Exec(ctx, `UPDATE public.tsw_account_route_bindings SET paused=true,paused_reason='proxy_retired',updated_at=now() WHERE node_id IN (SELECT id FROM public.tsw_proxy_pool_nodes WHERE retired)`); err != nil {
		return err
	}
	rows, err := p.pool.Query(ctx, `SELECT id FROM tsw_proxy_pool_nodes WHERE retired`)
	if err != nil {
		return err
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		var bound bool
		if err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_account_route_bindings WHERE node_id=$1)`, id).Scan(&bound); err != nil {
			return err
		}
		if bound {
			continue
		}
		remove := func() error {
			_, err := p.pool.Exec(ctx, `DELETE FROM tsw_proxy_pool_nodes WHERE id=$1`, id)
			return err
		}
		if p.egress != nil {
			err = p.egress.RemoveIdleNode(id.String(), remove)
		} else {
			err = remove()
		}
		if err != nil && !errors.Is(err, egress.ErrNodeInUse) {
			return err
		}
	}
	return nil
}

func permanentlyUnusableProxy(code string, steps []egress.ProbeStep) bool {
	switch code {
	case "proxy_timeout", "proxy_cancelled", "proxy_dns_failed", "proxy_connection_failed", "proxy_tls_failed", "proxy_browser_challenge", "proxy_browser_unavailable", "proxy_browser_verification_incomplete":
		return false
	case "proxy_target_http_rejected":
		rejected := false
		for _, step := range steps {
			if step.HTTPStatus >= 500 || step.HTTPStatus == 429 || step.HTTPStatus == 408 {
				return false
			}
			rejected = rejected || step.HTTPStatus >= 400
		}
		return rejected
	}
	return true
}
func (p *proxyControl) removeNode(ctx context.Context, id openapi_types.UUID) (ownerapi.ProxyPool, error) {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	remove := func() error {
		var bound bool
		if err := p.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_account_route_bindings WHERE node_id=$1)`, uuid.UUID(id)).Scan(&bound); err != nil {
			return err
		}
		if bound {
			return egress.ErrNodeInUse
		}
		_, err := p.pool.Exec(ctx, `DELETE FROM tsw_proxy_pool_nodes WHERE id=$1`, uuid.UUID(id))
		return err
	}
	var err error
	if p.egress != nil {
		err = p.egress.RemoveIdleNode(id.String(), remove)
	} else {
		err = remove()
	}
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	p.notify()
	return p.view(ctx)
}
func (p *proxyControl) updateSettings(ctx context.Context, request ownerapi.ProxyPoolSettingsRequest) (ownerapi.ProxyPool, error) {
	p.refresh.Lock()
	defer p.refresh.Unlock()
	if request.TargetHealthy != nil && (*request.TargetHealthy < 1 || *request.TargetHealthy > 1000) || request.ProbeConcurrency != nil && (*request.ProbeConcurrency < 1 || *request.ProbeConcurrency > 100) || request.TaskConcurrency != nil && (*request.TaskConcurrency < 1 || *request.TaskConcurrency > 100) {
		return ownerapi.ProxyPool{}, errInvalidProxySettings
	}
	_, err := p.pool.Exec(ctx, `UPDATE tsw_proxy_pool_settings SET target_healthy=COALESCE($1,target_healthy),probe_concurrency=COALESCE($2,probe_concurrency),task_concurrency=COALESCE($3,task_concurrency),updated_at=now() WHERE id=true`, request.TargetHealthy, request.ProbeConcurrency, request.TaskConcurrency)
	if err != nil {
		return ownerapi.ProxyPool{}, err
	}
	if err := p.restoreSettings(ctx); err != nil {
		return ownerapi.ProxyPool{}, err
	}
	if request.TargetHealthy != nil {
		p.force.Store(true)
		p.notify()
	}
	return p.view(ctx)
}

func (p *proxyControl) view(ctx context.Context, paging ...int) (ownerapi.ProxyPool, error) {
	page, size := 1, 20
	if len(paging) > 0 {
		page = paging[0]
	}
	if len(paging) > 1 {
		size = paging[1]
	}
	return p.filteredView(ctx, page, size, "", "")
}
func (p *proxyControl) filteredView(ctx context.Context, page, size int, state, kind string) (ownerapi.ProxyPool, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	size = min(size, 100)
	result := ownerapi.ProxyPool{Mode: ownerapi.ProxyPoolModeDirect, Page: page, PageSize: size, Refilling: p.refilling.Load(), Nodes: []ownerapi.ProxyPoolNode{}, Sources: []ownerapi.ProxyPoolSource{}, Providers: []ownerapi.ProxyProvider{}}
	if err := p.pool.QueryRow(ctx, `SELECT routing_mode,target_healthy,probe_concurrency,task_concurrency,refill_requested,refill_generated,refill_succeeded,last_refill_at FROM tsw_proxy_pool_settings WHERE id=true`).Scan(&result.Mode, &result.TargetHealthy, &result.ProbeConcurrency, &result.TaskConcurrency, &result.RefillRequested, &result.RefillGenerated, &result.RefillSucceeded, &result.LastRefillAt); err != nil {
		return result, err
	}
	active := map[string]int{}
	if p.egress != nil {
		active = p.egress.ActiveNodeCounts()
		result.ActiveLeases = p.egress.ActiveCount()
	}
	for _, d := range proxyprovider.Catalog() {
		result.Providers = append(result.Providers, ownerapi.ProxyProvider{Kind: d.Kind, Label: d.Label, Host: d.Host, Port: d.Port, MinMinutes: d.MinMinutes, MaxMinutes: d.MaxMinutes})
	}
	sources, err := p.readSources(ctx)
	if err != nil {
		return result, err
	}
	for _, saved := range sources {
		config, _ := json.Marshal(saved.settings)
		var form ownerapi.ProxySourceRequest
		if err := json.Unmarshal(config, &form); err != nil {
			return result, err
		}
		source := ownerapi.ProxyPoolSource{Id: saved.id, Kind: ownerapi.ProxyPoolSourceKind(saved.settings.Kind), Label: saved.settings.Label, Enabled: saved.enabled, Config: form, LastSyncedAt: saved.lastSynced, UrlMasked: ""}
		if saved.lastError != "" {
			value := saved.lastError
			source.LastError = &value
		}
		if saved.settings.Kind == "subscription" {
			if parsed, err := url.Parse(string(saved.secret)); err == nil {
				source.UrlMasked = parsed.Scheme + "://" + parsed.Host + "/…"
			}
		} else {
			var creds proxyprovider.Credentials
			if err := json.Unmarshal(saved.secret, &creds); err == nil {
				source.UsernameSet = creds.Username != ""
				source.PasswordSet = creds.Password != ""
			}
		}
		result.Sources = append(result.Sources, source)
		if saved.enabled {
			copy := source
			result.Source = &copy
		}
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE NOT n.retired AND ($1='' OR n.state=$1) AND ($2='' OR COALESCE(s.kind,'manual')=$2)),count(*) FILTER(WHERE state='healthy' AND NOT retired AND (stable_until IS NULL OR stable_until>now()+interval '2 minutes')),count(*) FILTER(WHERE state='pending' AND NOT retired),count(*) FILTER(WHERE state='isolated' AND NOT retired) FROM tsw_proxy_pool_nodes n LEFT JOIN tsw_proxy_pool_sources s ON s.id=n.source_id`, state, kind).Scan(&result.Total, &result.HealthyCount, &result.PendingCount, &result.IsolatedCount); err != nil {
		return result, err
	}
	rows, err := p.pool.Query(ctx, `SELECT n.id,n.source_id,n.scheme,n.display_host,n.state,n.failure_reason,n.checked_at,n.healthy_at,n.region,n.session_key,n.stable_until,n.diagnostics,COALESCE(s.kind,'manual') FROM tsw_proxy_pool_nodes n LEFT JOIN tsw_proxy_pool_sources s ON s.id=n.source_id WHERE NOT n.retired AND ($3='' OR n.state=$3) AND ($4='' OR COALESCE(s.kind,'manual')=$4) ORDER BY n.created_at DESC,n.id LIMIT $1 OFFSET $2`, size, (page-1)*size, state, kind)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var node ownerapi.ProxyPoolNode
		var raw []byte
		if err := rows.Scan(&node.Id, &node.SourceId, &node.Scheme, &node.DisplayHost, &node.State, &node.FailureReason, &node.CheckedAt, &node.HealthyAt, &node.Region, &node.SessionKey, &node.StableUntil, &raw, &node.SourceKind); err != nil {
			return result, err
		}
		node.Diagnostics = []ownerapi.ProxyDiagnosticStep{}
		if err := json.Unmarshal(raw, &node.Diagnostics); err != nil {
			return result, err
		}
		node.LeaseCount = active[node.Id.String()]
		result.Nodes = append(result.Nodes, node)
	}
	return result, rows.Err()
}

func fetchSubscription(ctx context.Context, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	// Subscription retrieval uses an explicit transport. The process-wide HTTP
	// proxy environment must not silently override Owner-managed routing.
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, subscriptionStatusError{status: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, proxyFetchLimit+1))
	if len(body) > proxyFetchLimit {
		return nil, errors.New("proxy_subscription_too_large")
	}
	return body, err
}

func parseSubscription(content []byte) []string {
	text := strings.TrimSpace(string(content))
	lines := splitSubscriptionCandidates(text)
	if !strings.Contains(text, "://") {
		encoded := strings.Join(strings.Fields(text), "")
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := encoding.DecodeString(encoded); err == nil {
				lines = splitSubscriptionCandidates(string(decoded))
				break
			}
		}
	}
	seen := make(map[string]bool, len(lines))
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = egress.NormalizeEndpointURL(strings.TrimSpace(strings.Trim(line, "\"'")))
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		if _, _, err := parseManagedProxy(line); err == nil {
			seen[line] = true
			out = append(out, line)
		}
	}
	return out
}

func splitSubscriptionCandidates(text string) []string {
	var candidates []string
	var current strings.Builder
	flush := func() {
		value := strings.TrimSpace(current.String())
		if value != "" {
			candidates = append(candidates, value)
		}
		current.Reset()
	}
	for _, char := range text {
		switch char {
		case '\n', '\r', ',':
			flush()
		case ' ', '\t':
			candidate := strings.Trim(strings.TrimSpace(current.String()), "\"'")
			if _, _, err := parseManagedProxy(candidate); err == nil {
				flush()
				continue
			}
			current.WriteRune(char)
		default:
			current.WriteRune(char)
		}
	}
	flush()
	return candidates
}

func parseManagedProxy(raw string) (string, string, error) {
	u, err := url.Parse(egress.NormalizeEndpointURL(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Port() == "" || !egress.ParsePort(u.Port()) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("invalid_proxy_node")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", "", errors.New("invalid_proxy_node")
	}
	if u.User != nil {
		if password, ok := u.User.Password(); !ok || u.User.Username() == "" || password == "" {
			return "", "", errors.New("invalid_proxy_node")
		}
	}
	return scheme, u.Host, nil
}
