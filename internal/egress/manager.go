package egress

import (
	"context"
	"errors"
	"sync"
)

// LeaseProvider is the narrow, already-verified route required by a platform attempt.
type LeaseProvider interface {
	Acquire(ctx context.Context) (*Lease, error)
	ActiveCount() int
}

// Manager exposes the active lease pool and its redacted admission status.
// Owner-managed verification can replace candidates at runtime while existing
// leases remain bound to their original routes.
type Manager struct {
	pool     *LeaseManager
	status   Status
	router   *Router
	mu       sync.RWMutex
	reloadMu sync.Mutex
	limit    int
	onChange func()
	capacity chan struct{}
}

func NewManager(pool *LeaseManager, status Status) *Manager {
	var router *Router
	if pool != nil {
		router = pool.router
	}
	return &Manager{pool: pool, status: status, router: router, limit: 5, capacity: make(chan struct{})}
}

func (m *Manager) Acquire(ctx context.Context) (*Lease, error) {
	if m == nil || m.pool == nil {
		return nil, ErrLeaseExhausted
	}
	for {
		m.mu.RLock()
		limit := m.limit
		changed := m.capacity
		m.mu.RUnlock()
		lease, err := m.pool.acquire(ctx, limit)
		if err == nil {
			lease.onRelease = m.signalChange
			return lease, nil
		}
		m.signalRefill()
		if !errors.Is(err, errLeaseBusy) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (m *Manager) ActiveCount() int {
	if m == nil || m.pool == nil {
		return 0
	}
	return m.pool.ActiveCount()
}

func (m *Manager) ActiveNodeCounts() map[string]int {
	if m == nil || m.pool == nil {
		return nil
	}
	return m.pool.ActiveCandidateIDs()
}

func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneStatus(m.status)
}

// SetMode changes only future acquisitions; active direct and proxy leases keep
// their transport and continue to count against the same concurrency ceiling.
func (m *Manager) SetMode(mode Mode) {
	if m == nil || m.pool == nil || (mode != ModeDirect && mode != ModeRequired) {
		return
	}
	m.reloadMu.Lock()
	m.pool.setMode(mode)
	m.mu.Lock()
	m.status.Policy = mode
	m.mu.Unlock()
	m.reloadMu.Unlock()
	m.capacityChanged()
}

// SetConcurrency changes the process-wide admission ceiling used by every
// business page. It affects new acquisitions and never interrupts a lease.
func (m *Manager) SetConcurrency(limit int) {
	if m == nil || limit < 1 || limit > 100 {
		return
	}
	m.mu.Lock()
	m.limit = limit
	m.mu.Unlock()
	m.capacityChanged()
}

func (m *Manager) SetProbeConcurrency(limit int) {
	if m == nil || m.router == nil || limit < 1 || limit > 100 {
		return
	}
	m.router.SetProbeConcurrency(limit)
}

func (m *Manager) Concurrency() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.limit
}

// Reload verifies and publishes the endpoint set maintained by the Owner
// proxy pool. Existing leases are kept until release; failed nodes never enter
// the new candidate set.
func (m *Manager) Reload(ctx context.Context, endpoints []Endpoint) (Admission, error) {
	return m.ReloadSelected(ctx, endpoints, nil)
}

// ReloadSelected reuses byte-identical healthy routes while probing only changed or selected ones.
func (m *Manager) ReloadSelected(ctx context.Context, endpoints []Endpoint, selected map[string]bool) (Admission, error) {
	if m == nil || m.router == nil || m.pool == nil {
		return Admission{}, ErrLeaseExhausted
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	admission, err := m.router.admitSelected(ctx, endpoints, selected)
	m.pool.ReplaceAdmission(admission)
	m.mu.Lock()
	policy := m.status.Policy
	m.status = m.router.Status(admission)
	m.status.Policy = policy
	m.mu.Unlock()
	m.capacityChanged()
	return admission, err
}

func (m *Manager) RemoveIdleNode(id string, remove func() error) error {
	if m == nil || m.pool == nil {
		return ErrLeaseExhausted
	}
	return m.pool.RemoveIdleNode(id, remove)
}

func cloneStatus(status Status) Status {
	status.AdmittedByScheme = copyCounts(status.AdmittedByScheme)
	status.FailureClasses = copyCounts(status.FailureClasses)
	return status
}

func copyCounts(input map[string]int) map[string]int {
	if input == nil {
		return nil
	}
	out := make(map[string]int, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

// SetRefillSignal installs a nonblocking notification owned by the runtime maintainer.
func (m *Manager) SetRefillSignal(signal func()) { m.mu.Lock(); m.onChange = signal; m.mu.Unlock() }
func (m *Manager) capacityChanged() {
	m.mu.Lock()
	if m.capacity != nil {
		close(m.capacity)
	}
	m.capacity = make(chan struct{})
	m.mu.Unlock()
}
func (m *Manager) signalChange() { m.capacityChanged(); m.signalRefill() }
func (m *Manager) signalRefill() {
	m.mu.RLock()
	notify := m.onChange
	m.mu.RUnlock()
	if notify != nil && m.Status().Policy != ModeDirect {
		notify()
	}
}
