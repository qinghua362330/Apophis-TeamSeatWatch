package egress

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
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

// PinLease converts one acquired lease into an exact admitted node lease while
// preserving its single global capacity reservation. A busy target is waited
// for without acquiring a second slot, so a limit of one cannot deadlock.
func (m *Manager) PinLease(ctx context.Context, outer *Lease, nodeID string, expectedFP []byte) (*Lease, error) {
	if m == nil || m.pool == nil || outer == nil || outer.manager != m.pool || nodeID == "" {
		return nil, ErrLeaseExhausted
	}
	if len(expectedFP) != 0 && len(expectedFP) != 32 {
		return nil, ErrEgressDrift
	}
	outer.mu.Lock()
	if outer.released {
		outer.mu.Unlock()
		return nil, ErrLeaseReleased
	}
	oldMode, oldCandidate, oldFP, oldClient := outer.mode, outer.candidate, outer.fingerprint, outer.client
	outer.mu.Unlock()
	converted := false
	for {
		m.mu.RLock()
		changed := m.capacity
		m.mu.RUnlock()
		m.pool.mu.Lock()
		if !converted {
			if oldMode == ModeRequired {
				delete(m.pool.active, oldFP)
				m.pool.directActive++
			}
			converted = true
			m.capacityChanged()
		}
		var target *Candidate
		busy := false
		for index := range m.pool.candidates {
			candidate := m.pool.candidates[index]
			if candidate.ID != nodeID {
				continue
			}
			if len(expectedFP) != 0 && subtle.ConstantTimeCompare(candidate.Fingerprint[:], expectedFP) != 1 {
				m.pool.mu.Unlock()
				m.restorePinReservation(outer, oldMode, oldCandidate, oldFP)
				return nil, ErrEgressDrift
			}
			if !candidate.endpoint.StableUntil.IsZero() && time.Until(candidate.endpoint.StableUntil) < stableWindow(ctx) {
				continue
			}
			if _, used := m.pool.active[candidate.Fingerprint]; used || m.pool.pinning[candidate.Fingerprint] {
				busy = true
				continue
			}
			copy := candidate
			target = &copy
			break
		}
		if target == nil {
			m.pool.mu.Unlock()
			if !busy {
				m.restorePinReservation(outer, oldMode, oldCandidate, oldFP)
				return nil, ErrTargetNotFound
			}
			select {
			case <-ctx.Done():
				m.restorePinReservation(outer, oldMode, oldCandidate, oldFP)
				return nil, ctx.Err()
			case <-changed:
			}
			continue
		}
		if m.pool.pinning == nil {
			m.pool.pinning = make(map[[32]byte]bool)
		}
		m.pool.pinning[target.Fingerprint] = true
		m.pool.mu.Unlock()

		client, err := m.router.ClientFor(*target)
		var candidateLease *Lease
		if err == nil {
			candidateLease = &Lease{manager: m.pool, candidate: *target, client: client, mode: ModeRequired, fingerprint: target.Fingerprint, verifiedAt: target.VerifiedAt}
			if !target.endpoint.StableUntil.IsZero() {
				candidateLease.client.Transport = sessionTransport{next: candidateLease.client.Transport, until: target.endpoint.StableUntil}
			}
			err = candidateLease.Remeasure(ctx)
		}
		if err == nil {
			outer.mu.Lock()
			m.pool.mu.Lock()
			delete(m.pool.pinning, target.Fingerprint)
			m.pool.directActive--
			m.pool.active[target.Fingerprint] = *target
			outer.mode, outer.candidate, outer.client, outer.fingerprint, outer.verifiedAt = candidateLease.mode, candidateLease.candidate, candidateLease.client, candidateLease.fingerprint, candidateLease.verifiedAt
			m.pool.mu.Unlock()
			outer.mu.Unlock()
			m.capacityChanged()
			if oldClient != nil && oldClient != candidateLease.client {
				oldClient.CloseIdleConnections()
				m.router.forgetClient(oldClient)
			}
			return outer, nil
		}
		if candidateLease != nil && candidateLease.client != nil {
			candidateLease.client.CloseIdleConnections()
			m.router.forgetClient(candidateLease.client)
		}
		m.pool.mu.Lock()
		delete(m.pool.pinning, target.Fingerprint)
		m.pool.mu.Unlock()
		m.restorePinReservation(outer, oldMode, oldCandidate, oldFP)
		m.capacityChanged()
		return nil, err
	}
}

func (m *Manager) restorePinReservation(outer *Lease, oldMode Mode, oldCandidate Candidate, oldFP [32]byte) {
	outer.mu.Lock()
	m.pool.mu.Lock()
	if oldMode == ModeRequired && m.poolHasCandidateLocked(oldCandidate) {
		if _, occupied := m.pool.active[oldFP]; occupied {
			outer.mode = ModeDirect
			outer.candidate = Candidate{}
			outer.fingerprint = [32]byte{}
			outer.verifiedAt = time.Time{}
			m.pool.mu.Unlock()
			outer.mu.Unlock()
			return
		}
		m.pool.active[oldFP] = oldCandidate
		m.pool.directActive--
	} else if oldMode == ModeRequired {
		outer.mode = ModeDirect
		outer.candidate = Candidate{}
		outer.fingerprint = [32]byte{}
		outer.verifiedAt = time.Time{}
	}
	m.pool.mu.Unlock()
	outer.mu.Unlock()
}

func (m *Manager) poolHasCandidateLocked(candidate Candidate) bool {
	for _, available := range m.pool.candidates {
		if available.ID == candidate.ID && available.Fingerprint == candidate.Fingerprint {
			return true
		}
	}
	return false
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
