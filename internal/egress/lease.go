package egress

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	ErrLeaseExhausted = errors.New("proxy_capacity_exhausted")
	ErrLeaseReleased  = errors.New("egress_lease_released")
	ErrEgressDrift    = errors.New("proxy_egress_drift")
	ErrNodeInUse      = errors.New("proxy_node_in_use")
	ErrSessionExpired = errors.New("proxy_session_expired")
	errLeaseBusy      = errors.New("proxy_capacity_busy")
)

const MinimumStableWindow = 2 * time.Minute

type stableWindowKey struct{}

// WithStableWindow reserves enough lifetime for a multi-stage business attempt.
func WithStableWindow(ctx context.Context, minimum time.Duration) context.Context {
	return context.WithValue(ctx, stableWindowKey{}, minimum)
}
func stableWindow(ctx context.Context) time.Duration {
	if minimum, ok := ctx.Value(stableWindowKey{}).(time.Duration); ok && minimum > MinimumStableWindow {
		return minimum
	}
	return MinimumStableWindow
}

// Lease binds one attempt to one admitted route. Release is explicit: closing
// HTTP connections must never make the same measured exit available early.
type Lease struct {
	manager     *LeaseManager
	candidate   Candidate
	client      *http.Client
	mode        Mode
	fingerprint [32]byte
	verifiedAt  time.Time
	mu          sync.Mutex
	released    bool
	onRelease   func()
}

func (l *Lease) Mode() Mode           { return l.mode }
func (l *Lease) Client() *http.Client { return l.client }
func (l *Lease) Scheme() string       { return l.candidate.Scheme }
func (l *Lease) KeyVersion() string {
	if l.mode != ModeRequired || l.manager == nil {
		return ""
	}
	return l.manager.router.config.HMACKeyVersion
}
func (l *Lease) VerifiedAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verifiedAt
}
func (l *Lease) Fingerprint() [32]byte { return l.fingerprint }
func (l *Lease) Candidate() Candidate  { return l.candidate }

// Release returns shared business capacity exactly once. Direct leases own no fingerprint.
func (l *Lease) Release() {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.released = true
	l.mu.Unlock()
	l.client.CloseIdleConnections()
	if l.manager != nil {
		l.manager.router.forgetClient(l.client)
	}
	if l.manager != nil {
		l.manager.release(l.fingerprint, l.mode)
	}
	if l.onRelease != nil {
		l.onRelease()
	}
}

// Remeasure verifies that a later platform stage still uses the originally leased exit.
func (l *Lease) Remeasure(ctx context.Context) error {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return ErrLeaseReleased
	}
	l.mu.Unlock()
	if l.mode == ModeDirect {
		return nil
	}
	body, err := probeBody(ctx, l.client, l.manager.router.config.IPEchoURL)
	if err != nil {
		l.manager.exclude(l.fingerprint)
		return ErrEgressDrift
	}
	addr, err := NormalizePublicIP(body)
	if err != nil {
		l.manager.exclude(l.fingerprint)
		return ErrEgressDrift
	}
	measured := Fingerprint(l.manager.router.config.HMACKey, l.manager.router.config.HMACKeyVersion, addr)
	if subtle.ConstantTimeCompare(measured[:], l.fingerprint[:]) != 1 {
		l.manager.exclude(l.fingerprint)
		return ErrEgressDrift
	}
	l.mu.Lock()
	l.verifiedAt = time.Now().UTC()
	l.mu.Unlock()
	return nil
}

// LeaseManager provides the ADR-0004 in-process exclusion boundary for a single worker.
type LeaseManager struct {
	router       *Router
	mu           sync.Mutex
	candidates   []Candidate
	active       map[[32]byte]Candidate
	quarantined  map[string]time.Time
	mode         Mode
	directActive int
}

// ReplaceAdmission replaces availability without changing active leases. Active
// identities are retained separately, including routes removed by a probe.
func (m *LeaseManager) ReplaceAdmission(admission Admission) {
	if m == nil || m.router.config.Mode != ModeRequired {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.candidates = m.candidates[:0]
	for _, candidate := range admission.Candidates {
		if quarantined, ok := m.quarantined[candidate.ID]; ok {
			if !candidate.VerifiedAt.After(quarantined) {
				m.router.invalidateCandidate(candidate.Fingerprint)
				continue
			}
			delete(m.quarantined, candidate.ID)
		}
		m.candidates = append(m.candidates, candidate)
	}
}

func NewLeaseManager(router *Router, admission Admission) (*LeaseManager, error) {
	if router == nil {
		return nil, errors.New("egress router is required")
	}
	manager := &LeaseManager{router: router, mode: router.config.Mode, active: make(map[[32]byte]Candidate), quarantined: make(map[string]time.Time)}
	if router.config.Mode == ModeRequired {
		manager.candidates = append(manager.candidates, admission.Candidates...)
	}
	return manager, nil
}

// Acquire never falls back and remeasures required candidates before their
// first business request. Drifted routes are quarantined until the next process admission.
func (m *LeaseManager) Acquire(ctx context.Context) (*Lease, error) {
	return m.acquire(ctx, 0)
}

func (m *LeaseManager) acquire(ctx context.Context, limit int) (*Lease, error) {
	drifted := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m.mu.Lock()
		if limit > 0 && len(m.active)+m.directActive >= limit {
			m.mu.Unlock()
			return nil, errors.Join(ErrLeaseExhausted, errLeaseBusy)
		}
		if m.mode == ModeDirect {
			m.directActive++
			m.mu.Unlock()
			client := m.router.clientForTransport(m.router.directTransport())
			return &Lease{manager: m, client: client, mode: ModeDirect}, nil
		}
		var selected *Candidate
		for index := range m.candidates {
			candidate := m.candidates[index]
			if !candidate.endpoint.StableUntil.IsZero() && time.Until(candidate.endpoint.StableUntil) < stableWindow(ctx) {
				continue
			}
			if _, used := m.active[candidate.Fingerprint]; used {
				continue
			}
			busy := false
			for _, active := range m.active {
				if active.ID == candidate.ID {
					busy = true
					break
				}
			}
			if busy {
				continue
			}
			selected = &candidate
			m.active[candidate.Fingerprint] = candidate
			break
		}
		m.mu.Unlock()
		if selected == nil {
			if drifted {
				return nil, ErrEgressDrift
			}
			return nil, ErrLeaseExhausted
		}
		client, err := m.router.ClientFor(*selected)
		if err != nil {
			m.quarantine(selected.Fingerprint)
			continue
		}
		lease := &Lease{
			manager: m, candidate: *selected, client: client, mode: ModeRequired,
			fingerprint: selected.Fingerprint, verifiedAt: selected.VerifiedAt,
		}
		if !selected.endpoint.StableUntil.IsZero() {
			lease.client.Transport = sessionTransport{next: lease.client.Transport, until: selected.endpoint.StableUntil}
		}
		if err := lease.Remeasure(ctx); err != nil {
			drifted = true
			lease.Release()
			continue
		}
		return lease, nil
	}
}

func (m *LeaseManager) quarantine(fingerprint [32]byte) {
	m.mu.Lock()
	delete(m.active, fingerprint)
	m.excludeLocked(fingerprint)
	m.mu.Unlock()
}

func (m *LeaseManager) exclude(fingerprint [32]byte) {
	m.mu.Lock()
	m.excludeLocked(fingerprint)
	m.mu.Unlock()
}

func (m *LeaseManager) excludeLocked(fingerprint [32]byte) {
	for index, candidate := range m.candidates {
		if candidate.Fingerprint == fingerprint {
			if m.quarantined == nil {
				m.quarantined = make(map[string]time.Time)
			}
			m.quarantined[candidate.ID] = time.Now()
			m.router.invalidateCandidate(fingerprint)
			m.candidates = append(m.candidates[:index], m.candidates[index+1:]...)
			break
		}
	}
}

func (m *LeaseManager) release(fingerprint [32]byte, mode Mode) {
	m.mu.Lock()
	if mode == ModeDirect {
		m.directActive--
	} else {
		delete(m.active, fingerprint)
	}
	m.mu.Unlock()
}

func (m *LeaseManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active) + m.directActive
}

func (m *LeaseManager) setMode(mode Mode) {
	m.mu.Lock()
	m.mode = mode
	m.mu.Unlock()
}

func (m *LeaseManager) ActiveCandidateIDs() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]int)
	for _, candidate := range m.active {
		result[candidate.ID]++
	}
	return result
}

// RemoveIdleNode holds the same boundary as lease reservation while the short
// persistence operation runs. The node cannot become leased between the check
// and deletion, and is removed from availability only after persistence succeeds.
func (m *LeaseManager) RemoveIdleNode(id string, remove func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, candidate := range m.active {
		if candidate.ID == id {
			return ErrNodeInUse
		}
	}
	if err := remove(); err != nil {
		return err
	}
	delete(m.quarantined, id)
	kept := m.candidates[:0]
	for _, candidate := range m.candidates {
		if candidate.ID != id {
			kept = append(kept, candidate)
		}
	}
	m.candidates = kept
	return nil
}

// sessionTransport refuses to continue a workflow after its promised stable window.
type sessionTransport struct {
	next  http.RoundTripper
	until time.Time
}

func (s sessionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !s.until.After(time.Now()) {
		return nil, ErrSessionExpired
	}
	return s.next.RoundTrip(req)
}
func (s sessionTransport) CloseIdleConnections() {
	if c, ok := s.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
