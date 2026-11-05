package egress

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newPinFixture(t *testing.T, ips ...string) (*Manager, []Candidate, func()) {
	t.Helper()
	proxies := make([]*httptest.Server, 0, len(ips))
	endpoints := make([]Endpoint, 0, len(ips))
	for index, ip := range ips {
		ip := ip
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, ip)
		}))
		proxies = append(proxies, proxy)
		endpoints = append(endpoints, Endpoint{ID: string(rune('a' + index)), URL: proxy.URL})
	}
	router, err := NewManaged("http://platform.test/", "http://echo.test/", []byte("pin-test-key"), "1")
	if err != nil {
		t.Fatal(err)
	}
	admission, err := router.AdmitEndpoints(context.Background(), endpoints)
	if err != nil {
		router.CloseIdleConnections()
		t.Fatal(err)
	}
	pool, err := NewLeaseManager(router, admission)
	if err != nil {
		router.CloseIdleConnections()
		t.Fatal(err)
	}
	manager := NewManager(pool, router.Status(admission))
	manager.SetConcurrency(1)
	manager.SetRefillSignal(func() {})
	cleanup := func() {
		for _, proxy := range proxies {
			proxy.Close()
		}
		router.CloseIdleConnections()
	}
	return manager, admission.Candidates, cleanup
}

func TestPinLeaseFromDirectPreservesOneGlobalSlot(t *testing.T) {
	manager, candidates, cleanup := newPinFixture(t, "8.8.8.8")
	defer cleanup()
	manager.SetMode(ModeDirect)
	outer, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := manager.PinLease(context.Background(), outer, candidates[0].ID, candidates[0].Fingerprint[:])
	if err != nil || pinned != outer {
		t.Fatalf("pin err=%v same=%t", err, pinned == outer)
	}
	if pinned.Mode() != ModeRequired || pinned.Candidate().ID != candidates[0].ID || manager.ActiveCount() != 1 {
		t.Fatalf("pin state mode=%s node=%s active=%d", pinned.Mode(), pinned.Candidate().ID, manager.ActiveCount())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := manager.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second acquire err=%v, want deadline", err)
	}
	outer.Release()
	outer.Release()
	if manager.ActiveCount() != 0 {
		t.Fatalf("active after idempotent release=%d", manager.ActiveCount())
	}
}

func TestPinLeaseReplacesTransportRegistryEntry(t *testing.T) {
	manager, candidates, cleanup := newPinFixture(t, "8.8.8.8")
	defer cleanup()
	manager.SetMode(ModeDirect)
	outer, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := len(manager.router.transports); got != 1 {
		t.Fatalf("initial transport registry=%d, want 1", got)
	}
	if _, err = manager.PinLease(context.Background(), outer, candidates[0].ID, candidates[0].Fingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if got := len(manager.router.transports); got != 1 {
		t.Fatalf("transport registry after pin=%d, want 1", got)
	}
	outer.Release()
	if got := len(manager.router.transports); got != 0 {
		t.Fatalf("transport registry after release=%d, want 0", got)
	}
}

func TestPinLeaseRejectsWrongTargetWithoutFallback(t *testing.T) {
	manager, candidates, cleanup := newPinFixture(t, "8.8.8.8")
	defer cleanup()
	manager.SetMode(ModeDirect)
	outer, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PinLease(context.Background(), outer, "missing", nil); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("missing target err=%v", err)
	}
	if manager.ActiveCount() != 1 {
		t.Fatalf("missing target changed active count=%d", manager.ActiveCount())
	}
	wrong := append([]byte(nil), candidates[0].Fingerprint[:]...)
	wrong[0] ^= 0xff
	if _, err := manager.PinLease(context.Background(), outer, candidates[0].ID, wrong); !errors.Is(err, ErrEgressDrift) {
		t.Fatalf("fingerprint mismatch err=%v", err)
	}
	if manager.ActiveCount() != 1 {
		t.Fatalf("fingerprint mismatch changed active count=%d", manager.ActiveCount())
	}
	outer.Release()
}

func TestPinLeaseBusyTargetCanCancelWithoutLeak(t *testing.T) {
	manager, candidates, cleanup := newPinFixture(t, "8.8.8.8", "1.1.1.1")
	defer cleanup()
	manager.SetMode(ModeRequired)
	manager.SetConcurrency(2)
	first, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := manager.PinLease(ctx, first, candidates[1].ID, candidates[1].Fingerprint[:]); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy target err=%v", err)
	}
	if manager.ActiveCount() != 2 {
		t.Fatalf("busy target leaked capacity active=%d", manager.ActiveCount())
	}
	first.Release()
	second.Release()
	if manager.ActiveCount() != 0 {
		t.Fatalf("active after cleanup=%d", manager.ActiveCount())
	}
}

func TestPinLeaseTwoRequiredLeasesCanSwapNodes(t *testing.T) {
	manager, candidates, cleanup := newPinFixture(t, "8.8.8.8", "1.1.1.1")
	defer cleanup()
	manager.SetMode(ModeRequired)
	manager.SetConcurrency(2)
	first, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Acquire(context.Background())
	if err != nil {
		first.Release()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, pinErr := manager.PinLease(context.Background(), first, candidates[1].ID, candidates[1].Fingerprint[:])
		errs <- pinErr
	}()
	go func() {
		defer wg.Done()
		_, pinErr := manager.PinLease(context.Background(), second, candidates[0].ID, candidates[0].Fingerprint[:])
		errs <- pinErr
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			first.Release()
			second.Release()
			t.Fatalf("swap pin error: %v", err)
		}
	}
	if manager.ActiveCount() != 2 {
		t.Fatalf("swap changed global active count=%d", manager.ActiveCount())
	}
	first.Release()
	second.Release()
	if manager.ActiveCount() != 0 {
		t.Fatalf("swap cleanup active=%d", manager.ActiveCount())
	}
}
