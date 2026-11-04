package egress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlatformBrowserChallengeIsNotProxyRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			_, _ = w.Write([]byte("1.1.1.1"))
			return
		}
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	router, err := NewManaged("http://platform.test/", "http://platform.test/echo", []byte("fixture-key"), "1")
	if err != nil {
		t.Fatal(err)
	}
	_, steps, code := router.VerifyEndpoint(t.Context(), Endpoint{ID: "fixture", URL: server.URL})
	if code != "proxy_browser_challenge" || len(steps) != 2 || steps[0].Code != "" || steps[1].HTTPStatus != http.StatusForbidden {
		t.Fatalf("browser challenge misclassified as an unusable proxy: code=%s steps=%+v", code, steps)
	}
}

func TestConfiguredReachabilityUsesProxyForDraftAdmissionAndLease(t *testing.T) {
	var platformHTTPCalls, browserCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") == "" {
			t.Error("probe escaped its authenticated proxy")
		}
		if r.URL.Path == "/echo" {
			_, _ = w.Write([]byte("1.1.1.1"))
			return
		}
		platformHTTPCalls.Add(1)
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	endpoint := Endpoint{ID: "fixture", URL: strings.Replace(proxy.URL, "://", "://fixture:secret@", 1)}
	config := Config{Mode: ModeRequired, ReachabilityURL: "http://platform.test/", IPEchoURL: "http://platform.test/echo", HMACKey: []byte("fixture-key"), HMACKeyVersion: "1"}
	config.ReachabilityProbe = func(ctx context.Context, client *http.Client, target string) (ReachabilityResult, error) {
		browserCalls.Add(1)
		if target != config.ReachabilityURL {
			t.Fatal("wrong platform target")
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, config.IPEchoURL, nil)
		response, err := client.Do(request)
		if err != nil {
			return ReachabilityResult{}, err
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if string(body) != "1.1.1.1" {
			t.Fatal("browser probe changed proxy exit")
		}
		return ReachabilityResult{HTTPStatus: http.StatusOK}, nil
	}
	router, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer router.CloseIdleConnections()
	_, steps, code := router.VerifyEndpoint(t.Context(), endpoint)
	if code != "" || steps[1].Code != "" {
		t.Fatalf("successful browser draft rejected: %s %+v", code, steps)
	}
	admission, err := router.AdmitEndpoints(t.Context(), []Endpoint{endpoint})
	if err != nil || admission.UniqueExitCount() != 1 {
		t.Fatalf("browser-capable proxy not admitted: %v %+v", err, admission.Failures)
	}
	leases, err := NewLeaseManager(router, admission)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(leases, router.Status(admission))
	lease, err := manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err := lease.Remeasure(t.Context()); err != nil {
		t.Fatalf("business lease changed the measured proxy exit: %v", err)
	}
	if browserCalls.Load() != 2 || platformHTTPCalls.Load() != 0 {
		t.Fatalf("platform did not exclusively use configured browser: browser=%d HTTP=%d", browserCalls.Load(), platformHTTPCalls.Load())
	}
}

func TestProxyAuthenticationFailureNeverRunsBrowserProbe(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	router, err := New(Config{Mode: ModeRequired, ReachabilityURL: "http://platform.test/", IPEchoURL: "http://platform.test/echo", HMACKey: []byte("key"), HMACKeyVersion: "1", ReachabilityProbe: func(context.Context, *http.Client, string) (ReachabilityResult, error) {
		t.Fatal("browser ran after proxy authentication failed")
		return ReachabilityResult{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, steps, code := router.VerifyEndpoint(t.Context(), Endpoint{ID: "fixture", URL: proxy.URL})
	if code != "proxy_auth_rejected" || len(steps) != 1 || steps[0].Stage != "exit" || steps[0].HTTPStatus != http.StatusProxyAuthRequired {
		t.Fatalf("proxy auth failure lost: %s %+v", code, steps)
	}
}

func TestProxyDiagnosticsLifetimeAndCachedVerification(t *testing.T) {
	var hits atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/echo" {
			w.Write([]byte("1.1.1.1"))
			return
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()
	router, err := NewManaged("http://fixture.test/ready", "http://fixture.test/echo", []byte(strings.Repeat("k", 32)), "1")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := Endpoint{ID: "fixture", URL: server.URL, StableUntil: time.Now().Add(90 * time.Second)}
	admission, err := router.AdmitEndpoints(context.Background(), []Endpoint{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	checked := hits.Load()
	if _, err := router.admitSelected(context.Background(), []Endpoint{endpoint}, map[string]bool{}); err != nil || hits.Load() != checked {
		t.Fatal("unchanged endpoint was probed again")
	}
	leases, _ := NewLeaseManager(router, admission)
	manager := NewManager(leases, router.Status(admission))
	if _, err := manager.Acquire(context.Background()); !errors.Is(err, ErrLeaseExhausted) {
		t.Fatal("short session admitted for OAuth")
	}
	endpoint.StableUntil = time.Now().Add(3 * time.Minute)
	if _, err := manager.Reload(context.Background(), []Endpoint{endpoint}); err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	router.mu.Lock()
	transports := len(router.transports)
	router.mu.Unlock()
	if transports != 0 {
		t.Fatal("released client transport retained")
	}
	for _, code := range []int{401, 403, 407, 429} {
		status.Store(int32(code))
		_, steps, failure := router.VerifyEndpoint(context.Background(), endpoint)
		if failure == "" || steps[len(steps)-1].HTTPStatus != code {
			t.Fatal("target HTTP status lost")
		}
		body, _ := json.Marshal(steps)
		if strings.Contains(string(body), server.URL) {
			t.Fatal("diagnostic leaked endpoint")
		}
	}
	status.Store(http.StatusOK)
	endpoint.Rotating = true
	_, _, failure := router.VerifyEndpoint(context.Background(), endpoint)
	if failure != "proxy_session_unstable" {
		t.Fatal("rotating endpoint admitted")
	}
}

func TestManagerConcurrentAdmissionAndReleaseNotification(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			w.Write([]byte("1.1.1.1"))
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	router, _ := NewManaged("http://fixture.test/ready", "http://fixture.test/echo", []byte(strings.Repeat("k", 32)), "1")
	admission, err := router.AdmitEndpoints(ctx, []Endpoint{{ID: "fixture", URL: server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	leases, _ := NewLeaseManager(router, admission)
	manager := NewManager(leases, router.Status(admission))
	manager.SetConcurrency(1)
	results := make(chan *Lease, 8)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			// The first admission performs an HTTP egress remeasurement. Keep the
			// contention window bounded, but allow that real probe to complete on
			// a loaded CI runner before declaring the slot unavailable.
			waiting, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			lease, err := manager.Acquire(waiting)
			if err == nil {
				results <- lease
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("unexpected acquire: %v", err)
			}
		}()
	}
	group.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("concurrent acquisition count %d", len(results))
	}
	held := <-results
	manager.SetRefillSignal(func() {})
	waiting := make(chan *Lease, 1)
	failure := make(chan error, 1)
	go func() {
		lease, err := manager.Acquire(ctx)
		if err != nil {
			failure <- err
		} else {
			waiting <- lease
		}
	}()
	held.Release()
	select {
	case lease := <-waiting:
		lease.Release()
	case err := <-failure:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("release failed to wake waiting task")
	}
}

func TestProxyDriftCannotBeRestoredFromCachedAdmission(t *testing.T) {
	var changed atomic.Bool
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/echo" {
			if changed.Load() {
				w.Write([]byte("8.8.8.8"))
			} else {
				w.Write([]byte("1.1.1.1"))
			}
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	ctx := context.Background()
	router, _ := NewManaged("http://fixture.test/ready", "http://fixture.test/echo", []byte(strings.Repeat("k", 32)), "1")
	endpoint := Endpoint{ID: "fixture", URL: server.URL}
	original, err := router.AdmitEndpoints(ctx, []Endpoint{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	leases, _ := NewLeaseManager(router, original)
	manager := NewManager(leases, router.Status(original))
	lease, err := manager.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed.Store(true)
	if err := lease.Remeasure(ctx); !errors.Is(err, ErrEgressDrift) {
		t.Fatal("drift not rejected")
	}
	lease.Release()
	// A maintenance pass which already copied the original cache cannot undo quarantine.
	leases.ReplaceAdmission(original)
	if _, err := manager.Acquire(ctx); !errors.Is(err, ErrLeaseExhausted) {
		t.Fatal("stale cached admission bypassed quarantine")
	}
	measuredBefore := hits.Load()
	next, err := manager.ReloadSelected(ctx, []Endpoint{endpoint}, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() <= measuredBefore || next.Candidates[0].Fingerprint == original.Candidates[0].Fingerprint {
		t.Fatal("quarantined route reused without fresh verification")
	}
	lease, err = manager.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
}
