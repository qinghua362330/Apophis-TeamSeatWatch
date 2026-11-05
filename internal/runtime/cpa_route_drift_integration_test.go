//go:build integration

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountroute"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
)

func TestCPACheckpointDriftPausesAccountAndPreventsUpload(t *testing.T) {
	pool, h, ring, ctx := newAutomaticRotationFixture(t)
	id := uuid.New()
	email := "route-renewal@example.test"
	_, version, fp, err := identity.Fingerprint(ring, identity.TargetLogin, email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,$4,$2)`, id, email, fp[:], version); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_credentials(target_account_id,password_secret,totp_secret,material_status,materials_sealed) VALUES($1,'sealed-password','sealed-totp','complete',true)`, id); err != nil {
		t.Fatal(err)
	}
	file := cpacred.File{Name: "route-renewal.json", Provider: "codex", Email: email, AccountID: "workspace-1", Revision: "old-material", StatusCode: 401}
	fake := &reauthCredentialFake{files: map[string]cpacred.File{file.Name: file}}
	h.cpaCredentials = fake
	h.cpaOAuthIssuer = func(context.Context, uuid.UUID, string, string, string) (cpacred.Credential, error) {
		t.Error("checkpoint retry issued another OAuth grant")
		return cpacred.Credential{}, errors.New("unexpected grant")
	}
	if err = h.enqueueCPAReauthorizations(ctx, []cpacred.File{file}); err != nil {
		t.Fatal(err)
	}
	work, ok, err := h.claimCPAReauthorization(ctx)
	if err != nil || !ok {
		t.Fatalf("claim=%v %v", ok, err)
	}
	var changed atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if changed.Load() {
			io.WriteString(w, "9.9.9.9")
		} else {
			io.WriteString(w, "8.8.8.8")
		}
	}))
	defer proxy.Close()
	keyVersion, key := ring.Current()
	router, err := egress.NewManaged("http://platform.test/", "http://echo.test/", key[:], "1")
	if err != nil {
		t.Fatal(err)
	}
	defer router.CloseIdleConnections()
	node := uuid.New()
	endpoint := egress.Endpoint{ID: node.String(), URL: proxy.URL}
	admitted, err := router.AdmitEndpoints(ctx, []egress.Endpoint{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	leases, err := egress.NewLeaseManager(router, admitted)
	if err != nil {
		t.Fatal(err)
	}
	manager := egress.NewManager(leases, router.Status(admitted))
	manager.SetMode(egress.ModeDirect)
	manager.SetConcurrency(1)
	_, nonce, ciphertext, err := auth.EncryptSecret([]byte(proxy.URL), ring)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(proxy.URL))
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_proxy_pool_nodes(id,endpoint_key_version,endpoint_nonce,endpoint_ciphertext,endpoint_digest,scheme,display_host,state,session_type) VALUES($1,$2,$3,$4,$5,'http','fixture','healthy','sticky')`, node, keyVersion, nonce, ciphertext, digest[:]); err != nil {
		t.Fatal(err)
	}
	h.targetRoutes = &accountroute.Store{Pool: pool, KeyRing: ring, Manager: manager}
	if err = h.targetRoutes.SeedExisting(ctx, id, node); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_account_route_settings SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	lease, err := h.targetRoutes.Acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := h.targetRoutes.Generation(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := cpacred.BuildCodexCredential(cpacred.DeliveryPayload{AccessToken: "fixture-access", RefreshToken: "fixture-refresh", IDToken: fixtureIDToken(email, "workspace-1"), WorkspaceID: "workspace-1"}, email, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	credential.Name = file.Name
	credential.RouteGeneration = generation.String()
	credential, err = cpacred.WithProxy(credential, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(credential)
	sealed, err := targetdomain.SealMaterial(string(raw), ring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET credential_payload=$2,delivery_revision=$3 WHERE id=$1`, work.ID, sealed, credential.Revision); err != nil {
		t.Fatal(err)
	}
	changed.Store(true)
	if err = lease.Remeasure(ctx); !errors.Is(err, egress.ErrEgressDrift) {
		t.Fatalf("drift=%v", err)
	}
	lease.Release()
	var paused bool
	var actualNode uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT paused,node_id FROM tsw_account_route_bindings WHERE target_account_id=$1`, id).Scan(&paused, &actualNode); err != nil {
		t.Fatal(err)
	}
	if !paused || actualNode != node {
		t.Fatal("drift did not pause the unchanged account binding")
	}
	if err = h.processCPAReauthorization(ctx, work); err == nil {
		t.Fatal("drifted checkpoint accepted")
	}
	if fake.uploads != 0 {
		t.Fatalf("uploads after drift=%d", fake.uploads)
	}
}
