//go:build integration

package accountsession

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"os"
	"testing"
	"time"
)

type integrationKeyRing struct{ key [32]byte }

func (r integrationKeyRing) Current() (uint16, [32]byte)      { return 1, r.key }
func (r integrationKeyRing) Lookup(v uint16) ([32]byte, bool) { return r.key, v == 1 }

type refreshStub struct {
	called   bool
	sawRoute bool
}

func (r *refreshStub) RefreshPersonal(ctx context.Context, material platform.MotherMaterial) (platform.PersonalRefreshResult, error) {
	r.called = true
	_, r.sawRoute = ctx.Value(routeProviderStub{}).(string)
	return platform.PersonalRefreshResult{Status: "ready", Session: testSession("fresh")}, nil
}

func testSession(token string) platform.PersonalSession {
	return platform.PersonalSession{AccessToken: token, DeviceID: "device", ExpiresAt: time.Now().Add(time.Hour), Cookies: []platform.SessionCookie{{Name: "__Secure-next-auth.session-token.0", Value: "cookie", Host: "chatgpt.com"}}}
}

func TestEnsureIntegrationForceFreshAndValidateFence(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required for accountsession route integration")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ring := integrationKeyRing{key: [32]byte{7}}
	id := uuid.New()
	password, err := target.SealMaterial("password", ring)
	if err != nil {
		t.Fatal(err)
	}
	totp, err := target.SealMaterial("JBSWY3DPEHPK3PXP", ring)
	if err != nil {
		t.Fatal(err)
	}
	hmac := sha256.Sum256(id[:])
	if _, err = pool.Exec(context.Background(), `INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,1,$4)`, id, "route-test-"+id.String(), hmac[:], "route-test"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tsw_target_personal_sessions WHERE target_account_id=$1`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tsw_target_personal_access WHERE target_account_id=$1`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tsw_target_credentials WHERE target_account_id=$1`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tsw_target_accounts WHERE id=$1`, id)
	}()
	if _, err = pool.Exec(context.Background(), `INSERT INTO tsw_target_credentials(target_account_id,password_secret,totp_secret,secret_revision,material_status,materials_sealed) VALUES($1,$2,$3,1,'complete',true)`, id, password, totp); err != nil {
		t.Fatal(err)
	}
	old := testSession("old")
	version, nonce, sealed, err := Seal("target", ring, id, 1, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(context.Background(), `INSERT INTO tsw_target_personal_access(target_account_id,secret_revision,attempt,status) VALUES($1,1,1,'ready')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(context.Background(), `INSERT INTO tsw_target_personal_sessions(target_account_id,secret_revision,attempt,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,1,1,$2,$3,$4,$5,$6)`, id, uuid.New(), version, nonce, sealed, old.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	provider := &routeProviderStub{}
	refresher := &refreshStub{}
	store := Store{Pool: pool, KeyRing: ring, Routes: provider}
	result, err := store.Ensure(context.Background(), id, refresher, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !refresher.called || !refresher.sawRoute || result.Session.AccessToken != "fresh" {
		t.Fatalf("force fresh did not bypass old session: called=%v route=%v token=%q", refresher.called, refresher.sawRoute, result.Session.AccessToken)
	}

	provider = &routeProviderStub{}
	store.Routes = rejectingRouteProvider{routeProviderStub: provider}
	refresher = &refreshStub{}
	if _, err = store.Ensure(context.Background(), id, refresher, true, nil); err == nil {
		t.Fatal("Validate failure unexpectedly published")
	}
	var status string
	if err = pool.QueryRow(context.Background(), `SELECT status FROM tsw_target_personal_access WHERE target_account_id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "ready" && !provider.validated {
		t.Fatal("validation fence was not reached")
	}
}

type rejectingRouteProvider struct{ *routeProviderStub }

func (rejectingRouteProvider) Validate(context.Context, uuid.UUID) error {
	return errors.New("route validation failed")
}
