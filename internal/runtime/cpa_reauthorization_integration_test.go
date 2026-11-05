//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
)

type reauthCredentialFake struct {
	files    map[string]cpacred.File
	fail     bool
	uploaded []byte
	uploads  int
}

func (f *reauthCredentialFake) List(context.Context) ([]cpacred.File, error) {
	out := make([]cpacred.File, 0, len(f.files))
	for _, v := range f.files {
		out = append(out, v)
	}
	return out, nil
}
func (f *reauthCredentialFake) Lookup(_ context.Context, name string) (cpacred.File, error) {
	return f.files[name], nil
}
func (*reauthCredentialFake) SetDisabled(context.Context, string, bool) (cpacred.Receipt, error) {
	return cpacred.Receipt{}, nil
}
func (f *reauthCredentialFake) Upload(_ context.Context, name string, raw []byte) (cpacred.Receipt, error) {
	f.uploads++
	if f.fail {
		return cpacred.Receipt{}, errors.New("upload unavailable")
	}
	var meta struct {
		Revision string `json:"credential_revision"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return cpacred.Receipt{}, err
	}
	f.uploaded = append([]byte(nil), raw...)
	file := f.files[name]
	file.Revision = meta.Revision
	file.StatusMessage = ""
	file.StatusCode = 0
	f.files[name] = file
	return cpacred.Receipt{StatusCode: 200, VerifiedAt: time.Now()}, nil
}
func (f *reauthCredentialFake) CredentialIdentity(_ context.Context, name string) (cpacred.File, error) {
	return f.files[name], nil
}

func TestCPAReauthorizationEnqueuesOnlyMatching401Credential(t *testing.T) {
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	defer pool.Close()
	account := uuid.New()
	_, version, fingerprint, err := identity.Fingerprint(ring, identity.TargetLogin, "reauth@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,$4,$2)`, account, "reauth@example.test", fingerprint[:], version); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_credentials(target_account_id,password_secret,totp_secret,material_status,materials_sealed) VALUES($1,'sealed-password','sealed-totp','complete',true)`, account); err != nil {
		t.Fatal(err)
	}
	files := []cpacred.File{
		{Name: "reauth.json", Email: "reauth@example.test", Provider: "codex", StatusMessage: "upstream HTTP 401 unauthorized", Revision: "r1", AccountID: "workspace-1"},
		{Name: "foreign-provider.json", Email: "reauth@example.test", Provider: "antigravity", StatusCode: 401},
		{Name: "unimported.json", Email: "absent@example.test", Provider: "codex", StatusCode: 401},
		{Name: "rate.json", Email: "reauth@example.test", Provider: "codex", StatusMessage: "HTTP 429", Revision: "r2"},
		{Name: "disabled.json", Email: "reauth@example.test", Provider: "codex", Disabled: true, StatusMessage: "HTTP 401", Revision: "r3"},
	}
	handler.cpaCredentials = &reauthCredentialFake{files: map[string]cpacred.File{"reauth.json": files[0], "rate.json": files[3], "disabled.json": files[4]}}
	if err = handler.enqueueCPAReauthorizations(ctx, files); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_reauthorizations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("reauthorization rows=%d want 1", count)
	}
	var status, target string
	if err = pool.QueryRow(ctx, `SELECT status,target_account_id::text FROM tsw_cpa_reauthorizations WHERE credential_name='reauth.json'`).Scan(&status, &target); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || target != account.String() {
		t.Fatalf("status=%s target=%s", status, target)
	}
}

func TestCPAReauthorizationLeaseIsExclusiveAndStaleFinishCannotCommit(t *testing.T) {
	pool, handler, _, ctx := newAutomaticRotationFixture(t)
	defer pool.Close()
	id := uuid.New()
	target := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,decode(repeat('11',32),'hex'),1,$2)`, target, "lease@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_cpa_reauthorizations(id,credential_id,credential_name,remote_revision,workspace_id,target_account_id,source_secret_revision) VALUES($1,'lease.json','lease.json','r1','workspace-1',$2,1)`, id, target); err != nil {
		t.Fatal(err)
	}
	first, ok, err := handler.claimCPAReauthorization(ctx)
	if err != nil || !ok {
		t.Fatalf("first claim ok=%v err=%v", ok, err)
	}
	if _, ok, err = handler.claimCPAReauthorization(ctx); err != nil || ok {
		t.Fatalf("second claim ok=%v err=%v", ok, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET lease_owner=$2 WHERE id=$1`, id, uuid.New()); err != nil {
		t.Fatal(err)
	}
	handler.finishCPAReauthorization(context.Background(), first, nil)
	var status string
	if err = pool.QueryRow(ctx, `SELECT status FROM tsw_cpa_reauthorizations WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("stale finish changed status to %s", status)
	}
}

func TestCPAReauthorizationRetriesSealedGrantAndAllowsLaterRenewal(t *testing.T) {
	pool, h, ring, ctx := newAutomaticRotationFixture(t)
	id := uuid.New()
	email := "renewal@example.test"
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
	file := cpacred.File{Name: "renewal.json", Provider: "codex", Email: email, AccountID: "workspace-1", Revision: "old-material", StatusCode: 401}
	fake := &reauthCredentialFake{files: map[string]cpacred.File{file.Name: file}, fail: true}
	h.cpaCredentials = fake
	grants := 0
	h.cpaOAuthIssuer = func(_ context.Context, target uuid.UUID, workspace, email, name string) (cpacred.Credential, error) {
		grants++
		if target != id || workspace != "workspace-1" {
			t.Fatal("wrong renewal account")
		}
		credential, err := cpacred.BuildCodexCredential(cpacred.DeliveryPayload{AccessToken: "access-renewal-fixture", RefreshToken: "refresh-renewal-fixture", IDToken: fixtureIDToken(email, workspace), WorkspaceID: workspace}, email, time.Now())
		credential.Name = name
		return credential, err
	}
	var operationsBefore int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_operations`).Scan(&operationsBefore); err != nil {
		t.Fatal(err)
	}
	if err = h.enqueueCPAReauthorizations(ctx, []cpacred.File{file}); err != nil {
		t.Fatal(err)
	}
	// The CPA cooldown label can clear while the durable 401 observation waits.
	observed := fake.files[file.Name]
	observed.StatusCode = 0
	fake.files[file.Name] = observed
	first, ok, err := h.claimCPAReauthorization(ctx)
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	err = h.processCPAReauthorization(ctx, first)
	if err == nil {
		t.Fatal("upload failure incorrectly succeeded")
	}
	h.finishCPAReauthorization(ctx, first, err)
	var sealed []byte
	if err = pool.QueryRow(ctx, `SELECT credential_payload FROM tsw_cpa_reauthorizations WHERE id=$1`, first.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte("refresh-renewal-fixture")) {
		t.Fatal("OAuth checkpoint not encrypted")
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET next_attempt_at=now() WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	second, ok, err := h.claimCPAReauthorization(ctx)
	if err != nil || !ok {
		t.Fatalf("retry claim: %v %v", ok, err)
	}
	fake.fail = false
	if err = h.processCPAReauthorization(ctx, second); err != nil {
		t.Fatal(err)
	}
	h.finishCPAReauthorization(ctx, second, nil)
	if grants != 1 || fake.uploads != 2 {
		t.Fatalf("grants=%d uploads=%d", grants, fake.uploads)
	}
	var status string
	var operationsAfter int
	if err = pool.QueryRow(ctx, `SELECT status FROM tsw_cpa_reauthorizations WHERE id=$1`, first.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatalf("status=%s", status)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_operations`).Scan(&operationsAfter); err != nil {
		t.Fatal(err)
	}
	if operationsAfter != operationsBefore {
		t.Fatal("401 renewal created a member operation")
	}
	// A different expired credential version on the same account is a new cycle.
	if _, err = pool.Exec(ctx, `UPDATE tsw_cpa_reauthorizations SET completed_at=now()-interval '11 minutes' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	renewed := fake.files[file.Name]
	renewed.StatusCode = 401
	fake.files[file.Name] = renewed
	if err = h.enqueueCPAReauthorizations(ctx, []cpacred.File{renewed}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_reauthorizations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("renewal cycles=%d", count)
	}
}
