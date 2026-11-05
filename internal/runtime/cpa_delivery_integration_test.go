//go:build integration

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
)

// fakeCPAPort records every remote write so a test can assert exactly what a
// rotation case asked CPA to do.
type fakeCPAPort struct {
	mu       sync.Mutex
	files    map[string]cpacred.File
	calls    []string
	uploaded []byte
	failWith error
}

func newFakeCPAPort(selector, name string) *fakeCPAPort {
	return &fakeCPAPort{files: map[string]cpacred.File{
		selector: {Name: name, AuthIndex: selector, Provider: "codex", Email: "degraded@example.com"},
	}}
}

func (f *fakeCPAPort) List(_ context.Context) ([]cpacred.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cpacred.File, 0, len(f.files))
	for _, file := range f.files {
		out = append(out, file)
	}
	return out, nil
}

func (f *fakeCPAPort) Lookup(_ context.Context, selector string) (cpacred.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[selector]
	if !ok {
		return cpacred.File{}, cpacred.ErrCredentialNotFound
	}
	return file, nil
}

func (f *fakeCPAPort) SetDisabled(_ context.Context, name string, disabled bool) (cpacred.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return cpacred.Receipt{}, f.failWith
	}
	f.calls = append(f.calls, "disable:"+name)
	for selector, file := range f.files {
		if file.Name == name {
			file.Disabled = disabled
			f.files[selector] = file
		}
	}
	return cpacred.Receipt{Operation: "status", Name: name, StatusCode: http.StatusOK}, nil
}

func (f *fakeCPAPort) Upload(_ context.Context, name string, payload []byte) (cpacred.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return cpacred.Receipt{}, f.failWith
	}
	f.calls = append(f.calls, "upload:"+name)
	f.uploaded = append([]byte(nil), payload...)
	f.files[name] = cpacred.File{Name: name, Provider: "codex"}
	return cpacred.Receipt{Operation: "upload", Name: name, StatusCode: http.StatusOK}, nil
}

func (f *fakeCPAPort) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.calls...)
	sort.Strings(out)
	return out
}

func TestCPAAutomaticRotationQuarantinesBeforeRemoval(t *testing.T) {
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	_ = ring
	port := newFakeCPAPort("credential-quarantine", "codex-degraded.json")
	handler.cpaCredentials = port

	eventID := uuid.New()
	response := receiveCPAEvent(t, handler, cpaPayload(eventID, "degraded@example.com", "credential-quarantine"))
	assertCPAResponse(t, response, http.StatusAccepted, "pending_rotation")

	if processed, err := handler.reconcileCPAAutomationOnce(ctx); err != nil || !processed {
		t.Fatalf("evaluate evidence: processed=%v err=%v", processed, err)
	}
	if got := rotationCaseStatus(t, ctx, pool, eventID); got != "quarantining" {
		t.Fatalf("automatic status=%s", got)
	}
	if calls := port.recorded(); len(calls) != 0 {
		t.Fatalf("quarantine was applied before its durable claim: %v", calls)
	}

	// Quarantine requires a durable local claim before any remote write.
	if processed, err := handler.reconcileCPAAutomationOnce(ctx); err != nil || !processed {
		t.Fatalf("claim quarantine: processed=%v err=%v", processed, err)
	}
	if got := rotationCaseStatus(t, ctx, pool, eventID); got != "removal_queued" {
		t.Fatalf("after quarantine status=%s", got)
	}
	if calls := port.recorded(); len(calls) != 1 || calls[0] != "disable:codex-degraded.json" {
		t.Fatalf("quarantine calls=%v", calls)
	}
	if got := rotationCaseStatus(t, ctx, pool, eventID); got != "removal_queued" {
		t.Fatalf("after quarantine status=%s detail=%s", got, rotationCaseDetail(t, ctx, pool, eventID))
	}
	var deliveryStatus string
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT status,attempts FROM tsw_cpa_rotation_deliveries
		WHERE kind='quarantine' AND case_id=(SELECT rotation_case_id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID).Scan(&deliveryStatus, &attempts); err != nil {
		t.Fatal(err)
	}
	if deliveryStatus != "applied" || attempts != 1 {
		t.Fatalf("quarantine receipt status=%s attempts=%d", deliveryStatus, attempts)
	}
}

func TestCPAAutomaticRotationBlocksAfterRemoteFailures(t *testing.T) {
	pool, handler, _, ctx := newAutomaticRotationFixture(t)
	port := newFakeCPAPort("credential-failing", "codex-failing.json")
	port.failWith = errFakeRemoteFailure
	handler.cpaCredentials = port

	eventID := uuid.New()
	receiveCPAEvent(t, handler, cpaPayload(eventID, "degraded@example.com", "credential-failing"))
	if processed, err := handler.reconcileCPAAutomationOnce(ctx); err != nil || !processed {
		t.Fatalf("evaluate evidence: processed=%v err=%v", processed, err)
	}
	for attempt := 1; attempt <= cpaDeliveryMaxAttempts; attempt++ {
		claimed, claimErr := handler.reconcileCPAAutomationOnce(ctx)
		t.Logf("attempt %d claim processed=%v err=%v state=%s", attempt, claimed, claimErr, rotationCaseDetail(t, ctx, pool, eventID))
		if claimErr != nil {
			t.Fatalf("claim attempt %d: err=%v", attempt, claimErr)
		}
		applied, applyErr := handler.reconcileCPAAutomationOnce(ctx)
		t.Logf("attempt %d apply processed=%v err=%v state=%s", attempt, applied, applyErr, rotationCaseDetail(t, ctx, pool, eventID))
		if applyErr != nil {
			t.Fatalf("apply attempt %d: err=%v", attempt, applyErr)
		}
		if _, err := pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now(),updated_at=now()
			WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID); err != nil {
			t.Fatal(err)
		}
	}
	if got := rotationCaseStatus(t, ctx, pool, eventID); got != "blocked" {
		t.Fatalf("after repeated remote failure status=%s", got)
	}
	var lastError string
	if err := pool.QueryRow(ctx, `SELECT last_error_code FROM tsw_cpa_rotation_cases WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if lastError != "cpa_remote_write_failed" {
		t.Fatalf("blocked reason=%s", lastError)
	}
	// No removal operation may exist for a case whose containment failed.
	var operations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_operations WHERE input_snapshot ? 'automation_case_id'`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("failed containment still queued %d operations", operations)
	}
}

var errFakeRemoteFailure = fakeRemoteFailure{}

type fakeRemoteFailure struct{}

func (fakeRemoteFailure) Error() string { return "remote failure" }

func newAutomaticRotationFixture(t *testing.T) (*pgxpool.Pool, *OwnerAuthHandler, cardIntegrationKeyRing, context.Context) {
	t.Helper()
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ids, _, _ := seedCardActivationGraph(t, ctx, pool)
	ring := cardIntegrationKeyRing{}
	setTargetFingerprint(t, ctx, pool, ids.membership, ring, "degraded@example.com")
	seedCPAWorkspaceManageEvidence(t, ctx, pool, uuid.MustParse(ids.membership))
	seedCPAEligibleReplacement(t, ctx, pool, ring, "replacement@example.com")
	origins, err := auth.ParseOriginPolicy("https://owner.test")
	if err != nil {
		t.Fatal(err)
	}
	return pool, &OwnerAuthHandler{pool: pool, keyRing: ring, origins: origins, cpaWebhookSecret: []byte(cpaIntegrationSecret)}, ring, ctx
}

func rotationCaseDetail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventID uuid.UUID) string {
	t.Helper()
	var status, errCode, delivery string
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT rotation.status,COALESCE(rotation.last_error_code,'-'),rotation.attempt_count,
		COALESCE((SELECT kind||':'||status||':'||attempts FROM tsw_cpa_rotation_deliveries d WHERE d.case_id=rotation.id ORDER BY kind LIMIT 1),'-')
		FROM tsw_cpa_rotation_cases rotation JOIN tsw_cpa_degradation_events event ON event.id=rotation.event_id
		WHERE event.event_id=$1`, eventID).Scan(&status, &errCode, &attempts, &delivery); err != nil {
		return "detail-error:" + err.Error()
	}
	return status + " err=" + errCode + " attempts=" + string(rune('0'+attempts%10)) + " delivery=" + delivery
}

func rotationCaseStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventID uuid.UUID) string {
	t.Helper()
	var status string
	if err := pool.QueryRow(ctx, `SELECT rotation.status FROM tsw_cpa_rotation_cases rotation
		JOIN tsw_cpa_degradation_events event ON event.id=rotation.event_id WHERE event.event_id=$1`, eventID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// TestCPAAutomaticRotationCompletesDelivery runs the full automatic chain:
// quarantine in CPA, verified removal, seat replacement, join, and registration
// of the new credential back into CPA. Completion is only reachable through an
// observed remote write receipt.
func TestCPAAutomaticRotationCompletesDelivery(t *testing.T) {
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	port := newFakeCPAPort("credential-chain", "codex-chain.json")
	handler.cpaCredentials = port

	var currentWorkspace, currentMother uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT workspace_id,mother_account_id FROM tsw_mother_workspace_bindings WHERE ended_at IS NULL LIMIT 1`).Scan(&currentWorkspace, &currentMother); err != nil {
		t.Fatal(err)
	}
	seedAdoptionRoster(t, ctx, pool, ring, currentWorkspace, currentMother, "current-cpa@example.com", "member", "current-cpa-member")
	currentFile := port.files["credential-chain"]
	currentFile.Email = "current-cpa@example.com"
	port.files["credential-chain"] = currentFile
	if _, err := pool.Exec(ctx, `DELETE FROM tsw_standby_child_memberships WHERE target_account_id IN (SELECT id FROM tsw_target_accounts WHERE identifier='replacement@example.com')`); err != nil {
		t.Fatal(err)
	}
	eventID := uuid.New()
	receiveCPAEvent(t, handler, cpaPayload(eventID, "current-cpa@example.com", "credential-chain"))
	if processed, err := handler.reconcileCPAAutomationOnce(ctx); err != nil || !processed {
		t.Fatalf("evaluate evidence: processed=%v err=%v", processed, err)
	}
	if got := rotationCaseStatus(t, ctx, pool, eventID); got != "quarantining" {
		t.Fatalf("automatic status=%s", got)
	}

	// Every later stage is automatic.
	step := func(want string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now()
			WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID); err != nil {
			t.Fatal(err)
		}
		if _, err := handler.reconcileCPAAutomationOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if got := rotationCaseStatus(t, ctx, pool, eventID); got != want {
			t.Fatalf("status=%s want %s detail=%s", got, want, rotationCaseDetail(t, ctx, pool, eventID))
		}
	}

	step("removal_queued")
	if calls := port.recorded(); len(calls) != 1 || calls[0] != "disable:codex-chain.json" {
		t.Fatalf("quarantine calls=%v", calls)
	}

	var caseID, removalOperation uuid.UUID
	var replacementAccount, replacementBatch, sourceMembership uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT rotation.id,rotation.removal_operation_id,rotation.replacement_account_id,
		rotation.replacement_batch_id,rotation.membership_id FROM tsw_cpa_rotation_cases rotation
		JOIN tsw_cpa_degradation_events event ON event.id=rotation.event_id WHERE event.event_id=$1`, eventID).
		Scan(&caseID, &removalOperation, &replacementAccount, &replacementBatch, &sourceMembership); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_batch_memberships SET state='removed',removed_at=now() WHERE id=$1`, sourceMembership); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_operations SET status='succeeded',completed_at=now() WHERE id=$1`, removalOperation); err != nil {
		t.Fatal(err)
	}
	step("removal_verified")
	step("replacement_queued")

	var replacementOperation uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT replacement_operation_id,replacement_batch_id FROM tsw_cpa_rotation_cases WHERE id=$1`, caseID).Scan(&replacementOperation, &replacementBatch); err != nil {
		t.Fatal(err)
	}
	// The join worker confirms the invitation and hands over to the login stage.
	if _, err := pool.Exec(ctx, `UPDATE tsw_operation_targets SET invitation_confirmed_at=now() WHERE operation_id=$1`, replacementOperation); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_operations SET status='awaiting_login',completed_at=NULL WHERE id=$1`, replacementOperation); err != nil {
		t.Fatal(err)
	}
	step("replacement_running")

	// The login worker joins the seat and publishes one credential version.
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at,platform_member_id,seat_type)
		SELECT gen_random_uuid(),$1,$2,operation_target.id,now(),'replacement-member','prolite'
		FROM tsw_operation_targets operation_target WHERE operation_target.operation_id=$3 LIMIT 1`, replacementBatch, replacementAccount, replacementOperation); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"access_token":"access-chain","refresh_token":"refresh-chain","id_token":"` + fixtureIDToken("replacement@example.com", "workspace-card") + `","expires_in":3600,"workspace_id":"workspace-card","platform_subject_id":"acct-chain"}`)
	var replacementMembership uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tsw_batch_memberships WHERE batch_id=$1 AND target_account_id=$2`, replacementBatch, replacementAccount).Scan(&replacementMembership); err != nil {
		t.Fatal(err)
	}
	var asset, version uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tsw_oauth_assets(membership_id,status,current_generation,platform_subject_id)
		VALUES($1,'ready',1,'acct-chain') RETURNING id`, replacementMembership).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	var workspace uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT workspace_id FROM tsw_cpa_rotation_cases WHERE id=$1`, caseID).Scan(&workspace); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	if err := pool.QueryRow(ctx, `INSERT INTO tsw_delivery_versions(oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id)
		VALUES($1,1,$2,$3,'acct-chain',$4) RETURNING id`, asset, payload, hash[:], workspace).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_assets SET current_delivery_version_id=$2 WHERE id=$1`, asset, version); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_operations SET status='succeeded',completed_at=now() WHERE id=$1`, replacementOperation); err != nil {
		t.Fatal(err)
	}

	// One proxy assignment is encrypted with the published OAuth version.
	// Upload retries must retain this same assignment and credential material.
	assignments := 0
	handler.cpaProxyAssignment = func(_ context.Context, _ uuid.UUID, source cpacred.Credential) (cpacred.Credential, error) {
		assignments++
		return cpacred.WithProxy(source, "socks5://127.0.0.1:19080")
	}

	// A published version cannot complete the case while CPA rejects registration.
	port.failWith = errFakeRemoteFailure
	step("delivering")
	if calls := port.recorded(); len(calls) != 1 {
		t.Fatalf("delivery happened before it was claimed: %v", calls)
	}
	port.failWith = nil
	step("completed")
	calls := port.recorded()
	if len(calls) != 2 || !strings.HasPrefix(calls[1], "upload:codex-") {
		t.Fatalf("delivery calls=%v", calls)
	}
	var deliveryStatus string
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT status,attempts FROM tsw_cpa_rotation_deliveries WHERE case_id=$1 AND kind='delivery'`, caseID).
		Scan(&deliveryStatus, &attempts); err != nil {
		t.Fatal(err)
	}
	if deliveryStatus != "applied" {
		t.Fatalf("delivery receipt status=%s", deliveryStatus)
	}
	if attempts != 2 {
		t.Fatalf("delivery attempts=%d want 2", attempts)
	}
	if assignments != 1 {
		t.Fatalf("proxy assignments=%d want 1 across upload retries", assignments)
	}
	if !bytes.Contains(port.uploaded, []byte(`"proxy_url":"socks5://127.0.0.1:19080"`)) {
		t.Fatal("CPA did not receive assigned proxy")
	}
	var ciphertext []byte
	if err := pool.QueryRow(ctx, `SELECT credential_payload FROM tsw_cpa_rotation_deliveries WHERE case_id=$1 AND kind='delivery'`, caseID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte("refresh-chain")) {
		t.Fatal("OAuth checkpoint is absent or unsealed")
	}
	// A completion resets the circuit so one success clears prior failures.
	var failures int
	if err := pool.QueryRow(ctx, `SELECT failure_count FROM tsw_cpa_automation_settings WHERE singleton`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 0 {
		t.Fatalf("failure count after completion=%d", failures)
	}
	_ = ring
}

func fixtureIDToken(email, account string) string {
	claims := `{"email":"` + email + `","https://api.openai.com/auth":{"chatgpt_account_id":"` + account + `"}}`
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
}
