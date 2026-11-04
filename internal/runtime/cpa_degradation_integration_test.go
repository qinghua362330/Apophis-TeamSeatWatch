//go:build integration

package runtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpaevent"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

const cpaIntegrationSecret = "0123456789abcdef0123456789abcdef"

type cpaDatabaseSnapshot struct {
	tasks, operations int
	membershipState   string
}

func TestCPADegradationIntegrationIsIdempotentAndNonDestructive(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
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
	defer pool.Close()

	ids, sessionToken, csrfToken := seedCardActivationGraph(t, ctx, pool)
	ring := cardIntegrationKeyRing{}
	setTargetFingerprint(t, ctx, pool, ids.membership, ring, "user@example.com")
	origins, err := auth.ParseOriginPolicy("https://owner.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := &OwnerAuthHandler{
		pool:             pool,
		keyRing:          ring,
		origins:          origins,
		cpaWebhookSecret: []byte(cpaIntegrationSecret),
	}

	uniqueID := uuid.New()
	unique := cpaPayload(uniqueID, "user@example.com", "credential-unique")
	before := cpaSnapshot(t, ctx, pool, ids.membership)
	first := receiveCPAEvent(t, handler, unique)
	assertCPAResponse(t, first, http.StatusAccepted, "pending_rotation")
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)
	processed, err := handler.reconcileCPAAutomationOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("reconcile without replacement: processed=%v err=%v", processed, err)
	}
	var caseStatus, caseError string
	if err = pool.QueryRow(ctx, `SELECT status,last_error_code FROM tsw_cpa_rotation_cases WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, uniqueID).Scan(&caseStatus, &caseError); err != nil {
		t.Fatal(err)
	}
	if caseStatus != "waiting_evidence" || caseError != "cpa_management_unconfigured" {
		t.Fatalf("case without verified evidence status=%s error=%s", caseStatus, caseError)
	}
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)

	retry := receiveCPAEvent(t, handler, unique)
	assertCPAResponse(t, retry, http.StatusOK, "pending_rotation")
	var uniqueRows int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_degradation_events WHERE event_id=$1`, uniqueID).Scan(&uniqueRows); err != nil {
		t.Fatal(err)
	}
	if uniqueRows != 1 {
		t.Fatalf("idempotent event rows=%d want 1", uniqueRows)
	}

	conflicting := unique
	conflicting.DetectedModel = "gpt-6-sol"
	conflict := receiveCPAEvent(t, handler, conflicting)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflicting event status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	notFoundID := uuid.New()
	notFound := cpaPayload(notFoundID, "later@example.com", "credential-later")
	before = cpaSnapshot(t, ctx, pool, ids.membership)
	missing := receiveCPAEvent(t, handler, notFound)
	assertCPAResponse(t, missing, http.StatusAccepted, "not_found")
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)

	setTargetFingerprint(t, ctx, pool, ids.membership, ring, "later@example.com")
	before = cpaSnapshot(t, ctx, pool, ids.membership)
	remapped := ownerCPARequest(t, http.MethodPost, "/api/owner/v1/cpa/degradation-events/"+notFoundID.String()+"/retry-map", sessionToken, csrfToken)
	handler.RetryMapCPADegradationEvent(remapped, remapped.Result().Request, openapi_types.UUID(eventRowID(t, ctx, pool, notFoundID)), ownerapi.RetryMapCPADegradationEventParams{})
	assertCPAResponse(t, remapped, http.StatusOK, "pending_rotation")
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)

	before = cpaSnapshot(t, ctx, pool, ids.membership)
	dismissed := ownerCPARequest(t, http.MethodPost, "/api/owner/v1/cpa/degradation-events/"+uniqueID.String()+"/dismiss", sessionToken, csrfToken)
	handler.DismissCPADegradationEvent(dismissed, dismissed.Result().Request, openapi_types.UUID(eventRowID(t, ctx, pool, uniqueID)), ownerapi.DismissCPADegradationEventParams{})
	assertCPAResponse(t, dismissed, http.StatusOK, "dismissed")
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)
	var dismissedCases int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_rotation_cases WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1) AND status='dismissed' AND replacement_account_id IS NULL AND replacement_standby_batch_id IS NULL`, uniqueID).Scan(&dismissedCases); err != nil {
		t.Fatal(err)
	}
	if dismissedCases != 1 {
		t.Fatalf("dismissed automation cases=%d want 1", dismissedCases)
	}
	var linkedDismissed int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_degradation_events WHERE event_id IN ($1,$2) AND mapping_status='dismissed' AND rotation_case_id IS NULL`, uniqueID, notFoundID).Scan(&linkedDismissed); err != nil {
		t.Fatal(err)
	}
	if linkedDismissed != 2 {
		t.Fatalf("linked dismissed events=%d want 2", linkedDismissed)
	}

	startedMembership := seedIndependentActiveMembership(t, ctx, pool, ids.membership, ring, "started@example.com")
	startedEventID := uuid.New()
	startedEvent := receiveCPAEvent(t, handler, cpaPayload(startedEventID, "started@example.com", "credential-started"))
	assertCPAResponse(t, startedEvent, http.StatusAccepted, "pending_rotation")
	var startedCase uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT rotation_case_id FROM tsw_cpa_degradation_events WHERE event_id=$1`, startedEventID).Scan(&startedCase); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='removal_queued',started_at=now() WHERE id=$1`, startedCase); err != nil {
		t.Fatal(err)
	}
	startedDismiss := ownerCPARequest(t, http.MethodPost, "/api/owner/v1/cpa/degradation-events/"+startedEventID.String()+"/dismiss", sessionToken, csrfToken)
	handler.DismissCPADegradationEvent(startedDismiss, startedDismiss.Result().Request, openapi_types.UUID(eventRowID(t, ctx, pool, startedEventID)), ownerapi.DismissCPADegradationEventParams{})
	if startedDismiss.Code != http.StatusConflict {
		t.Fatalf("started rotation dismiss status=%d body=%s", startedDismiss.Code, startedDismiss.Body.String())
	}
	var retainedStatus, retainedCaseStatus string
	if err = pool.QueryRow(ctx, `SELECT event.mapping_status,rotation.status FROM tsw_cpa_degradation_events event JOIN tsw_cpa_rotation_cases rotation ON rotation.id=event.rotation_case_id WHERE event.event_id=$1`, startedEventID).Scan(&retainedStatus, &retainedCaseStatus); err != nil {
		t.Fatal(err)
	}
	if retainedStatus != "pending_rotation" || retainedCaseStatus != "removal_queued" {
		t.Fatalf("started rotation changed after dismiss: event=%s case=%s", retainedStatus, retainedCaseStatus)
	}
	if state := membershipState(t, ctx, pool, startedMembership); state != "active" {
		t.Fatalf("started membership state=%s want active", state)
	}

	secondMembership := seedSecondActiveMembership(t, ctx, pool, ids.membership)
	before = cpaSnapshot(t, ctx, pool, ids.membership)
	ambiguous := receiveCPAEvent(t, handler, cpaPayload(uuid.New(), "later@example.com", "credential-ambiguous"))
	assertCPAResponse(t, ambiguous, http.StatusAccepted, "ambiguous")
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)
	if state := membershipState(t, ctx, pool, secondMembership); state != "active" {
		t.Fatalf("second membership state=%s want active", state)
	}
}

func TestCPAAutomaticRotationQueuesOneExactRemoval(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
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
	defer pool.Close()

	ids, _, _ := seedCardActivationGraph(t, ctx, pool)
	ring := cardIntegrationKeyRing{}
	setTargetFingerprint(t, ctx, pool, ids.membership, ring, "degraded@example.com")
	otherMembership := seedIndependentActiveMembership(t, ctx, pool, ids.membership, ring, "healthy@example.com")
	seedCPAWorkspaceManageEvidence(t, ctx, pool, uuid.MustParse(ids.membership))
	replacementAccount, standbyBatch := seedCPAEligibleReplacement(t, ctx, pool, ring, "replacement@example.com")

	origins, err := auth.ParseOriginPolicy("https://owner.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := &OwnerAuthHandler{pool: pool, keyRing: ring, origins: origins, cpaWebhookSecret: []byte(cpaIntegrationSecret)}
	handler.cpaCredentials = newFakeCPAPort("credential-exact-remove", "codex-degraded.json")
	eventID := uuid.New()
	response := receiveCPAEvent(t, handler, cpaPayload(eventID, "degraded@example.com", "credential-exact-remove"))
	assertCPAResponse(t, response, http.StatusAccepted, "pending_rotation")

	processed, err := handler.reconcileCPAAutomationOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("evaluate evidence: processed=%v err=%v", processed, err)
	}
	var quarantineStatus, quarantineError string
	if err = pool.QueryRow(ctx, `SELECT status,COALESCE(last_error_code,'') FROM tsw_cpa_rotation_cases WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID).Scan(&quarantineStatus, &quarantineError); err != nil {
		t.Fatal(err)
	}
	if quarantineStatus != "quarantining" {
		t.Fatalf("automatic case status=%s error=%s", quarantineStatus, quarantineError)
	}
	processed, err = handler.reconcileCPAAutomationOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("queue exact removal: processed=%v err=%v", processed, err)
	}

	var caseID, removalOperation, reservedAccount, reservedStandby uuid.UUID
	var caseStatus string
	if err = pool.QueryRow(ctx, `SELECT id,status,removal_operation_id,replacement_account_id,replacement_standby_batch_id
		FROM tsw_cpa_rotation_cases WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID).
		Scan(&caseID, &caseStatus, &removalOperation, &reservedAccount, &reservedStandby); err != nil {
		t.Fatal(err)
	}
	if caseStatus != "removal_queued" || reservedAccount != replacementAccount || reservedStandby != standbyBatch {
		t.Fatalf("rotation reservation status=%s account=%s standby=%s", caseStatus, reservedAccount, reservedStandby)
	}

	var operations, targets, tasks, wrongTargets int
	if err = pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM tsw_operations WHERE id=$1 AND operation_type='remove'),
		(SELECT count(*) FROM tsw_operation_targets WHERE operation_id=$1),
		(SELECT count(*) FROM tsw_tasks task JOIN tsw_operation_targets target ON target.id=task.operation_target_id WHERE target.operation_id=$1 AND task.task_type='remove'),
		(SELECT count(*) FROM tsw_operation_targets WHERE operation_id=$1 AND membership_id<>$2)`, removalOperation, ids.membership).
		Scan(&operations, &targets, &tasks, &wrongTargets); err != nil {
		t.Fatal(err)
	}
	if operations != 1 || targets != 1 || tasks != 1 || wrongTargets != 0 {
		t.Fatalf("exact removal counts operations=%d targets=%d tasks=%d wrong_targets=%d", operations, targets, tasks, wrongTargets)
	}
	if state := membershipState(t, ctx, pool, otherMembership); state != "active" {
		t.Fatalf("healthy membership state=%s want active", state)
	}

	if _, err = pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now() WHERE id=$1`, caseID); err != nil {
		t.Fatal(err)
	}
	processed, err = handler.reconcileCPAAutomationOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("observe queued removal: processed=%v err=%v", processed, err)
	}
	if err = pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM tsw_operations WHERE id=$1),
		(SELECT count(*) FROM tsw_operation_targets WHERE operation_id=$1),
		(SELECT count(*) FROM tsw_tasks task JOIN tsw_operation_targets target ON target.id=task.operation_target_id WHERE target.operation_id=$1)`, removalOperation).
		Scan(&operations, &targets, &tasks); err != nil {
		t.Fatal(err)
	}
	if operations != 1 || targets != 1 || tasks != 1 {
		t.Fatalf("reconcile duplicated removal operations=%d targets=%d tasks=%d", operations, targets, tasks)
	}

	// These fixtures exercise orchestration after worker receipts, not live Team writes.
	advance := func(want string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now() WHERE id=$1`, caseID); err != nil {
			t.Fatal(err)
		}
		if processed, err := handler.reconcileCPAAutomationOnce(ctx); err != nil || !processed {
			t.Fatalf("advance to %s: processed=%v err=%v", want, processed, err)
		}
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM tsw_cpa_rotation_cases WHERE id=$1`, caseID).Scan(&status); err != nil || status != want {
			t.Fatalf("rotation status=%s want %s err=%v", status, want, err)
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_batch_memberships SET state='removed',removed_at=now() WHERE id=$1`, ids.membership); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_operations SET status='succeeded',completed_at=now() WHERE id=$1`, removalOperation); err != nil {
		t.Fatal(err)
	}
	advance("removal_verified")
	advance("replacement_queued")
	var replacementOperation uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT replacement_operation_id FROM tsw_cpa_rotation_cases WHERE id=$1`, caseID).Scan(&replacementOperation); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_tasks SET status='succeeded',finished_at=now() WHERE operation_target_id IN (SELECT id FROM tsw_operation_targets WHERE operation_id=$1)`, replacementOperation); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_operation_targets SET invitation_confirmed_at=now() WHERE operation_id=$1`, replacementOperation); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_operations SET status='awaiting_login',completed_at=NULL WHERE id=$1`, replacementOperation); err != nil {
		t.Fatal(err)
	}
	advance("replacement_running")
	var loginTasks int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_tasks WHERE dedupe_key LIKE 'workspace-oauth:%' AND operation_target_id IN (SELECT id FROM tsw_operation_targets WHERE operation_id=$1)`, replacementOperation).Scan(&loginTasks); err != nil || loginTasks != 1 {
		t.Fatalf("login tasks=%d want 1 err=%v", loginTasks, err)
	}
	advance("replacement_running")
	if _, err = pool.Exec(ctx, `UPDATE tsw_operations SET status='succeeded',completed_at=now() WHERE id=$1`, replacementOperation); err != nil {
		t.Fatal(err)
	}
	advance("credentials_pending")
	if state := membershipState(t, ctx, pool, otherMembership); state != "active" {
		t.Fatalf("healthy membership changed during replacement: %s", state)
	}
}

func cpaPayload(eventID uuid.UUID, email, credentialID string) cpaevent.Payload {
	return cpaevent.Payload{
		EventID: eventID, CredentialID: credentialID, CredentialRevision: "revision-1",
		Email: email, ExpectedModel: "gpt-6.1-sol", DetectedModel: "gpt-6-luna",
		Confidence: 0.97, ObservedAt: time.Now().UTC().Truncate(time.Second), Status: "quarantined",
	}
}

func receiveCPAEvent(t *testing.T, handler *OwnerAuthHandler, payload cpaevent.Payload) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(cpaIntegrationSecret))
	_, _ = mac.Write([]byte(timestamp + "\n"))
	_, _ = mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/cpa/degradation-events", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CPA-Event-ID", payload.EventID.String())
	request.Header.Set("X-CPA-Timestamp", timestamp)
	request.Header.Set("X-CPA-Signature", hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	handler.receiveCPADegradationEvent(response, request)
	return response
}

func ownerCPARequest(t *testing.T, method, path, sessionToken, csrfToken string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
	request.Header.Set(auth.CSRFHeaderName, csrfToken)
	request.Header.Set("Origin", "https://owner.test")
	request.Header.Set("User-Agent", "integration")
	response := httptest.NewRecorder()
	response.Result().Request = request
	return response
}

func assertCPAResponse(t *testing.T, response *httptest.ResponseRecorder, status int, mappingStatus string) ownerapi.CPADegradationEvent {
	t.Helper()
	if response.Code != status {
		t.Fatalf("event status=%d want %d body=%s", response.Code, status, response.Body.String())
	}
	var event ownerapi.CPADegradationEvent
	if err := json.Unmarshal(response.Body.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if string(event.MappingStatus) != mappingStatus {
		t.Fatalf("mapping status=%s want %s", event.MappingStatus, mappingStatus)
	}
	return event
}

func setTargetFingerprint(t *testing.T, ctx context.Context, pool *pgxpool.Pool, membership string, ring cardIntegrationKeyRing, email string) {
	t.Helper()
	normalized, version, fingerprint, err := identity.Fingerprint(ring, identity.TargetLogin, email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE tsw_target_accounts SET identifier=$2,identifier_hmac=$3,identifier_key_version=$4 WHERE id=(SELECT target_account_id FROM tsw_batch_memberships WHERE id=$1)`, membership, normalized, fingerprint[:], version); err != nil {
		t.Fatal(err)
	}
}

func eventRowID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1`, eventID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func cpaSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, membership string) cpaDatabaseSnapshot {
	t.Helper()
	var snapshot cpaDatabaseSnapshot
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM tsw_tasks),(SELECT count(*) FROM tsw_operations),(SELECT state FROM tsw_batch_memberships WHERE id=$1)`, membership).Scan(&snapshot.tasks, &snapshot.operations, &snapshot.membershipState); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertCPANonDestructive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, membership string, before cpaDatabaseSnapshot) {
	t.Helper()
	after := cpaSnapshot(t, ctx, pool, membership)
	if after != before {
		t.Fatalf("event changed operational state: before=%+v after=%+v", before, after)
	}
}

func membershipState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, membership uuid.UUID) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM tsw_batch_memberships WHERE id=$1`, membership).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func seedSecondActiveMembership(t *testing.T, ctx context.Context, pool *pgxpool.Pool, originalMembership string) uuid.UUID {
	t.Helper()
	workspace, binding, batch, operation, operationTarget, membership := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var owner, mother, target uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT operation.owner_id,binding.mother_account_id,membership.target_account_id
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_operation_targets operation_target ON operation_target.id=membership.join_operation_target_id
		JOIN tsw_operations operation ON operation.id=operation_target.operation_id
		WHERE membership.id=$1`, originalMembership).Scan(&owner, &mother, &target); err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES($1,$2,'ambiguous workspace')`, []any{workspace, "workspace-" + workspace.String()}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES($1,$2,$3)`, []any{binding, mother, workspace}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at) VALUES($1,$2,2,'serving',now()+interval '1 day')`, []any{batch, binding}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,status,completed_at,correlation_id) VALUES($1,$2,$3,$4,'join',$5,decode(repeat('55',32),'hex'),'{}','succeeded',now(),'cpa-event-fixture')`, []any{operation, owner, workspace, batch, "cpa-ambiguous-" + operation.String()}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal) VALUES($1,$2,$3,1)`, []any{operationTarget, operation, target}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at) VALUES($1,$2,$3,$4,now())`, []any{membership, batch, target, operationTarget}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',completed_at=now() WHERE id=$1`, []any{operationTarget, membership}},
	}
	for _, item := range queries {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	return membership
}

func seedIndependentActiveMembership(t *testing.T, ctx context.Context, pool *pgxpool.Pool, originalMembership string, ring cardIntegrationKeyRing, email string) uuid.UUID {
	t.Helper()
	target, operationTarget, membership := uuid.New(), uuid.New(), uuid.New()
	var batch, operation uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT membership.batch_id,joined_target.operation_id FROM tsw_batch_memberships membership JOIN tsw_operation_targets joined_target ON joined_target.id=membership.join_operation_target_id WHERE membership.id=$1`, originalMembership).Scan(&batch, &operation); err != nil {
		t.Fatal(err)
	}
	normalized, version, fingerprint, err := identity.Fingerprint(ring, identity.TargetLogin, email)
	if err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,$4,$2)`, []any{target, normalized, fingerprint[:], version}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal,status,completed_at) SELECT $1,$2,$3,COALESCE(max(ordinal),0)+1,'succeeded',now() FROM tsw_operation_targets WHERE operation_id=$2`, []any{operationTarget, operation, target}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at,platform_member_id,seat_type) VALUES($1,$2,$3,$4,now(),$5,'prolite')`, []any{membership, batch, target, operationTarget, "member-" + membership.String()}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2 WHERE id=$1`, []any{operationTarget, membership}},
	}
	for _, item := range queries {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	return membership
}

func seedCPAWorkspaceManageEvidence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, membership uuid.UUID) int64 {
	t.Helper()
	var workspace, mother uuid.UUID
	var targetIdentifier string
	var currentPlatformMemberID *string
	if err := pool.QueryRow(ctx, `SELECT binding.workspace_id,binding.mother_account_id,target.identifier,membership.platform_member_id
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id
		WHERE membership.id=$1`, membership).Scan(&workspace, &mother, &targetIdentifier, &currentPlatformMemberID); err != nil {
		t.Fatal(err)
	}
	platformMemberID := "member-" + membership.String()
	if currentPlatformMemberID == nil || *currentPlatformMemberID == "" {
		if _, err := pool.Exec(ctx, `UPDATE tsw_batch_memberships SET platform_member_id=$2,seat_type='prolite',updated_at=now(),version=version+1 WHERE id=$1`, membership, platformMemberID); err != nil {
			t.Fatal(err)
		}
	} else {
		platformMemberID = *currentPlatformMemberID
		if _, err := pool.Exec(ctx, `UPDATE tsw_batch_memberships SET seat_type='prolite',updated_at=now(),version=version+1 WHERE id=$1`, membership); err != nil {
			t.Fatal(err)
		}
	}
	var verificationID int64
	if err := pool.QueryRow(ctx, `INSERT INTO tsw_workspace_verifications(
		workspace_id,mother_account_id,discovery_run_id,session_generation,secret_revision,token_attempt,token_exchange_id,
		source,outcome,permission,completeness,observed_at,expires_at,active_until,seat_limit,member_count,pending_invite_count,seat_type_counts)
		VALUES($1,$2,$3,$4,1,1,$5,'injected_platform_reader','verified','manage','complete',now(),now()+interval '1 hour',now()+interval '30 days',20,2,0,'{"prolite":2}'::jsonb)
		RETURNING id`, workspace, mother, uuid.New(), uuid.New(), uuid.New()).Scan(&verificationID); err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		identifier, role, memberID string
		hmacByte                   byte
	}{
		{identifier: "owner@example.com", role: "owner", memberID: "owner-member", hmacByte: 0x71},
		{identifier: targetIdentifier, role: "member", memberID: platformMemberID, hmacByte: 0x72},
	}
	for _, entry := range queries {
		if _, err := pool.Exec(ctx, `INSERT INTO tsw_workspace_verification_entries(verification_id,kind,identifier,identifier_hmac,identifier_key_version,status,role,platform_member_id,seat_type)
			VALUES($1,'member',$2,$3,1,'active',$4,$5,'prolite')`, verificationID, entry.identifier, bytes.Repeat([]byte{entry.hmacByte}, 32), entry.role, entry.memberID); err != nil {
			t.Fatal(err)
		}
	}
	return verificationID
}

func seedCPAEligibleReplacement(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ring cardIntegrationKeyRing, email string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	account, standby := uuid.New(), uuid.New()
	normalized, version, fingerprint, err := identity.Fingerprint(ring, identity.TargetLogin, email)
	if err != nil {
		t.Fatal(err)
	}
	var sourceAccount uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT target_account_id FROM tsw_target_credentials LIMIT 1`).Scan(&sourceAccount); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,$4,$2)`, account, normalized, fingerprint[:], version); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_credentials(target_account_id,password_secret,totp_secret,material_status,materials_sealed,latest_probe_status,latest_probe_endpoint_key,latest_probe_origin,latest_probed_at,last_verified_at)
		SELECT $1,password_secret,totp_secret,'complete',true,'available','account_usage','worker',now(),now() FROM tsw_target_credentials WHERE target_account_id=$2`, account, sourceAccount); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_standby_child_batches(id,name) VALUES($1,'CPA automatic replacements')`, standby); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_standby_child_memberships(target_account_id,batch_id) VALUES($1,$2)`, account, standby); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour)
	claims, _ := json.Marshal(map[string]any{"exp": expiresAt.Unix(), "sub": "auth0|replacement", "email": normalized})
	session := platform.PersonalSession{
		AccessToken: "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".fixture",
		ExpiresAt:   expiresAt,
		DeviceID:    "cpa-rotation-fixture",
		Cookies:     []platform.SessionCookie{{Name: "__Secure-next-auth.session-token", Value: "fixture-cookie"}},
	}
	keyVersion, nonce, sealed, err := sealSessionFor("target", ring, account, 1, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_personal_access(target_account_id,secret_revision,attempt,status,checked_at) VALUES($1,1,1,'ready',now())`, account); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO tsw_target_personal_sessions(target_account_id,secret_revision,attempt,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,1,1,$2,$3,$4,$5,$6)`, account, uuid.New(), keyVersion, nonce, sealed, expiresAt); err != nil {
		t.Fatal(err)
	}
	return account, standby
}
