//go:build integration

package runtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
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

	secondMembership := seedSecondActiveMembership(t, ctx, pool, ids.membership)
	before = cpaSnapshot(t, ctx, pool, ids.membership)
	ambiguous := receiveCPAEvent(t, handler, cpaPayload(uuid.New(), "later@example.com", "credential-ambiguous"))
	assertCPAResponse(t, ambiguous, http.StatusAccepted, "ambiguous")
	assertCPANonDestructive(t, ctx, pool, ids.membership, before)
	if state := membershipState(t, ctx, pool, secondMembership); state != "active" {
		t.Fatalf("second membership state=%s want active", state)
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
