//go:build integration

package runtime

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

// TestCPARefreshesUnmappedEventWithoutRotationCase proves that a recent
// unresolved callback causes a real selected-workspace verification write. It
// does not enqueue the generic workspace_read task, and the second pass is
// throttled by the fresh verification row.
func TestCPARefreshesUnmappedEventWithoutRotationCase(t *testing.T) {
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
	// Use the shared fixture builder for the complete schema and base graph.
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	defer pool.Close()
	_ = ring
	var workspace, mother uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT binding.workspace_id,binding.mother_account_id FROM tsw_mother_workspace_bindings binding LIMIT 1`).Scan(&workspace, &mother); err != nil {
		t.Fatal(err)
	}
	run, generation := uuid.New(), uuid.New()
	// The card fixture has no selected-workspace exchange, so seed the same
	// durable binding an Owner verification would use.
	login := "owner@example.test"
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_mother_account_credentials(mother_account_id,login_identifier,identifier_hmac,identifier_key_version,password_secret) VALUES($1,$2,decode(repeat('71',32),'hex'),1,'sealed-test')`, mother, login); err != nil {
		t.Fatal(err)
	}
	personal := platform.PersonalSession{AccessToken: "fixture-personal-token", DeviceID: "fixture-device", Cookies: []platform.SessionCookie{{Name: "__Secure-next-auth.session-token", Value: "fixture-cookie"}}, ExpiresAt: time.Now().Add(time.Hour)}
	key, nonce, sealed, err := sealPersonalSession(cardIntegrationKeyRing{}, mother, 1, personal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_mother_personal_sessions(mother_account_id,secret_revision,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,1,$2,$3,$4,$5,$6)`, mother, generation, key, nonce, sealed, personal.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_mother_discoveries(mother_account_id,run_id,secret_revision,session_generation,status) VALUES($1,$2,1,$3,'discovered')`, mother, run, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_mother_workspace_visibility(mother_account_id,workspace_id,run_id,access_status) VALUES($1,$2,$3,'readable')`, mother, workspace, run); err != nil {
		t.Fatal(err)
	}
	binding := workspaceAccessBinding{motherID: mother, workspaceID: workspace, run: run, generation: generation, revision: 1, attempt: 1, exchangeID: uuid.New()}
	access := fixtureWorkspaceAccess("workspace-card")
	key, nonce, sealed, err = sealWorkspaceAccess(cardIntegrationKeyRing{}, binding, access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_selected_workspace_tokens(mother_account_id,workspace_id,discovery_run_id,session_generation,secret_revision,attempt,exchange_id,status,key_version,nonce,sealed_access,expires_at) VALUES($1,$2,$3,$4,1,1,$5,'ready',$6,$7,$8,$9)`, mother, workspace, run, generation, binding.exchangeID, key, nonce, sealed, access.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_cpa_degradation_events(event_id,credential_id,credential_revision,normalized_email,expected_model,detected_model,confidence,observed_at,event_status,mapping_status,mapping_message) VALUES($1,'unmapped-credential','rev-1',$2,'gpt-5.5','gpt-5.5-mini',0.99,now(),'quarantined','not_found','awaiting selected workspace refresh')`, uuid.New(), login); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE tsw_workspace_verification_entries DISABLE TRIGGER USER; ALTER TABLE tsw_workspace_verifications DISABLE TRIGGER USER; DELETE FROM tsw_workspace_verification_entries; DELETE FROM tsw_workspace_verifications; ALTER TABLE tsw_workspace_verifications ENABLE TRIGGER USER; ALTER TABLE tsw_workspace_verification_entries ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	// The callback has no operational mother_workspace_binding yet. The
	// selected token and readable visibility are the only adoption anchors.
	if _, err := pool.Exec(ctx, `UPDATE tsw_mother_workspace_bindings SET status='ended',ended_at=now()`); err != nil {
		t.Fatal(err)
	}
	activeUntil := time.Now().Add(time.Hour)
	seatLimit, members, invites := 20, 1, 0
	handler.selectedWorkspaceReader = &selectedFixture{facts: platform.SelectedWorkspaceFacts{Permission: "manage", Result: platform.Result{Outcome: platform.OutcomeOperational, Completeness: platform.Complete, ObservedAt: time.Now().UTC(), ActiveUntil: &activeUntil, SeatLimit: &seatLimit, MemberCount: &members, PendingInviteCount: &invites, Members: []platform.Member{{Kind: "member", PlatformMemberID: "owner-member", Identifier: login, Status: "listed", Role: "owner", SeatType: "prolite"}}}}}
	refreshed, err := handler.refreshCPAEvidenceOnce(ctx)
	if err != nil || !refreshed {
		t.Fatalf("refresh=%v err=%v", refreshed, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_workspace_verifications WHERE workspace_id=$1 AND mother_account_id=$2 AND permission='manage' AND outcome='verified'`, workspace, mother).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("manage verifications=%d", count)
	}
	var generic int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_tasks WHERE task_type='workspace_read'`).Scan(&generic); err != nil {
		t.Fatal(err)
	}
	if generic != 0 {
		t.Fatalf("generic workspace_read tasks=%d", generic)
	}
	refreshed, err = handler.refreshCPAEvidenceOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed {
		t.Fatal("fresh verification was refreshed before throttle window")
	}
}
