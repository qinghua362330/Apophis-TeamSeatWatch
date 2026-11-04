//go:build integration

package runtime

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
)

func seedAdoptionRoster(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ring cardIntegrationKeyRing, workspace, mother uuid.UUID, email, role, memberID string) {
	t.Helper()
	normalized, version, fingerprint, err := identity.Fingerprint(ring, identity.WorkspaceEntry, email)
	if err != nil {
		t.Fatal(err)
	}
	var verification int64
	// Keep the verification fresh and make it the newest snapshot for this workspace.
	if err := pool.QueryRow(ctx, `INSERT INTO tsw_workspace_verifications(workspace_id,mother_account_id,discovery_run_id,session_generation,secret_revision,token_attempt,token_exchange_id,source,outcome,permission,completeness,observed_at,expires_at,active_until,seat_limit,member_count,pending_invite_count,seat_type_counts) VALUES($1,$2,$3,$4,1,1,$5,'injected_platform_reader','verified','manage','complete',now(),now()+interval '1 hour',now()+interval '1 hour',20,2,0,'{"prolite":2}'::jsonb) RETURNING id`, workspace, mother, uuid.New(), uuid.New(), uuid.New()).Scan(&verification); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_workspace_verification_entries(verification_id,kind,identifier,identifier_hmac,identifier_key_version,status,role,platform_member_id,seat_type)
 SELECT $1,kind,identifier,identifier_hmac,identifier_key_version,status,role,platform_member_id,seat_type FROM tsw_workspace_verification_entries
 WHERE verification_id<>$1 AND role IN ('owner','account-owner') ORDER BY verification_id DESC LIMIT 1`, verification); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_workspace_verification_entries(verification_id,kind,identifier,identifier_hmac,identifier_key_version,status,role,platform_member_id,seat_type) VALUES($1,'member',$2,$3,$4,'active',$5,$6,'prolite')`, verification, normalized, fingerprint[:], version, role, memberID); err != nil {
		t.Fatal(err)
	}
}

func TestCPAAdoptsUniqueRosterMember(t *testing.T) {
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	var workspace, mother uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT binding.workspace_id,binding.mother_account_id FROM tsw_mother_workspace_bindings binding JOIN tsw_batches batch ON batch.binding_id=binding.id AND batch.status='serving' LIMIT 1`).Scan(&workspace, &mother); err != nil {
		t.Fatal(err)
	}
	seedAdoptionRoster(t, ctx, pool, ring, workspace, mother, "adopt@example.com", "member", "adopt-member")
	eventID := uuid.New()
	response := receiveCPAEvent(t, handler, cpaPayload(eventID, "adopt@example.com", "adopt-credential"))
	assertCPAResponse(t, response, 202, "pending_rotation")
	var adoptionCount, caseCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_member_adoptions WHERE normalized_email='adopt@example.com'`).Scan(&adoptionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_rotation_cases WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID).Scan(&caseCount); err != nil {
		t.Fatal(err)
	}
	if adoptionCount != 1 || caseCount != 1 {
		t.Fatalf("adoptions=%d cases=%d", adoptionCount, caseCount)
	}
	retry := receiveCPAEvent(t, handler, cpaPayload(eventID, "adopt@example.com", "adopt-credential"))
	assertCPAResponse(t, retry, 200, "pending_rotation")
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_member_adoptions WHERE normalized_email='adopt@example.com'`).Scan(&adoptionCount); err != nil {
		t.Fatal(err)
	}
	if adoptionCount != 1 {
		t.Fatalf("idempotent adoption count=%d", adoptionCount)
	}
}

func TestCPAAdoptionRejectsPrivilegedRosterMember(t *testing.T) {
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	var workspace, mother uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT binding.workspace_id,binding.mother_account_id FROM tsw_mother_workspace_bindings binding JOIN tsw_batches batch ON batch.binding_id=binding.id AND batch.status='serving' LIMIT 1`).Scan(&workspace, &mother); err != nil {
		t.Fatal(err)
	}
	seedAdoptionRoster(t, ctx, pool, ring, workspace, mother, "owner-adopt@example.com", "owner", "owner-adopt")
	eventID := uuid.New()
	response := receiveCPAEvent(t, handler, cpaPayload(eventID, "owner-adopt@example.com", "owner-credential"))
	assertCPAResponse(t, response, 202, "not_found")
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cpa_member_adoptions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("privileged adoption count=%d", count)
	}
}

func TestCPAAdoptionCreatesMissingOperationalBinding(t *testing.T) {
	pool, handler, ring, ctx := newAutomaticRotationFixture(t)
	var workspace, mother uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT workspace_id,mother_account_id FROM tsw_mother_workspace_bindings WHERE ended_at IS NULL LIMIT 1`).Scan(&workspace, &mother); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_mother_workspace_bindings SET status='ended',ended_at=now(),version=version+1 WHERE workspace_id=$1 AND ended_at IS NULL`, workspace); err != nil {
		t.Fatal(err)
	}
	seedAdoptionRoster(t, ctx, pool, ring, workspace, mother, "unbound-cpa@example.com", "member", "unbound-member")
	response := receiveCPAEvent(t, handler, cpaPayload(uuid.New(), "unbound-cpa@example.com", "unbound-credential"))
	event := assertCPAResponse(t, response, 202, "pending_rotation")
	var active bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_cpa_rotation_cases rotation JOIN tsw_batches batch ON batch.id=rotation.source_batch_id JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id WHERE rotation.id=$1 AND binding.ended_at IS NULL AND batch.status='serving')`, event.RotationCaseId).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("adoption did not create a live binding and serving batch")
	}
}
