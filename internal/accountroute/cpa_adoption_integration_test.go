//go:build integration

package accountroute

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
)

// This fixture exercises the durable binding fences directly against the same
// PostgreSQL schema used by Store. Network probing is intentionally omitted;
// egress lease tests own transport verification.
func TestCPAAdoptionBindingFences(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err = db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	var target, node string
	err = db.QueryRowContext(ctx, `INSERT INTO tsw_target_accounts(identifier,identifier_hmac,identifier_key_version,display_label) VALUES('adoption@example.com',decode(repeat('aa',32),'hex'),1,'adoption') RETURNING id`).Scan(&target)
	if err != nil {
		t.Fatal(err)
	}
	err = db.QueryRowContext(ctx, `INSERT INTO tsw_proxy_pool_nodes(endpoint_key_version,endpoint_nonce,endpoint_ciphertext,endpoint_digest,scheme,display_host,state,session_type) VALUES(0,''::bytea,''::bytea,decode(repeat('bb',32),'hex'),'http','fixture','healthy','sticky') RETURNING id`).Scan(&node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO tsw_account_route_bindings(target_account_id,node_id) VALUES($1,$2)`, target, node); err != nil {
		t.Fatal(err)
	}
	pctx, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pctx.Close()
	binding, err := (Store{Pool: pctx}).EnsureBinding(ctx, mustUUID(t, target))
	if err != nil || binding.NodeID.String() != node {
		t.Fatalf("EnsureBinding: %v", err)
	}
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	if _, err = db.ExecContext(ctx, `UPDATE tsw_account_route_bindings SET expected_ip_fingerprint=$2,ip_key_version=1 WHERE target_account_id=$1 AND expected_ip_fingerprint IS NULL`, target, fp); err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err = db.QueryRowContext(ctx, `SELECT expected_ip_fingerprint FROM tsw_account_route_bindings WHERE target_account_id=$1`, target).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(fp) {
		t.Fatal("first measured fingerprint was not persisted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE tsw_account_route_bindings SET paused=true,paused_reason='egress_drift' WHERE target_account_id=$1 AND node_id=$2 AND expected_ip_fingerprint<>$3`, target, node, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	var sameNode string
	if err = db.QueryRowContext(ctx, `SELECT node_id FROM tsw_account_route_bindings WHERE target_account_id=$1`, target).Scan(&sameNode); err != nil {
		t.Fatal(err)
	}
	if sameNode != node {
		t.Fatal("drift reassigned the bound node")
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO tsw_account_route_bindings(target_account_id,node_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, target, node); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM tsw_account_route_bindings WHERE target_account_id=$1`, target).Scan(&count); err != nil || count != 1 {
		t.Fatalf("binding was duplicated: %v", err)
	}
	var pausedTarget string
	if err = db.QueryRowContext(ctx, `INSERT INTO tsw_target_accounts(identifier,identifier_hmac,identifier_key_version,display_label) VALUES('paused@example.com',decode(repeat('cc',32),'hex'),1,'paused') RETURNING id`).Scan(&pausedTarget); err != nil {
		t.Fatal(err)
	}
	if err = (Store{Pool: pctx}).Pause(ctx, mustUUID(t, pausedTarget), "missing_proxy"); err != nil {
		t.Fatal(err)
	}
	pausedBinding, pausedErr := (Store{Pool: pctx}).EnsureBinding(ctx, mustUUID(t, pausedTarget))
	if !errors.Is(pausedErr, ErrPaused) || pausedBinding.NodeID != uuid.Nil {
		t.Fatalf("paused NULL binding was not preserved: binding=%+v err=%v", pausedBinding, pausedErr)
	}
}

func mustUUID(t *testing.T, raw string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
