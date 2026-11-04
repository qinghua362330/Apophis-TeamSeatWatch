//go:build integration

package task

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
)

func TestEnqueueRetentionCleanupUsesTypedCycleKeyAndIsIdempotent(t *testing.T) {
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

	store := NewStore(pool, nil)
	created, err := store.EnqueueRetentionCleanup(ctx, "2026-11-04T03:55")
	if err != nil || !created {
		t.Fatalf("first enqueue: created=%t err=%v", created, err)
	}
	created, err = store.EnqueueRetentionCleanup(ctx, "2026-11-04T03:55")
	if err != nil || created {
		t.Fatalf("duplicate enqueue: created=%t err=%v", created, err)
	}

	var dedupe, correlation, cycle string
	if err = pool.QueryRow(ctx, `SELECT dedupe_key,correlation_id,input_snapshot->>'cycle_key' FROM tsw_tasks WHERE task_type='retention_cleanup'`).Scan(&dedupe, &correlation, &cycle); err != nil {
		t.Fatal(err)
	}
	if dedupe != "retention-cleanup:2026-11-04T03:55" || correlation != dedupe || cycle != dedupe {
		t.Fatalf("unexpected retention task: dedupe=%q correlation=%q cycle=%q", dedupe, correlation, cycle)
	}

	item, err := store.ClaimRetentionCleanup(ctx, "retention-test-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CompleteRetentionCleanup(ctx, item, func(context.Context, pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var status string
	var auditCount int
	if err = pool.QueryRow(ctx, `SELECT status FROM tsw_tasks WHERE id=$1`, item.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM tsw_audit_events WHERE event_type='retention.cleanup_completed' AND entity_id=$1`, item.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || auditCount != 1 {
		t.Fatalf("retention completion: status=%q audit_count=%d", status, auditCount)
	}
}
