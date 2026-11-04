//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestCPAAutomaticRotationUpgradeFrom61Integration(t *testing.T) {
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
	files, err := fs.Sub(sqlFiles, "sql")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 61); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO tsw_cpa_degradation_events(event_id,credential_id,credential_revision,normalized_email,expected_model,detected_model,confidence,observed_at,event_status) VALUES(gen_random_uuid(),'upgrade-credential','revision-1','upgrade@example.com','gpt-5.5','gpt-5.5-mini',0.99,now(),'quarantined')`); err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 62); err != nil {
		t.Fatal(err)
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil || version != 62 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	var settings, events, cases, foreignKeys int
	if err = db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM tsw_cpa_automation_settings WHERE singleton),
		(SELECT count(*) FROM tsw_cpa_degradation_events WHERE credential_id='upgrade-credential'),
		(SELECT count(*) FROM tsw_cpa_rotation_cases),
		(SELECT count(*) FROM information_schema.table_constraints WHERE table_schema='public' AND table_name='tsw_cpa_degradation_events' AND constraint_name='tsw_cpa_degradation_events_rotation_case_fk')`).Scan(&settings, &events, &cases, &foreignKeys); err != nil {
		t.Fatal(err)
	}
	if settings != 1 || events != 1 || cases != 0 || foreignKeys != 1 {
		t.Fatalf("upgrade result settings=%d events=%d cases=%d foreign_keys=%d", settings, events, cases, foreignKeys)
	}
}
