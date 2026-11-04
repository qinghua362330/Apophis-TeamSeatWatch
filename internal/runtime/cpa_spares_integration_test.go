//go:build integration

package runtime

import (
	"testing"

	"github.com/google/uuid"
)

func TestEnsureCPASparePoolEnrollsOnlyEligibleImportedAccounts(t *testing.T) {
	pool, _, _, ctx := newAutomaticRotationFixture(t)
	spare, grouped, active, cpaCurrent := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	batch := uuid.New()
	for i, account := range []uuid.UUID{spare, grouped, cpaCurrent} {
		hmac := make([]byte, 32)
		hmac[0] = byte(i + 1)
		if _, err := pool.Exec(ctx, `INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,1,$2)`, account, account.String(), hmac); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tsw_target_credentials(target_account_id,password_secret,material_status,materials_sealed) VALUES($1,'password','complete',true)`, account); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_standby_child_batches(id,name) VALUES($1,'operator group')`, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_standby_child_memberships(target_account_id,batch_id) VALUES($1,$2)`, grouped, batch); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT target_account_id FROM tsw_batch_memberships WHERE state='active' LIMIT 1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	currentHMAC := make([]byte, 32)
	currentHMAC[0] = 3
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_cpa_credentials(credential_id,credential_name,provider,observed_revision,email_hmac,email_key_version) VALUES('current','current.json','codex','r1',$1,1)`, currentHMAC); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = ensureCPASparePoolTx(ctx, tx); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var spareBatch, groupedBatch *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT spare.batch_id,grouped.batch_id FROM tsw_standby_child_memberships spare JOIN tsw_standby_child_memberships grouped ON grouped.target_account_id=$2 WHERE spare.target_account_id=$1`, spare, grouped).Scan(&spareBatch, &groupedBatch); err != nil {
		t.Fatal(err)
	}
	if spareBatch == nil || *spareBatch != uuid.MustParse(cpaAutomaticSpareBatchID) || groupedBatch == nil || *groupedBatch != batch {
		t.Fatalf("spare batch=%v grouped batch=%v", spareBatch, groupedBatch)
	}
	var activeRows, currentRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_standby_child_memberships WHERE target_account_id=$1`, active).Scan(&activeRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_standby_child_memberships WHERE target_account_id=$1`, cpaCurrent).Scan(&currentRows); err != nil {
		t.Fatal(err)
	}
	if activeRows != 0 || currentRows != 0 {
		t.Fatalf("active rows=%d cpa-current rows=%d", activeRows, currentRows)
	}
}
