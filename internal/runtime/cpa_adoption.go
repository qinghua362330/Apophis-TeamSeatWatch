package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
)

// adoptCPAMemberTx imports a uniquely identified ordinary Pro seat from the
// freshest complete manage roster. It never performs a platform join.
func (h *OwnerAuthHandler) adoptCPAMemberTx(ctx context.Context, tx pgx.Tx, email string) (accountID, membershipID, workspaceID uuid.UUID, found bool, err error) {
	normalized, keyVersion, fingerprint, err := identity.Fingerprint(h.keyRing, identity.TargetLogin, email)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	_, entryVersion, entryFingerprint, err := identity.Fingerprint(h.keyRing, identity.WorkspaceEntry, email)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('tsw:cpa-adoption'))`).Scan(&locked); err != nil || !locked {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	var ownerID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM tsw_owners WHERE singleton`).Scan(&ownerID); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	var memberID, role, seat, workspaceText, motherText string
	var matches int
	err = tx.QueryRow(ctx, `WITH latest AS (
 SELECT DISTINCT ON (v.workspace_id) v.* FROM tsw_workspace_verifications v
 JOIN tsw_mother_accounts mother ON mother.id=v.mother_account_id AND mother.status='active'
 WHERE NOT EXISTS(SELECT 1 FROM tsw_mother_workspace_bindings b WHERE b.workspace_id=v.workspace_id AND b.ended_at IS NULL AND b.mother_account_id<>v.mother_account_id)
 AND (v.source='injected_platform_reader' OR EXISTS(SELECT 1 FROM tsw_selected_workspace_tokens token WHERE token.workspace_id=v.workspace_id AND token.mother_account_id=v.mother_account_id AND token.status='ready' AND token.expires_at>now() AND token.discovery_run_id=v.discovery_run_id AND token.session_generation=v.session_generation AND token.secret_revision=v.secret_revision AND token.attempt=v.token_attempt AND token.exchange_id=v.token_exchange_id))
 ORDER BY v.workspace_id,v.id DESC
), matched AS (
 SELECT v.workspace_id,v.mother_account_id,e.platform_member_id,e.role,e.seat_type FROM latest v
 JOIN tsw_workspace_verification_entries e ON e.verification_id=v.id
 WHERE v.outcome='verified' AND v.permission='manage' AND v.completeness='complete'
 AND v.active_until>now() AND v.expires_at>now()
 AND e.kind='member' AND e.identifier_key_version=$1 AND e.identifier_hmac=$2 AND e.status IN ('active','listed')
 AND NOT EXISTS(SELECT 1 FROM tsw_batch_memberships old JOIN tsw_target_accounts a ON a.id=old.target_account_id
 JOIN tsw_batches batch ON batch.id=old.batch_id JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
 WHERE binding.workspace_id=v.workspace_id AND a.identifier_key_version=$3 AND a.identifier_hmac=$4 AND old.state='removed' AND old.removed_at>=v.observed_at)
) SELECT count(*)::int,coalesce(min(platform_member_id),''),coalesce(min(role),''),coalesce(min(seat_type),''),coalesce(min(workspace_id::text),''),coalesce(min(mother_account_id::text),'') FROM matched`, entryVersion, entryFingerprint[:], keyVersion, fingerprint[:]).Scan(&matches, &memberID, &role, &seat, &workspaceText, &motherText)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if matches != 1 || strings.TrimSpace(memberID) == "" || seat != "prolite" || (strings.ToLower(strings.TrimSpace(role)) != "member" && strings.ToLower(strings.TrimSpace(role)) != "standard-user") {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, nil
	}
	workspaceID, err = uuid.Parse(workspaceText)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if err = tx.QueryRow(ctx, `SELECT id FROM tsw_target_accounts WHERE identifier_key_version=$1 AND identifier_hmac=$2`, keyVersion, fingerprint[:]).Scan(&accountID); errors.Is(err, pgx.ErrNoRows) {
		if err = tx.QueryRow(ctx, `INSERT INTO tsw_target_accounts(identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,$3,$1) RETURNING id`, normalized, fingerprint[:], keyVersion).Scan(&accountID); err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, false, err
		}
	} else if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	var bindingID, batchID uuid.UUID
	if _, err = tx.Exec(ctx, `INSERT INTO tsw_mother_workspace_bindings(mother_account_id,workspace_id) VALUES($1,$2) ON CONFLICT(workspace_id) WHERE ended_at IS NULL DO NOTHING`, motherText, workspaceID); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if err = tx.QueryRow(ctx, `SELECT id FROM tsw_mother_workspace_bindings WHERE workspace_id=$1 AND mother_account_id=$2 AND ended_at IS NULL`, workspaceID, motherText).Scan(&bindingID); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if err = tx.QueryRow(ctx, `SELECT membership.id FROM tsw_batch_memberships membership JOIN tsw_batches batch ON batch.id=membership.batch_id WHERE batch.binding_id=$1 AND membership.target_account_id=$2 AND membership.state='active'`, bindingID, accountID).Scan(&membershipID); err == nil {
		return accountID, membershipID, workspaceID, true, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if err = tx.QueryRow(ctx, `SELECT id FROM tsw_batches WHERE binding_id=$1 AND status='serving' ORDER BY sequence_no DESC LIMIT 1`, bindingID).Scan(&batchID); errors.Is(err, pgx.ErrNoRows) {
		if err = tx.QueryRow(ctx, `INSERT INTO tsw_batches(binding_id,sequence_no,status,planned_at,service_started_at) SELECT $1,coalesce(max(sequence_no),0)+1,'serving',now(),now() FROM tsw_batches WHERE binding_id=$1 RETURNING id`, bindingID).Scan(&batchID); err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, false, err
		}
	} else if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	requestHash := sha256.Sum256([]byte("cpa-adopt\x00" + normalized + "\x00" + workspaceID.String()))
	input, _ := json.Marshal(map[string]any{"email": normalized, "platform_member_id": memberID, "workspace_id": workspaceID.String(), "provenance": "cpa_roster_adoption"})
	var opID, targetID uuid.UUID
	if err = tx.QueryRow(ctx, `INSERT INTO tsw_operations(owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id,status,completed_at) VALUES($1,$2,$3,'adopt',$4,$5,$6,$7,'succeeded',now()) ON CONFLICT(owner_id,operation_type,idempotency_key) DO UPDATE SET updated_at=now() RETURNING id`, ownerID, workspaceID, batchID, "cpa-adopt-"+hex.EncodeToString(requestHash[:]), requestHash[:], input, "cpa-adopt:"+workspaceID.String()).Scan(&opID); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tsw_operation_targets(operation_id,target_account_id,ordinal,status,completed_at) VALUES($1,$2,1,'succeeded',now()) RETURNING id`, opID, accountID).Scan(&targetID); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tsw_batch_memberships(batch_id,target_account_id,join_operation_target_id,platform_member_id,state,seat_type,joined_at) VALUES($1,$2,$3,$4,'active','prolite',now()) RETURNING id`, batchID, accountID, targetID, memberID).Scan(&membershipID); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tsw_cpa_member_adoptions(operation_id,workspace_id,target_account_id,membership_id,normalized_email,platform_member_id) VALUES($1,$2,$3,$4,$5,$6)`, opID, workspaceID, accountID, membershipID, normalized, memberID)
	return accountID, membershipID, workspaceID, true, err
}
