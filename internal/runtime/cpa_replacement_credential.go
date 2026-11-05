package runtime

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
)

// cpaReplacementCredential checkpoints the assigned proxy and credential before CPA sees any upload.
// Retries reuse that exact encrypted credential, rather than issuing new grants.
func (h *OwnerAuthHandler) cpaReplacementCredential(ctx context.Context, action cpaRotationAction, source cpacred.Credential) (cpacred.Credential, error) {
	var target uuid.UUID
	var workspace string
	var revision int64
	var sealed []byte
	var deliveryRevision *string
	err := h.pool.QueryRow(ctx, `SELECT c.replacement_account_id,w.platform_workspace_id,t.secret_revision,d.credential_payload,d.delivery_revision
		FROM tsw_cpa_rotation_deliveries d
		JOIN tsw_cpa_rotation_cases c ON c.id=d.case_id
		JOIN tsw_workspaces w ON w.id=c.workspace_id
		JOIN tsw_target_accounts a ON a.id=c.replacement_account_id AND a.status='active'
		JOIN tsw_target_credentials t ON t.target_account_id=a.id AND t.materials_sealed AND t.material_status='complete'
		WHERE d.id=$1 AND d.claim_token=$2 AND d.status='in_flight' AND c.status='delivering'
		AND d.credential_name=$3 AND d.credential_revision=$4`, action.DeliveryID, action.ClaimToken, source.Name, source.Revision).Scan(&target, &workspace, &revision, &sealed, &deliveryRevision)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if h.targetRoutes != nil {
		enabled, err := h.targetRoutes.Enabled(ctx)
		if err != nil {
			return cpacred.Credential{}, err
		}
		if enabled {
			var current bool
			err = h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_account_route_bindings b JOIN tsw_batch_memberships m ON m.target_account_id=b.target_account_id JOIN tsw_oauth_assets a ON a.membership_id=m.id JOIN tsw_delivery_versions v ON v.id=a.current_delivery_version_id WHERE b.target_account_id=$1 AND NOT b.paused AND v.created_at>=b.created_at)`, target).Scan(&current)
			if err != nil {
				return cpacred.Credential{}, err
			}
			if !current {
				return cpacred.Credential{}, errors.New("CPA source predates account proxy binding")
			}
		}
	}
	type checkpoint struct {
		Credential     cpacred.Credential
		SecretRevision int64
		Workspace      string
	}
	var saved checkpoint
	if len(sealed) > 0 {
		raw, err := targetdomain.OpenMaterial(sealed, h.keyRing)
		if err != nil {
			return cpacred.Credential{}, err
		}
		if json.Unmarshal([]byte(raw), &saved) != nil || saved.SecretRevision != revision || saved.Workspace != workspace || saved.Credential.Name != source.Name || saved.Credential.Email != source.Email || deliveryRevision == nil || saved.Credential.Revision != *deliveryRevision {
			return cpacred.Credential{}, errors.New("CPA credential checkpoint no longer matches replacement")
		}
		if err := h.verifyCPARoute(ctx, target, saved.Credential); err != nil {
			return cpacred.Credential{}, err
		}
		return saved.Credential, nil
	}
	credential, err := h.cpaProxyAssignment(ctx, target, source)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if err := h.verifyCPARoute(ctx, target, credential); err != nil {
		return cpacred.Credential{}, err
	}
	saved = checkpoint{credential, revision, workspace}
	raw, err := json.Marshal(saved)
	if err != nil {
		return cpacred.Credential{}, err
	}
	sealed, err = targetdomain.SealMaterial(string(raw), h.keyRing)
	if err != nil {
		return cpacred.Credential{}, err
	}
	updated, err := h.pool.Exec(ctx, `UPDATE tsw_cpa_rotation_deliveries d SET credential_payload=$3,delivery_revision=$4
		WHERE d.id=$1 AND d.claim_token=$2 AND d.status='in_flight' AND d.credential_payload IS NULL
		AND EXISTS(SELECT 1 FROM tsw_target_accounts a JOIN tsw_target_credentials t ON t.target_account_id=a.id
		WHERE a.id=$5 AND a.status='active' AND t.secret_revision=$6 AND t.materials_sealed AND t.material_status='complete')`, action.DeliveryID, action.ClaimToken, sealed, credential.Revision, target, revision)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if updated.RowsAffected() != 1 {
		return cpacred.Credential{}, errors.New("CPA replacement changed during credential grant")
	}
	return credential, nil
}
