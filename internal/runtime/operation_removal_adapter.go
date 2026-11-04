package runtime

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/task"
)

// operationRemovalAdapter binds the removal worker to the same selected
// Workspace authority used by Owner operations. It never receives or opens a
// password; each snapshot and delete rechecks the durable manage evidence.
type operationRemovalAdapter struct {
	owner                       *OwnerAuthHandler
	client                      *http.Client
	target                      task.RemovalTarget
	mother, workspace, exchange uuid.UUID
	frozenMemberID              string
}

func (h *OwnerAuthHandler) operationRemover(ctx context.Context, client *http.Client, target task.RemovalTarget) (platform.Remover, error) {
	workspace, err := uuid.Parse(target.WorkspaceID)
	if err != nil || target.PlatformWorkspace == "" {
		return nil, errOperationAuthority
	}
	var mother, exchange uuid.UUID
	var frozenMemberID string
	err = h.pool.QueryRow(ctx, `SELECT binding.mother_account_id,membership.platform_member_id,
		COALESCE((SELECT v.token_exchange_id FROM tsw_workspace_verifications v
			WHERE v.workspace_id=binding.workspace_id AND v.mother_account_id=binding.mother_account_id
				AND v.outcome='verified' AND v.permission='manage' AND v.completeness='complete'
				AND v.active_until>now() AND v.expires_at>now() ORDER BY v.id DESC LIMIT 1), '00000000-0000-0000-0000-000000000000')
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		WHERE membership.id=$1 AND binding.workspace_id=$2 AND binding.ended_at IS NULL`, target.MembershipID, workspace).Scan(&mother, &frozenMemberID, &exchange)
	if err != nil {
		return nil, errOperationAuthority
	}
	if frozenMemberID == "" || exchange == uuid.Nil {
		return nil, errOperationAuthority
	}
	adapter := &operationRemovalAdapter{owner: h, client: client, target: target, mother: mother, workspace: workspace, exchange: exchange, frozenMemberID: frozenMemberID}
	if _, err = adapter.authority(ctx); err != nil {
		return nil, err
	}
	return adapter, nil
}

func (a *operationRemovalAdapter) authority(ctx context.Context) (platform.WorkspaceAccess, error) {
	tx, err := a.owner.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return platform.WorkspaceAccess{}, errOperationAuthority
	}
	defer tx.Rollback(ctx)
	facts, _, access, err := a.owner.selectedWorkspaceSnapshotTx(ctx, tx, a.workspace, a.mother)
	if err != nil || facts.Status != "verified" || !facts.CanManage || facts.ExchangeId == nil || *facts.ExchangeId != a.exchange || access.WorkspaceID != a.target.PlatformWorkspace {
		return platform.WorkspaceAccess{}, errOperationAuthority
	}
	if err = tx.Commit(ctx); err != nil {
		return platform.WorkspaceAccess{}, errOperationAuthority
	}
	return access, nil
}

func (a *operationRemovalAdapter) SnapshotMembers(ctx context.Context, workspace string) (platform.ExactMemberSnapshot, error) {
	if workspace != a.target.PlatformWorkspace {
		return platform.ExactMemberSnapshot{}, errOperationAuthority
	}
	access, err := a.authority(ctx)
	if err != nil {
		return platform.ExactMemberSnapshot{}, err
	}
	return (platform.OfficialWorkspaceMemberRemover{Client: staticDiscoveryClient(a.client)}).SnapshotWorkspaceMembers(ctx, access, workspace)
}

func (a *operationRemovalAdapter) RemoveMember(ctx context.Context, workspace, memberID string) (platform.RemoveMemberResult, error) {
	if workspace != a.target.PlatformWorkspace || memberID == "" || memberID != a.frozenMemberID {
		return platform.RemoveMemberResult{}, errOperationAuthority
	}
	access, err := a.authority(ctx)
	if err != nil {
		return platform.RemoveMemberResult{}, err
	}
	return (platform.OfficialWorkspaceMemberRemover{Client: staticDiscoveryClient(a.client)}).RemoveWorkspaceMember(ctx, access, workspace, memberID, a.target.OperationID)
}

// staticDiscoveryClient supplies the already leased HTTP client to the official
// remover without acquiring a second route.
func staticDiscoveryClient(client *http.Client) platform.DiscoveryClient {
	return func(context.Context) (*http.Client, func(), error) {
		if client == nil {
			return nil, nil, errors.New("workspace client unavailable")
		}
		return client, func() {}, nil
	}
}
