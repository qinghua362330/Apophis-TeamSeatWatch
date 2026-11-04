-- +goose Up
ALTER TABLE tsw_operations DROP CONSTRAINT tsw_operations_type_ck;
ALTER TABLE tsw_operations ADD CONSTRAINT tsw_operations_type_ck CHECK (operation_type IN ('join','remove','adopt'));
CREATE TABLE tsw_cpa_member_adoptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id uuid NOT NULL UNIQUE REFERENCES tsw_operations(id) ON DELETE RESTRICT,
    workspace_id uuid NOT NULL REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    target_account_id uuid NOT NULL REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    membership_id uuid NOT NULL REFERENCES tsw_batch_memberships(id) ON DELETE RESTRICT,
    normalized_email text NOT NULL,
    platform_member_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tsw_cpa_member_adoptions_identity_uq ON tsw_cpa_member_adoptions(workspace_id,target_account_id);
-- +goose Down
DROP TABLE tsw_cpa_member_adoptions;
ALTER TABLE tsw_operations DROP CONSTRAINT tsw_operations_type_ck;
ALTER TABLE tsw_operations ADD CONSTRAINT tsw_operations_type_ck CHECK (operation_type IN ('join','remove'));
