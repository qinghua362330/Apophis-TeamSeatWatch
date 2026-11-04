-- +goose Up
CREATE TABLE tsw_cpa_degradation_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id uuid NOT NULL UNIQUE,
    credential_id text NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 512),
    credential_revision text NOT NULL CHECK (length(credential_revision) BETWEEN 1 AND 256),
    normalized_email text NOT NULL CHECK (length(normalized_email) BETWEEN 3 AND 254),
    expected_model text NOT NULL CHECK (length(expected_model) BETWEEN 1 AND 200),
    detected_model text NOT NULL CHECK (length(detected_model) BETWEEN 1 AND 200),
    confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    observed_at timestamptz NOT NULL,
    event_status text NOT NULL CHECK (event_status = 'quarantined'),
    mapping_status text NOT NULL DEFAULT 'received' CHECK (mapping_status IN ('received','mapped','ambiguous','not_found','pending_rotation','dismissed')),
    target_account_id uuid REFERENCES tsw_target_accounts(id) ON DELETE SET NULL,
    membership_id uuid REFERENCES tsw_batch_memberships(id) ON DELETE SET NULL,
    workspace_id uuid REFERENCES tsw_workspaces(id) ON DELETE SET NULL,
    rotation_case_id uuid,
    mapping_message text NOT NULL DEFAULT '' CHECK (length(mapping_message) <= 1000),
    received_at timestamptz NOT NULL DEFAULT now(),
    mapped_at timestamptz,
    dismissed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((mapping_status IN ('mapped','pending_rotation') AND target_account_id IS NOT NULL AND membership_id IS NOT NULL AND workspace_id IS NOT NULL) OR mapping_status NOT IN ('mapped','pending_rotation')),
    CHECK ((mapping_status = 'dismissed') = (dismissed_at IS NOT NULL))
);
CREATE INDEX tsw_cpa_degradation_events_status_idx ON tsw_cpa_degradation_events(mapping_status, received_at DESC);
CREATE INDEX tsw_cpa_degradation_events_credential_idx ON tsw_cpa_degradation_events(credential_id, received_at DESC);
CREATE INDEX tsw_cpa_degradation_events_target_idx ON tsw_cpa_degradation_events(target_account_id, received_at DESC) WHERE target_account_id IS NOT NULL;

-- +goose Down
DROP TABLE tsw_cpa_degradation_events;
