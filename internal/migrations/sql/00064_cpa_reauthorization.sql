-- +goose Up
CREATE TABLE tsw_cpa_reauthorizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id text NOT NULL,
    credential_name text NOT NULL,
    remote_revision text NOT NULL,
    workspace_id text NOT NULL,
    target_account_id uuid NOT NULL REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    source_secret_revision bigint NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','blocked','superseded')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_owner uuid,
    lease_expires_at timestamptz,
    credential_payload bytea,
    delivery_revision text,
    last_error_code text,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(credential_name,remote_revision),
    CHECK ((status='running')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((credential_payload IS NULL)=(delivery_revision IS NULL))
);
CREATE INDEX tsw_cpa_reauthorizations_ready_idx ON tsw_cpa_reauthorizations(status,next_attempt_at);

ALTER TABLE tsw_cpa_rotation_deliveries
    ADD COLUMN credential_payload bytea,
    ADD COLUMN delivery_revision text,
    ADD CONSTRAINT tsw_cpa_delivery_credential_pair_ck CHECK ((credential_payload IS NULL)=(delivery_revision IS NULL));

-- +goose Down
ALTER TABLE tsw_cpa_rotation_deliveries
    DROP CONSTRAINT tsw_cpa_delivery_credential_pair_ck,
    DROP COLUMN credential_payload,
    DROP COLUMN delivery_revision;
DROP TABLE tsw_cpa_reauthorizations;
