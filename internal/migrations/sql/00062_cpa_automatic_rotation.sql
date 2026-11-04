-- +goose Up
CREATE TABLE tsw_cpa_automation_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT true,
    minimum_confidence double precision NOT NULL DEFAULT 0.95 CHECK (minimum_confidence >= 0 AND minimum_confidence <= 1),
    consecutive_detections integer NOT NULL DEFAULT 1 CHECK (consecutive_detections BETWEEN 1 AND 10),
    failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    circuit_open_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO tsw_cpa_automation_settings(singleton) VALUES (true);

CREATE TABLE tsw_cpa_automation_workspace_settings (
    workspace_id uuid PRIMARY KEY REFERENCES tsw_workspaces(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tsw_cpa_rotation_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id uuid NOT NULL UNIQUE REFERENCES tsw_cpa_degradation_events(id) ON DELETE RESTRICT,
    credential_id text NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 512),
    credential_revision text NOT NULL CHECK (length(credential_revision) BETWEEN 1 AND 256),
    target_account_id uuid NOT NULL REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    membership_id uuid NOT NULL REFERENCES tsw_batch_memberships(id) ON DELETE RESTRICT,
    workspace_id uuid NOT NULL REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    source_batch_id uuid NOT NULL REFERENCES tsw_batches(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'pending_automation' CHECK (status IN (
        'pending_automation','waiting_evidence','awaiting_approval','quarantining',
        'removal_queued','removal_running','removal_verified',
        'waiting_replacement','replacement_queued','replacement_running','credentials_pending','delivering',
        'completed','blocked','failed','dismissed'
    )),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error_code text CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
    removal_operation_id uuid REFERENCES tsw_operations(id) ON DELETE RESTRICT,
    replacement_operation_id uuid REFERENCES tsw_operations(id) ON DELETE RESTRICT,
    replacement_account_id uuid REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    replacement_standby_batch_id uuid REFERENCES tsw_standby_child_batches(id) ON DELETE RESTRICT,
    replacement_batch_id uuid REFERENCES tsw_batches(id) ON DELETE RESTRICT,
    started_at timestamptz,
    completed_at timestamptz,
    -- Optional operator decisions retained for compatibility with manual cases.
    approved_by uuid,
    approved_at timestamptz,
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((status IN ('completed','blocked','failed','dismissed')) = (completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX tsw_cpa_rotation_cases_membership_active_uq ON tsw_cpa_rotation_cases(membership_id)
    WHERE status NOT IN ('completed','failed','dismissed');
CREATE UNIQUE INDEX tsw_cpa_rotation_cases_replacement_active_uq ON tsw_cpa_rotation_cases(replacement_account_id)
    WHERE replacement_account_id IS NOT NULL AND status NOT IN ('completed','failed','dismissed');
CREATE INDEX tsw_cpa_rotation_cases_runnable_idx ON tsw_cpa_rotation_cases(status,next_attempt_at,created_at)
    WHERE status NOT IN ('completed','blocked','failed','dismissed');

ALTER TABLE tsw_cpa_degradation_events
    ADD CONSTRAINT tsw_cpa_degradation_events_rotation_case_fk
    FOREIGN KEY(rotation_case_id) REFERENCES tsw_cpa_rotation_cases(id) ON DELETE SET NULL;

-- Read-only observations of the CPA credential inventory. This lets mapping and
-- diagnostics see which credentials CPA actually serves without asking an owner
-- to import the same account twice. No token material is stored: identity is the
-- keyed HMAC used everywhere else.
CREATE TABLE tsw_cpa_credentials (
    credential_id text PRIMARY KEY CHECK (length(credential_id) BETWEEN 1 AND 512),
    credential_name text NOT NULL CHECK (length(credential_name) BETWEEN 1 AND 200),
    provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    observed_revision text NOT NULL CHECK (length(observed_revision) BETWEEN 1 AND 256),
    email_hmac bytea CHECK (email_hmac IS NULL OR octet_length(email_hmac) = 32),
    email_key_version integer CHECK (email_key_version IS NULL OR email_key_version > 0),
    disabled boolean NOT NULL DEFAULT false,
    remote_status text CHECK (remote_status IS NULL OR length(remote_status) BETWEEN 1 AND 64),
    present boolean NOT NULL DEFAULT true,
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    last_sync_id uuid,
    CHECK ((email_hmac IS NULL) = (email_key_version IS NULL))
);
CREATE INDEX tsw_cpa_credentials_identity_idx ON tsw_cpa_credentials(email_key_version, email_hmac)
    WHERE email_hmac IS NOT NULL AND present;
CREATE INDEX tsw_cpa_credentials_provider_idx ON tsw_cpa_credentials(provider, last_observed_at DESC);

-- One row per completed inventory sync so a diagnostic can cite when the view
-- was last refreshed instead of assuming it is current.
CREATE TABLE tsw_cpa_sync_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    outcome text NOT NULL DEFAULT 'running' CHECK (outcome IN ('running','succeeded','failed')),
    credential_count integer NOT NULL DEFAULT 0 CHECK (credential_count >= 0),
    error_code text CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128)
);
CREATE INDEX tsw_cpa_sync_runs_recent_idx ON tsw_cpa_sync_runs(started_at DESC);

-- One row per remote CPA mutation a rotation case needs. The receipt columns
-- record what CPA actually confirmed, so a restart never repeats a write whose
-- outcome is already observed.
CREATE TABLE tsw_cpa_rotation_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL REFERENCES tsw_cpa_rotation_cases(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('quarantine','delivery')),
    credential_name text NOT NULL CHECK (length(credential_name) BETWEEN 1 AND 200),
    credential_revision text NOT NULL CHECK (length(credential_revision) BETWEEN 1 AND 256),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_flight','applied','failed','unknown')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claim_token uuid,
    claimed_at timestamptz,
    remote_status integer CHECK (remote_status IS NULL OR remote_status BETWEEN 100 AND 599),
    last_error_code text CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
    applied_at timestamptz,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (case_id, kind),
    CHECK ((status = 'in_flight') = (claim_token IS NOT NULL))
);
CREATE INDEX tsw_cpa_rotation_deliveries_pending_idx ON tsw_cpa_rotation_deliveries(case_id)
    WHERE status IN ('pending','in_flight');

-- +goose Down
ALTER TABLE tsw_cpa_degradation_events DROP CONSTRAINT tsw_cpa_degradation_events_rotation_case_fk;
DROP TABLE tsw_cpa_rotation_deliveries;
DROP TABLE tsw_cpa_sync_runs;
DROP TABLE tsw_cpa_credentials;
DROP TABLE tsw_cpa_rotation_cases;
DROP TABLE tsw_cpa_automation_workspace_settings;
DROP TABLE tsw_cpa_automation_settings;
