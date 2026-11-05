-- +goose Up
CREATE TABLE public.tsw_account_route_settings (
 id boolean PRIMARY KEY DEFAULT true CHECK (id=true),
 enabled boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.tsw_account_route_settings(id,enabled) VALUES(true,false) ON CONFLICT (id) DO NOTHING;
ALTER TABLE public.tsw_target_personal_sessions ADD COLUMN proxy_binding_generation uuid;
CREATE TABLE public.tsw_account_route_bindings (
 target_account_id uuid PRIMARY KEY REFERENCES public.tsw_target_accounts(id) ON DELETE CASCADE,
 node_id uuid REFERENCES public.tsw_proxy_pool_nodes(id) ON DELETE RESTRICT,
 binding_generation uuid NOT NULL DEFAULT gen_random_uuid(),
 expected_ip_fingerprint bytea CHECK (expected_ip_fingerprint IS NULL OR octet_length(expected_ip_fingerprint)=32),
 ip_key_version smallint,
 session_generation uuid,
 paused boolean NOT NULL DEFAULT false,
 paused_reason text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tsw_account_route_bindings_node_idx ON public.tsw_account_route_bindings(node_id);
REVOKE ALL ON public.tsw_account_route_settings,public.tsw_account_route_bindings FROM PUBLIC;
-- +goose Down
DROP TABLE public.tsw_account_route_bindings;
DROP TABLE public.tsw_account_route_settings;
ALTER TABLE public.tsw_target_personal_sessions DROP COLUMN proxy_binding_generation;
