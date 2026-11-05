// Package accountroute pins target-account authentication to one verified
// egress node. A binding is immutable by default: unhealthy or drifted routes
// pause the account instead of silently moving a login to another IP.
package accountroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
)

var (
	ErrDisabled        = errors.New("account route policy disabled")
	ErrPaused          = errors.New("account route binding paused")
	ErrNoBinding       = errors.New("account route binding unavailable")
	ErrBindingConflict = errors.New("account route binding conflict")
)

type bindingGenerationContextKey struct{}

type Binding struct {
	TargetID            uuid.UUID
	NodeID              uuid.UUID
	Generation          uuid.UUID
	ExpectedFingerprint []byte
	IPKeyVersion        int16
	SessionGeneration   *uuid.UUID
	Paused              bool
	Endpoint            string
}

type Store struct {
	Pool    *pgxpool.Pool
	KeyRing auth.KeyRing
	Manager *egress.Manager
}

// RouteProvider is intentionally structural so accountsession does not import
// this package and create a cycle.
type RouteProvider interface {
	Prepare(context.Context, uuid.UUID) (context.Context, bool, func(), error)
	Validate(context.Context, uuid.UUID) error
	Published(context.Context, pgx.Tx, uuid.UUID) error
}

func (s Store) Enabled(ctx context.Context) (bool, error) {
	if s.Pool == nil {
		return false, ErrNoBinding
	}
	var enabled bool
	err := s.Pool.QueryRow(ctx, `SELECT enabled FROM public.tsw_account_route_settings WHERE id=true`).Scan(&enabled)
	return enabled, err
}

func (s Store) EnsureBinding(ctx context.Context, targetID uuid.UUID) (Binding, error) {
	var b Binding
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return b, err
	}
	defer tx.Rollback(ctx)
	var endpointKey int16
	var endpointNonce, endpointCiphertext []byte
	err = tx.QueryRow(ctx, `SELECT b.target_account_id,COALESCE(b.node_id,'00000000-0000-0000-0000-000000000000'::uuid),b.binding_generation,b.expected_ip_fingerprint,COALESCE(b.ip_key_version,0),b.session_generation,b.paused,COALESCE(n.endpoint_key_version,0),COALESCE(n.endpoint_nonce,''::bytea),COALESCE(n.endpoint_ciphertext,''::bytea)
FROM public.tsw_account_route_bindings b LEFT JOIN public.tsw_proxy_pool_nodes n ON n.id=b.node_id WHERE b.target_account_id=$1 FOR SHARE OF b`, targetID).
		Scan(&b.TargetID, &b.NodeID, &b.Generation, &b.ExpectedFingerprint, &b.IPKeyVersion, &b.SessionGeneration, &b.Paused, &endpointKey, &endpointNonce, &endpointCiphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingCPA bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_cpa_credentials c JOIN tsw_target_accounts a ON a.identifier_key_version=c.email_key_version AND a.identifier_hmac=c.email_hmac WHERE a.id=$1 AND c.present AND c.provider='codex')`, targetID).Scan(&existingCPA); err != nil {
			return b, err
		}
		if existingCPA {
			return b, ErrNoBinding
		}
		err = tx.QueryRow(ctx, `INSERT INTO public.tsw_account_route_bindings(target_account_id,node_id,binding_generation)
SELECT $1,n.id,gen_random_uuid() FROM public.tsw_proxy_pool_nodes n LEFT JOIN public.tsw_proxy_pool_sources src ON src.id=n.source_id WHERE n.state='healthy' AND n.retired=false AND n.session_type<>'rotating' AND (n.stable_until IS NULL OR n.stable_until>clock_timestamp()) AND (n.source_id IS NULL OR src.enabled) ORDER BY random() LIMIT 1 ON CONFLICT (target_account_id) DO NOTHING
RETURNING target_account_id,node_id,binding_generation,expected_ip_fingerprint,COALESCE(ip_key_version,0),session_generation,paused`, targetID).
			Scan(&b.TargetID, &b.NodeID, &b.Generation, &b.ExpectedFingerprint, &b.IPKeyVersion, &b.SessionGeneration, &b.Paused)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT target_account_id,COALESCE(node_id,'00000000-0000-0000-0000-000000000000'::uuid),binding_generation,expected_ip_fingerprint,COALESCE(ip_key_version,0),session_generation,paused FROM public.tsw_account_route_bindings WHERE target_account_id=$1 FOR UPDATE`, targetID).Scan(&b.TargetID, &b.NodeID, &b.Generation, &b.ExpectedFingerprint, &b.IPKeyVersion, &b.SessionGeneration, &b.Paused)
			if errors.Is(err, pgx.ErrNoRows) {
				return b, ErrNoBinding
			}
		}
		if err != nil {
			return b, err
		}
	} else if err != nil {
		return b, err
	}
	if len(endpointCiphertext) == 0 && b.NodeID != uuid.Nil {
		if err = tx.QueryRow(ctx, `SELECT endpoint_key_version,endpoint_nonce,endpoint_ciphertext FROM public.tsw_proxy_pool_nodes WHERE id=$1`, b.NodeID).Scan(&endpointKey, &endpointNonce, &endpointCiphertext); err != nil {
			return b, err
		}
	}
	if len(endpointCiphertext) > 0 {
		plain, decryptErr := auth.DecryptSecret(uint16(endpointKey), endpointNonce, endpointCiphertext, s.KeyRing)
		if decryptErr != nil {
			return b, decryptErr
		}
		b.Endpoint = string(plain)
	}
	if err = tx.Commit(ctx); err != nil {
		return b, err
	}
	if b.Paused {
		return b, ErrPaused
	}
	return b, nil
}

// Bind records the first successful measured exit atomically. Existing
// bindings are never reassigned here.
func (s Store) Bind(ctx context.Context, targetID uuid.UUID, outer *egress.Lease) (*egress.Lease, error) {
	b, err := s.EnsureBinding(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if s.Manager == nil {
		return nil, ErrNoBinding
	}
	if b.NodeID == uuid.Nil {
		return nil, ErrPaused
	}
	lease, err := s.Manager.PinLease(ctx, outer, b.NodeID.String(), b.ExpectedFingerprint)
	if err != nil {
		if errors.Is(err, egress.ErrEgressDrift) {
			_ = s.Pause(ctx, targetID, "egress_drift")
		}
		return nil, err
	}
	lease.SetDriftHandler(func(_ context.Context) {
		pauseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = s.Pause(pauseCtx, targetID, "egress_drift")
	})
	if len(b.ExpectedFingerprint) == 0 {
		var keyVersion int16
		if lease.KeyVersion() != "" {
			var parsed int
			_, _ = fmt.Sscanf(lease.KeyVersion(), "%d", &parsed)
			keyVersion = int16(parsed)
		}
		fp := lease.Fingerprint()
		result, updateErr := s.Pool.Exec(ctx, `UPDATE public.tsw_account_route_bindings SET expected_ip_fingerprint=$2,ip_key_version=$3,updated_at=now() WHERE target_account_id=$1 AND binding_generation=$4 AND expected_ip_fingerprint IS NULL`, targetID, fp[:], keyVersion, b.Generation)
		if updateErr != nil {
			err = updateErr
			lease.Release()
			return nil, err
		}
		if result.RowsAffected() != 1 {
			var existing []byte
			if readErr := s.Pool.QueryRow(ctx, `SELECT expected_ip_fingerprint FROM public.tsw_account_route_bindings WHERE target_account_id=$1`, targetID).Scan(&existing); readErr != nil || !bytes.Equal(existing, fp[:]) {
				lease.Release()
				return nil, ErrBindingConflict
			}
		}
	}
	return lease, nil
}

func (s Store) Acquire(ctx context.Context, targetID uuid.UUID) (*egress.Lease, error) {
	outer, err := s.Manager.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	lease, err := s.Bind(ctx, targetID, outer)
	if err != nil {
		outer.Release()
		return nil, err
	}
	return lease, nil
}

func (s Store) Prepare(ctx context.Context, targetID uuid.UUID) (context.Context, bool, func(), error) {
	enabled, err := s.Enabled(ctx)
	if err != nil {
		return ctx, false, nil, err
	}
	if !enabled {
		return ctx, false, func() {}, nil
	}
	b, err := s.EnsureBinding(ctx, targetID)
	if err != nil {
		return ctx, false, nil, err
	}
	targetKey := targetID.String()
	ctx = egress.WithTarget(ctx, targetKey)
	ctx = context.WithValue(ctx, bindingGenerationContextKey{}, b.Generation)
	forceFresh := b.SessionGeneration == nil
	if !forceFresh {
		var current uuid.UUID
		if queryErr := s.Pool.QueryRow(ctx, `SELECT generation FROM public.tsw_target_personal_sessions WHERE target_account_id=$1`, targetID).Scan(&current); queryErr != nil || current != *b.SessionGeneration {
			forceFresh = true
		}
	}
	if borrowed, ok := egress.BorrowedLease(ctx, targetKey); ok && borrowed != nil {
		ctx = egress.WithBorrowedLease(ctx, targetKey, borrowed)
		return ctx, forceFresh, func() {}, nil
	}
	lease, err := s.Acquire(ctx, targetID)
	if err != nil {
		return ctx, false, nil, err
	}
	ctx = egress.WithBorrowedLease(ctx, targetKey, lease)
	return ctx, forceFresh, lease.Release, nil
}

func (s Store) Published(ctx context.Context, tx pgx.Tx, targetID uuid.UUID) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM public.tsw_account_route_settings WHERE id=true`).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	lease, ok := egress.BorrowedLease(ctx, targetID.String())
	if !ok || lease == nil {
		return ErrNoBinding
	}
	var generation uuid.UUID
	var expected []byte
	if err := tx.QueryRow(ctx, `SELECT binding_generation,expected_ip_fingerprint FROM public.tsw_account_route_bindings WHERE target_account_id=$1 FOR UPDATE`, targetID).Scan(&generation, &expected); err != nil {
		return err
	}
	if snapshot, ok := ctx.Value(bindingGenerationContextKey{}).(uuid.UUID); !ok || snapshot != generation {
		return ErrBindingConflict
	}
	fp := lease.Fingerprint()
	if len(expected) == 0 || !bytes.Equal(expected, fp[:]) {
		return ErrBindingConflict
	}
	result, err := tx.Exec(ctx, `UPDATE public.tsw_target_personal_sessions p SET proxy_binding_generation=b.binding_generation
FROM public.tsw_account_route_bindings b WHERE p.target_account_id=$1 AND b.target_account_id=p.target_account_id AND b.paused=false AND b.binding_generation=$2`, targetID, generation)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrBindingConflict
	}
	result, err = tx.Exec(ctx, `UPDATE public.tsw_account_route_bindings b SET session_generation=p.generation
FROM public.tsw_target_personal_sessions p WHERE b.target_account_id=$1 AND p.target_account_id=b.target_account_id AND b.paused=false AND b.binding_generation=$2`, targetID, generation)
	if err == nil && result.RowsAffected() != 1 {
		return ErrBindingConflict
	}
	return err
}

func (s Store) Validate(ctx context.Context, targetID uuid.UUID) error {
	enabled, err := s.Enabled(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	lease, ok := egress.BorrowedLease(ctx, targetID.String())
	if !ok || lease == nil {
		return ErrNoBinding
	}
	var generation uuid.UUID
	var paused bool
	var expected []byte
	if err = s.Pool.QueryRow(ctx, `SELECT binding_generation,paused,expected_ip_fingerprint FROM public.tsw_account_route_bindings WHERE target_account_id=$1`, targetID).Scan(&generation, &paused, &expected); err != nil {
		return err
	}
	snapshot, snapshotOK := ctx.Value(bindingGenerationContextKey{}).(uuid.UUID)
	fp := lease.Fingerprint()
	if paused || !snapshotOK || generation != snapshot || !bytes.Equal(expected, fp[:]) {
		return ErrBindingConflict
	}
	if err = lease.Remeasure(ctx); errors.Is(err, egress.ErrEgressDrift) {
		_ = s.Pause(ctx, targetID, "egress_drift")
		return err
	}
	return err
}

func (s Store) WithCredential(ctx context.Context, targetID uuid.UUID, credential cpacred.Credential) (cpacred.Credential, error) {
	b, err := s.EnsureBinding(ctx, targetID)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if b.Endpoint == "" {
		return cpacred.Credential{}, ErrNoBinding
	}
	if snapshot, ok := ctx.Value(bindingGenerationContextKey{}).(uuid.UUID); ok && snapshot != b.Generation {
		return cpacred.Credential{}, ErrBindingConflict
	}
	if credential.RouteGeneration != "" && credential.RouteGeneration != b.Generation.String() {
		return cpacred.Credential{}, ErrBindingConflict
	}
	credential, err = cpacred.WithProxy(credential, b.Endpoint)
	if err != nil {
		return cpacred.Credential{}, err
	}
	credential.RouteGeneration = b.Generation.String()
	return credential, nil
}

func (s Store) VerifyCredential(ctx context.Context, targetID uuid.UUID, credential cpacred.Credential) error {
	b, err := s.EnsureBinding(ctx, targetID)
	if err != nil {
		return err
	}
	if b.SessionGeneration == nil || credential.RouteGeneration != b.Generation.String() || b.Endpoint == "" {
		return ErrBindingConflict
	}
	var current uuid.UUID
	if err = s.Pool.QueryRow(ctx, `SELECT generation FROM public.tsw_target_personal_sessions WHERE target_account_id=$1`, targetID).Scan(&current); err != nil || current != *b.SessionGeneration {
		return ErrBindingConflict
	}
	var payload struct {
		ProxyURL string `json:"proxy_url"`
	}
	if err = json.Unmarshal(credential.AuthFile, &payload); err != nil || payload.ProxyURL != b.Endpoint {
		return ErrBindingConflict
	}
	return nil
}

func (s Store) Endpoint(ctx context.Context, targetID uuid.UUID) (string, error) {
	var key int16
	var nonce, ciphertext []byte
	err := s.Pool.QueryRow(ctx, `SELECT n.endpoint_key_version,n.endpoint_nonce,n.endpoint_ciphertext FROM public.tsw_account_route_bindings b JOIN public.tsw_proxy_pool_nodes n ON n.id=b.node_id WHERE b.target_account_id=$1 AND b.paused=false`, targetID).Scan(&key, &nonce, &ciphertext)
	if err != nil {
		return "", err
	}
	plain, err := auth.DecryptSecret(uint16(key), nonce, ciphertext, s.KeyRing)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SeedExisting is an explicit migration hook for already-imported CPA files.
func (s Store) SeedExisting(ctx context.Context, targetID, nodeID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO public.tsw_account_route_bindings(target_account_id,node_id,binding_generation) VALUES($1,$2,gen_random_uuid()) ON CONFLICT (target_account_id) DO NOTHING`, targetID, nodeID)
	if err != nil {
		return err
	}
	var current uuid.UUID
	if err = s.Pool.QueryRow(ctx, `SELECT node_id FROM public.tsw_account_route_bindings WHERE target_account_id=$1`, targetID).Scan(&current); err != nil {
		return err
	}
	if current != nodeID {
		return ErrBindingConflict
	}
	return nil
}

func (s Store) Pause(ctx context.Context, targetID uuid.UUID, reason string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO public.tsw_account_route_bindings(target_account_id,node_id,binding_generation,paused,paused_reason)
VALUES($1,NULL,gen_random_uuid(),true,$2) ON CONFLICT (target_account_id) DO UPDATE SET paused=true,paused_reason=EXCLUDED.paused_reason,updated_at=now()`, targetID, reason)
	return err
}

func (s Store) Generation(ctx context.Context, targetID uuid.UUID) (uuid.UUID, error) {
	b, err := s.EnsureBinding(ctx, targetID)
	return b.Generation, err
}
