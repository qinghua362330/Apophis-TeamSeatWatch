package runtime

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

type borrowedTargetRoute struct{ *egress.Lease }

func (borrowedTargetRoute) Release() {}

// Manual frozen intents cannot silently reuse a pre-binding Personal generation.
// Explicit account login prepares a new generation before a new intent is made.
func (h *OwnerAuthHandler) manualTargetRoute(ctx context.Context, target uuid.UUID) (context.Context, func(), error) {
	if h.targetRoutes == nil {
		return ctx, func() {}, nil
	}
	routed, fresh, release, err := h.targetRoutes.Prepare(ctx, target)
	if err != nil {
		return ctx, func() {}, err
	}
	if fresh {
		release()
		return ctx, func() {}, platform.ErrRotationCredentialsUnavailable
	}
	return routed, release, nil
}

func (h *OwnerAuthHandler) accountRoutes() accountsession.RouteProvider {
	if h.targetRoutes == nil {
		return nil
	}
	return h.targetRoutes
}

// verifyCPARoute fences both new deliveries and retries against the account's
// current route. A checkpoint from before policy activation cannot be uploaded.
func (h *OwnerAuthHandler) verifyCPARoute(ctx context.Context, target uuid.UUID, credential cpacred.Credential) error {
	if h.targetRoutes == nil {
		return nil
	}
	enabled, err := h.targetRoutes.Enabled(ctx)
	if err != nil || !enabled {
		return err
	}
	routed, fresh, release, err := h.targetRoutes.Prepare(ctx, target)
	if err != nil {
		return err
	}
	defer release()
	if fresh {
		return platform.ErrRotationCredentialsUnavailable
	}
	if err = h.targetRoutes.Validate(routed, target); err != nil {
		return err
	}
	return h.targetRoutes.VerifyCredential(routed, target, credential)
}

// Adopt an existing CPA route before issuing an account's first managed login.
// Unknown remote proxies pause adoption rather than moving the account's IP.
func (h *OwnerAuthHandler) seedCPATargetRoute(ctx context.Context, target uuid.UUID, file cpacred.File) error {
	if h.targetRoutes == nil {
		return nil
	}
	enabled, err := h.targetRoutes.Enabled(ctx)
	if err != nil || !enabled {
		return err
	}
	if file.ProxyDigest == "" {
		return h.targetRoutes.Pause(ctx, target, "cpa_proxy_missing")
	}
	var node uuid.UUID
	err = h.pool.QueryRow(ctx, `SELECT id FROM tsw_proxy_pool_nodes WHERE encode(endpoint_digest,'hex')=$1 AND NOT retired`, file.ProxyDigest).Scan(&node)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return h.targetRoutes.Pause(ctx, target, "cpa_proxy_unknown")
		}
		return err
	}
	if err = h.targetRoutes.SeedExisting(ctx, target, node); err != nil {
		_ = h.targetRoutes.Pause(ctx, target, "cpa_proxy_conflict")
		return err
	}
	return nil
}

// Reconcile existing CPA routes before background workers can log in accounts.
func (h *OwnerAuthHandler) reconcileCPATargetRoutes(ctx context.Context, files []cpacred.File) error {
	if h.targetRoutes == nil {
		return nil
	}
	enabled, err := h.targetRoutes.Enabled(ctx)
	if err != nil || !enabled {
		return err
	}
	for _, file := range files {
		if file.Provider != "codex" || file.Email == "" {
			continue
		}
		var target uuid.UUID
		err = h.pool.QueryRow(ctx, `SELECT id FROM tsw_target_accounts WHERE lower(identifier)=lower($1) AND status='active'`, file.Email).Scan(&target)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		actual, readErr := h.cpaRenewalIdentity(ctx, file)
		if readErr != nil {
			return readErr
		}
		if err = h.seedCPATargetRoute(ctx, target, actual); err != nil {
			return err
		}
	}
	return nil
}
