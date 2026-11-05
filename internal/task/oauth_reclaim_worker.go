package task

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"strings"
	"time"

	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	oauthdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/oauth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

func (w *Worker) runDeliveryReclaim(ctx context.Context, item Task, lease *egress.Lease) error {
	target, err := w.Store.DeliveryReclaimTarget(ctx, item)
	if err != nil {
		return err
	}
	attempt, err := w.Store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		return err
	}
	unknown := func(code string) platform.DeliveryLiveness {
		return platform.DeliveryLiveness{Status: oauthdomain.ProbeUnknown, ErrorCode: code, Origin: "reclaim", ObservedAt: time.Now().UTC()}
	}
	finish := func(generated platform.DeliveryCredentialSet, probe platform.DeliveryLiveness, tier string, noAction, unavailable bool) error {
		if err := w.Store.RecordDeliveryReclaimStage(ctx, item, attempt, "publish", tier); err != nil {
			return err
		}
		if err := w.Store.FinishDeliveryReclaim(ctx, item, attempt, target, generated, probe, tier, noAction, unavailable); err != nil {
			if errors.Is(err, ErrDeliveryAttemptSuperseded) {
				return ErrAttemptFailed
			}
			return err
		}
		if !noAction && (tier == "unrecoverable" || probe.Status != oauthdomain.ProbeOK) {
			return ErrAttemptFailed
		}
		return nil
	}
	if w.DeliveryAdapter == nil {
		return finish(platform.DeliveryCredentialSet{}, unknown("oauth_reclaim_unavailable"), "unrecoverable", false, false)
	}
	adapter, err := w.DeliveryAdapter(lease.Client(), platform.Credentials{LoginIdentifier: target.TargetIdentifier, Password: target.Password})
	if err != nil {
		return finish(platform.DeliveryCredentialSet{}, unknown("oauth_reclaim_configuration_invalid"), "unrecoverable", false, false)
	}
	if err := w.Store.RecordDeliveryReclaimStage(ctx, item, attempt, "probe", ""); err != nil {
		return err
	}
	probe, probeErr := adapter.CheckDeliveryLiveness(ctx, target.AccessToken, target.PlatformWorkspace)
	probe = normalizeReclaimProbe(probe, probeErr)

	if err := lease.Remeasure(ctx); err != nil {
		probe = unknown("proxy_egress_drift")
	}
	if probe.Status == oauthdomain.ProbeOK && oauthdomain.ProbeAuthoritative(probe.Status, probe.HTTPStatus) {
		return finish(platform.DeliveryCredentialSet{}, probe, "probe_ok", true, false)
	}
	if probe.Status != oauthdomain.ProbeAuthError || probe.HTTPStatus != 401 {
		tier := "unrecoverable"
		if probe.Status == oauthdomain.ProbeUnknown || probe.Status == oauthdomain.ProbeTransientFailure || probe.Status == oauthdomain.ProbeRateLimited || probe.HTTPStatus == 0 {
			tier = "token_refresh"
		}
		return finish(platform.DeliveryCredentialSet{}, probe, tier, false, false)
	}

	// Refresh is attempted only after an authoritative 401. It uses the same
	// lease-owned client and is followed by a probe on the same measured exit.
	if err := w.Store.RecordDeliveryReclaimStage(ctx, item, attempt, "refresh", "token_refresh"); err != nil {
		return err
	}
	var refreshed platform.DeliveryCredentialSet
	var refreshErr error
	if w.DeliveryRefresh != nil {
		refreshed, refreshErr = w.DeliveryRefresh(ctx, lease.Client(), target.RefreshToken)
	} else {
		refreshed, refreshErr = platform.RefreshDeliveryCredentials(ctx, lease.Client(), target.RefreshToken)
	}
	if refreshErr == nil {
		refreshed, refreshErr = platform.ValidateDeliveryIdentity(refreshed, target.PlatformWorkspace)
	}
	if refreshErr == nil {
		if err := lease.Remeasure(ctx); err != nil {
			refreshErr = err
		} else {
			refreshProbe, refreshProbeErr := adapter.CheckDeliveryLiveness(ctx, refreshed.AccessToken, target.PlatformWorkspace)
			refreshProbe = normalizeReclaimProbe(refreshProbe, refreshProbeErr)
			if err := lease.Remeasure(ctx); err != nil {
				refreshProbe = unknown("proxy_egress_drift")
			}
			if refreshProbe.Status == oauthdomain.ProbeOK && oauthdomain.ProbeAuthoritative(refreshProbe.Status, refreshProbe.HTTPStatus) {
				return finish(refreshed, refreshProbe, "token_refresh", false, false)
			}
			if refreshProbe.Status != oauthdomain.ProbeAuthError || refreshProbe.HTTPStatus != 401 {
				return finish(platform.DeliveryCredentialSet{}, refreshProbe, "token_refresh", false, false)
			}
		}
	}

	if err := w.Store.RecordDeliveryReclaimStage(ctx, item, attempt, "relogin", "full_relogin"); err != nil {
		return err
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	// A fresh browser context is required for the password/TOTP leg while the
	// HTTP transport remains lease-bound to the same egress route.
	lease.Client().Jar = nil
	environment, err := (accountsession.Store{Pool: w.Store.pool, KeyRing: w.Store.keyRing, Routes: w.AccountRoutes}).Environment(ctx, uuid.MustParse(target.TargetAccountID))
	if err != nil {
		return err
	}
	generated, reloginErr := adapter.CreateDeliveryCredentials(ctx, platform.DeliveryCredentialRequest{
		Environment: environment,
		Identifier:  target.TargetIdentifier,
		Password:    target.Password,
		TOTPSecret:  target.TOTPSecret,
		Recovery:    target.RecoverySecret,
		Workspace:   target.PlatformWorkspace,
	})
	if reloginErr != nil {
		return finish(platform.DeliveryCredentialSet{}, platform.DeliveryLiveness{Status: oauthdomain.ProbeUnknown, ErrorCode: "full_relogin_failed", Origin: "reclaim", ObservedAt: time.Now().UTC()}, "unrecoverable", false, true)
	}
	generated, reloginErr = platform.ValidateDeliveryIdentity(generated, target.PlatformWorkspace)
	if reloginErr != nil {
		return finish(platform.DeliveryCredentialSet{}, platform.DeliveryLiveness{Status: oauthdomain.ProbeUnknown, ErrorCode: "full_relogin_identity_invalid", Origin: "reclaim", ObservedAt: time.Now().UTC()}, "unrecoverable", false, true)
	}
	if err := lease.Remeasure(ctx); err != nil {
		return finish(platform.DeliveryCredentialSet{}, unknown("proxy_egress_drift"), "unrecoverable", false, true)
	}
	if err := w.Store.RecordDeliveryReclaimStage(ctx, item, attempt, "publish", "full_relogin"); err != nil {
		return err
	}
	finalProbe, finalProbeErr := adapter.CheckDeliveryLiveness(ctx, generated.AccessToken, target.PlatformWorkspace)
	finalProbe = normalizeReclaimProbe(finalProbe, finalProbeErr)

	if err := lease.Remeasure(ctx); err != nil {
		finalProbe = unknown("proxy_egress_drift")
	}
	if finalProbe.Status == oauthdomain.ProbeOK && oauthdomain.ProbeAuthoritative(finalProbe.Status, finalProbe.HTTPStatus) {
		return finish(generated, finalProbe, "full_relogin", false, false)
	}
	return finish(platform.DeliveryCredentialSet{}, finalProbe, "full_relogin", false, true)
}

func normalizeReclaimProbe(probe platform.DeliveryLiveness, probeErr error) platform.DeliveryLiveness {
	if probe.ObservedAt.IsZero() {
		probe.ObservedAt = time.Now().UTC()
	}
	probe.Origin = "reclaim"
	if probeErr != nil && strings.TrimSpace(probe.ErrorCode) == "" {
		probe.ErrorCode = "oauth_reclaim_probe_failed"
	}
	if probe.Status == "" {
		probe.Status = oauthdomain.ProbeUnknown
	}
	return probe
}
