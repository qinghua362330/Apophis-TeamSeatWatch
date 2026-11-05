package task

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	oauthdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/oauth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

func (w *Worker) runDeliveryGeneration(ctx context.Context, item Task, lease *egress.Lease) error {
	ctx, stop, err := w.keepOAuthLease(ctx, item)
	if err != nil {
		return err
	}
	defer stop()
	target, err := w.Store.DeliveryTarget(ctx, item)
	if err != nil {
		return err
	}
	attempt, err := w.Store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		return err
	}
	probeFailure := func(code string) platform.DeliveryLiveness {
		return platform.DeliveryLiveness{Status: oauthdomain.ProbeUnknown, ErrorCode: code, Origin: "generation", ObservedAt: time.Now().UTC()}
	}
	if w.DeliveryAdapter == nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure("oauth_generator_unavailable"))
	}
	generator, err := w.DeliveryAdapter(lease.Client(), platform.Credentials{LoginIdentifier: target.TargetIdentifier, Password: target.Password})
	if err != nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure("oauth_configuration_invalid"))
	}
	sessionStore := accountsession.Store{Pool: w.Store.pool, KeyRing: w.Store.keyRing, Routes: w.AccountRoutes}
	refresher := platform.PersonalWebRefresher{Client: func(context.Context) (*http.Client, func(), error) { return lease.Client(), nil, nil }}
	personal, err := sessionStore.Ensure(ctx, uuid.MustParse(target.TargetAccountID), refresher, false, nil)
	if err != nil || personal.Status != "ready" {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure("account_session_unavailable"))
	}
	input := platform.DeliveryCredentialRequest{Environment: personal.Environment, Identifier: target.TargetIdentifier, Password: target.Password, TOTPSecret: target.TOTPSecret, Recovery: target.RecoverySecret, Workspace: target.PlatformWorkspace, PersonalSession: &personal.Session}
	generated, err := generator.CreateDeliveryCredentials(ctx, input)
	if errors.Is(err, platform.ErrBrowserSessionExpired) {
		// Only confirmed authentication rejection authorizes one fresh login.
		personal, err = sessionStore.Ensure(ctx, uuid.MustParse(target.TargetAccountID), refresher, true, nil)
		if err == nil && personal.Status == "ready" {
			input.PersonalSession = &personal.Session
			generated, err = generator.CreateDeliveryCredentials(ctx, input)
		} else {
			err = platform.ErrBrowserSessionExpired
		}
	}
	if err != nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure(platform.OAuthFailureCode(err)))
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, generated, probeFailure("proxy_egress_drift"))
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	probe, probeErr := generator.CheckDeliveryLiveness(ctx, generated.AccessToken, target.PlatformWorkspace)
	if probe.ObservedAt.IsZero() {
		probe.ObservedAt = time.Now().UTC()
	}
	if probe.Origin == "" {
		probe.Origin = "generation"
	}
	if probeErr != nil && probe.ErrorCode == "" {
		probe.ErrorCode = "oauth_probe_failed"
	}
	if err := lease.Remeasure(ctx); err != nil {
		probe.Status = oauthdomain.ProbeTransientFailure
		probe.HTTPStatus = 0
		probe.ErrorCode = "proxy_egress_drift"
	}
	return w.finishDeliveryAttempt(ctx, item, attempt, target, generated, probe)
}

func (w *Worker) finishDeliveryAttempt(ctx context.Context, item Task, attempt DeliveryAttempt, target DeliveryTarget, generated platform.DeliveryCredentialSet, probe platform.DeliveryLiveness) error {
	if err := w.Store.FinishDeliveryAttempt(ctx, item, attempt, target, generated, probe); err != nil {
		if errors.Is(err, ErrDeliveryAttemptSuperseded) {
			return ErrAttemptFailed
		}
		return err
	}
	if probe.Status != oauthdomain.ProbeOK {
		return ErrAttemptFailed
	}
	return nil
}
