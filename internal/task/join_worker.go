package task

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	oauthdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/oauth"

	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

func (w *Worker) runJoin(ctx context.Context, item Task, lease *egress.Lease) error {
	if w.Joiner == nil {
		return w.finishJoinFailure(ctx, item, "platform_configuration_invalid", "prepare", "failed")
	}
	target, err := w.Store.JoinTarget(ctx, item)
	if err != nil {
		return w.finishJoinFailure(ctx, item, "platform_credential_unavailable", "credential_resolution", "failed")
	}
	if target.OAuthAuthorized && target.InvitationConfirmed {
		return w.runWorkspaceAuthorization(ctx, item, lease, target)
	}
	if target.PlatformRequestMayHaveReached {
		return w.runJoinReconcile(ctx, item, lease)
	}
	joiner, err := w.Joiner(ctx, lease.Client(), target)
	if err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "workspace_authority_changed", "workspace_authority_changed", "send_invitation", nil)
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "proxy_egress_drift", "proxy_egress_drift", "before_join_request", nil)
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	// Fence the first POST in durable state before sending it. A worker crash
	// after this point must read the invitation facts rather than send again.
	if err := w.Store.MarkJoinSideEffectStarted(ctx, item, "send_invitation"); err != nil {
		return err
	}
	invitation, inviteErr := joiner.Invite(ctx, target.PlatformWorkspace, target.TargetIdentifier)
	if err := w.recordJoinStage(ctx, item, "send_invitation", invitation, inviteErr); err != nil {
		return err
	}
	if inviteErr != nil || !invitation.Success {
		code := invitation.ErrorCode
		if code == "" {
			code = "invitation_unconfirmed"
		}
		status := "failed"
		if invitation.RequestMayHaveEffect {
			status = "unknown"
		}
		return w.finishJoin(ctx, item, target, status, code, code, "send_invitation", nil)
	}
	return w.Store.FinishInvitation(ctx, item, target)
}

// Step 3 follows the account's OAuth login and selects the frozen workspace.
// No workspace request/accept API is issued by this operation flow.
func (w *Worker) runWorkspaceAuthorization(ctx context.Context, item Task, lease *egress.Lease, target JoinTarget) error {
	ctx, stop, err := w.keepOAuthLease(ctx, item)
	if err != nil {
		return err
	}
	defer stop()
	login, err := w.Store.JoinLoginTarget(ctx, item)
	if err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "platform_credential_unavailable", "platform_credential_unavailable", "oauth_login", nil)
	}
	if w.DeliveryAdapter == nil {
		return w.finishJoin(ctx, item, target, "blocked", "platform_configuration_invalid", "platform_configuration_invalid", "oauth_login", nil)
	}
	generator, err := w.DeliveryAdapter(lease.Client(), platform.Credentials{LoginIdentifier: login.TargetIdentifier, Password: login.Password})
	if err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "platform_configuration_invalid", "platform_configuration_invalid", "oauth_login", nil)
	}
	sessions := accountsession.Store{Pool: w.Store.pool, KeyRing: w.Store.keyRing, Routes: w.AccountRoutes}
	refresher := platform.PersonalWebRefresher{Client: func(context.Context) (*http.Client, func(), error) { return lease.Client(), nil, nil }}
	personal, err := sessions.Ensure(ctx, uuid.MustParse(target.TargetID), refresher, false, nil)
	if err != nil || personal.Status != "ready" {
		return w.finishJoin(ctx, item, target, "blocked", "platform_credential_unavailable", "platform_credential_unavailable", "oauth_login", nil)
	}
	generate := func(session platform.PersonalSession) (platform.DeliveryCredentialSet, error) {
		identity, identityErr := platform.PersonalSessionIdentity(session)
		if identityErr != nil || !strings.EqualFold(identity.Identifier, login.TargetIdentifier) || login.PlatformSubjectID != "" && login.PlatformSubjectID != identity.SubjectID {
			return platform.DeliveryCredentialSet{}, platform.ErrPersonalIdentityUnavailable
		}
		login.PlatformSubjectID = identity.SubjectID
		return generator.CreateDeliveryCredentials(ctx, platform.DeliveryCredentialRequest{Environment: personal.Environment, Identifier: login.TargetIdentifier, Password: login.Password, TOTPSecret: login.TOTPSecret, Recovery: login.RecoverySecret, Workspace: target.PlatformWorkspace, PersonalSession: &session})
	}
	credentials, err := generate(personal.Session)
	if errors.Is(err, platform.ErrBrowserSessionExpired) {
		personal, err = sessions.Ensure(ctx, uuid.MustParse(target.TargetID), refresher, true, nil)
		if err == nil && personal.Status == "ready" {
			credentials, err = generate(personal.Session)
		} else {
			err = platform.ErrBrowserSessionExpired
		}
	}
	if err != nil {
		code := platform.OAuthFailureCode(err)
		return w.finishJoin(ctx, item, target, "blocked", code, code, "oauth_login", nil)
	}
	if err = lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "proxy_egress_drift", "proxy_egress_drift", "oauth_login", nil)
	}
	if err = w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	probe, err := generator.CheckDeliveryLiveness(ctx, credentials.AccessToken, target.PlatformWorkspace)
	if probe.ObservedAt.IsZero() {
		probe.ObservedAt = time.Now().UTC()
	}
	if err != nil || probe.Status != oauthdomain.ProbeOK || !validDeliveryCredentials(login, credentials, probe) {
		return w.finishJoin(ctx, item, target, "blocked", "oauth_probe_failed", "oauth_probe_failed", "oauth_login", nil)
	}
	// Use the OAuth-confirmed subject to read the real premium member. This read
	// validates the resulting relationship; it does not authorize another join.
	joiner, err := w.Joiner(ctx, lease.Client(), target)
	if err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "workspace_authority_changed", "workspace_authority_changed", "oauth_login", nil)
	}
	member, err := joiner.VerifyMembership(ctx, target.PlatformWorkspace, target.TargetIdentifier, credentials.PlatformSubjectID)
	if err != nil || !member.Complete || !member.Present {
		return w.finishJoin(ctx, item, target, "unknown", "member_not_confirmed", "member_not_confirmed", "oauth_login", nil)
	}
	if member.SeatType != "prolite" || member.PlatformMemberID != credentials.PlatformSubjectID {
		return w.finishJoin(ctx, item, target, "blocked", "seat_type_mismatch", "seat_type_mismatch", "oauth_login", nil)
	}
	if err = lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "proxy_egress_drift", "proxy_egress_drift", "oauth_login", nil)
	}
	return w.Store.FinishJoinAuthorization(ctx, item, target, member, login, credentials, probe)
}

func (w *Worker) runJoinReconcile(ctx context.Context, item Task, lease *egress.Lease) error {
	if w.Joiner == nil {
		return w.finishJoinReconcile(ctx, item, JoinTarget{}, platform.MembershipResult{ErrorCode: "platform_configuration_invalid"})
	}
	target, err := w.Store.JoinTarget(ctx, item)
	if err != nil {
		return err
	}
	joiner, err := w.Joiner(ctx, lease.Client(), target)
	if err != nil {
		return w.finishJoinReconcile(ctx, item, target, platform.MembershipResult{ErrorCode: "platform_configuration_invalid"})
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoinReconcile(ctx, item, target, platform.MembershipResult{ErrorCode: "proxy_egress_drift"})
	}
	member, verifyErr := joiner.VerifyMembership(ctx, target.PlatformWorkspace, target.TargetIdentifier, target.PlatformSubjectID)
	if verifyErr != nil || !member.Complete {
		member.Complete = false
		member.ErrorCode = "membership_unknown"
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoinReconcile(ctx, item, target, platform.MembershipResult{ErrorCode: "proxy_egress_drift"})
	}
	return w.finishJoinReconcile(ctx, item, target, member)
}

func (w *Worker) recordJoinStage(ctx context.Context, item Task, stage string, receipt platform.JoinAttemptResult, attemptErr error) error {
	if attemptErr != nil {
		receipt.Success = false
		if receipt.ErrorCode == "" {
			receipt.ErrorCode = "transport_failure"
			if receipt.HTTPStatus != 0 {
				receipt.ErrorCode = "incomplete_response"
			}
		}
	}
	return w.Store.RecordJoinStageResult(ctx, item, stage, receipt)
}

func (w *Worker) finishJoin(ctx context.Context, item Task, target JoinTarget, status, outcome, diagnostic, stage string, member *platform.MembershipResult) error {
	if err := w.Store.FinishJoin(ctx, item, target, status, outcome, diagnostic, stage, member); err != nil {
		return err
	}
	if status != "succeeded" {
		return ErrAttemptFailed
	}
	return nil
}

func (w *Worker) finishJoinFailure(ctx context.Context, item Task, diagnostic, stage, status string) error {
	target, err := w.Store.JoinTarget(ctx, item)
	if err != nil {
		return err
	}
	return w.finishJoin(ctx, item, target, status, diagnostic, diagnostic, stage, nil)
}

func (w *Worker) finishJoinReconcile(ctx context.Context, item Task, target JoinTarget, member platform.MembershipResult) error {
	if target.OperationID == "" {
		return errors.New("join reconciliation target is missing")
	}
	if err := w.Store.FinishJoinReconciliation(ctx, item, target, member); err != nil {
		return err
	}
	return nil
}
