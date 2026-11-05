package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
)

// acquireCPAOAuth performs the legacy same-account browser OAuth grant used to
// repair a CPA credential. It deliberately has no membership or delivery side
// effects; callers decide when this issuer is safe to invoke.
func (h *OwnerAuthHandler) acquireCPAOAuth(ctx context.Context, targetID uuid.UUID, workspaceID, email, name string) (cpacred.Credential, error) {
	if h.pool == nil || h.personalRefresh == nil || h.rotationJoinEgress == nil || h.rotationCredentialAdapters == nil {
		return cpacred.Credential{}, cpacred.ErrNotConfigured
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if targetID == uuid.Nil || workspaceID == "" {
		return cpacred.Credential{}, errors.New("CPA OAuth renewal identity is incomplete")
	}

	if h.targetRoutes != nil {
		routed, _, release, routeErr := h.targetRoutes.Prepare(ctx, targetID)
		if routeErr != nil {
			return cpacred.Credential{}, routeErr
		}
		defer release()
		ctx = routed
	}
	// Read the complete sealed material under one revision. The revision is
	// checked again immediately before and after the remote grant below.
	var identifier string
	var revision int64
	var passwordSecret, totpSecret, recoverySecret []byte
	err := h.pool.QueryRow(ctx, `SELECT a.identifier,c.secret_revision,c.password_secret,c.totp_secret,c.recovery_secret
FROM public.tsw_target_accounts a
JOIN public.tsw_target_credentials c ON c.target_account_id=a.id
WHERE a.id=$1 AND a.status='active' AND c.material_status='complete' AND c.materials_sealed`, targetID).
		Scan(&identifier, &revision, &passwordSecret, &totpSecret, &recoverySecret)
	if err != nil {
		return cpacred.Credential{}, err
	}
	password, err := targetdomain.OpenMaterial(passwordSecret, h.keyRing)
	if err != nil {
		return cpacred.Credential{}, err
	}
	totp, err := targetdomain.OpenMaterial(totpSecret, h.keyRing)
	if err != nil {
		return cpacred.Credential{}, err
	}
	recovery, err := targetdomain.OpenMaterial(recoverySecret, h.keyRing)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if strings.TrimSpace(identifier) == "" || strings.TrimSpace(password) == "" || strings.TrimSpace(totp) == "" {
		return cpacred.Credential{}, errors.New("CPA OAuth renewal material is incomplete")
	}
	if err := h.checkCPAOAuthSourceRevision(ctx, targetID, revision); err != nil {
		return cpacred.Credential{}, err
	}

	session, err := (accountsession.Store{Pool: h.pool, KeyRing: h.keyRing, Routes: h.accountRoutes()}).Ensure(ctx, targetID, h.personalRefresh, false, nil)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if session.Status != "ready" {
		code := session.Status
		if session.Failure != nil {
			code += ":" + session.Failure.Code
		}
		return cpacred.Credential{}, fmt.Errorf("personal session refresh unavailable: %s", code)
	}
	route, err := h.rotationJoinEgress(ctx)
	if err != nil {
		return cpacred.Credential{}, err
	}
	if route == nil || route.Client() == nil {
		if route != nil {
			route.Release()
		}
		return cpacred.Credential{}, errors.New("egress unavailable")
	}
	defer route.Release()
	client := route.Client()
	adapters := h.rotationCredentialAdapters(func(context.Context) (*http.Client, func(), error) {
		return client, nil, nil
	})
	if adapters == nil {
		return cpacred.Credential{}, cpacred.ErrNotConfigured
	}

	access, err := adapters.ExchangeCandidateWorkspace(ctx, session.Session, workspaceID, "")
	if err != nil {
		return cpacred.Credential{}, err
	}
	// Same-account renewal is not a rotation-slot admission. The official
	// exchanged session already bounds its usable lifetime; a longer raw JWT
	// expiry must not invalidate an otherwise valid current web session.
	claimedWorkspace, subject := platform.WorkspaceAccessIdentity(access)
	if claimedWorkspace != workspaceID || subject == "" || (!platform.ValidateWorkspaceAccess(access, workspaceID, time.Now()) || !platform.ValidateRotationCandidatePersonal(session.Session, subject, time.Now())) {
		return cpacred.Credential{}, errors.New("CPA OAuth workspace identity mismatch")
	}
	config, err := platform.NewHTTPConfig("https://chatgpt.com")
	if err != nil {
		return cpacred.Credential{}, err
	}
	reader, err := config.OAuthReader(client)
	if err != nil {
		return cpacred.Credential{}, err
	}
	request := platform.DeliveryCredentialRequest{
		Environment: session.Environment, Identifier: identifier, Password: password,
		TOTPSecret: totp, Recovery: recovery, Workspace: workspaceID, PersonalSession: &session.Session,
	}
	oauth, err := reader.CreateDeliveryCredentials(ctx, request)
	if errors.Is(err, platform.ErrBrowserSessionExpired) {
		fresh, refreshErr := (accountsession.Store{Pool: h.pool, KeyRing: h.keyRing, Routes: h.accountRoutes()}).Ensure(ctx, targetID, h.personalRefresh, true, nil)
		if refreshErr != nil {
			return cpacred.Credential{}, refreshErr
		}
		if fresh.Status != "ready" {
			return cpacred.Credential{}, platform.ErrBrowserSessionExpired
		}
		request.PersonalSession = &fresh.Session
		oauth, err = reader.CreateDeliveryCredentials(ctx, request)
	}
	if err != nil {
		return cpacred.Credential{}, err
	}
	oauth, err = platform.ValidateDeliveryIdentity(oauth, workspaceID)
	if err != nil || oauth.PlatformSubjectID != subject || oauth.AccessToken == "" || oauth.RefreshToken == "" || oauth.IDToken == "" {
		return cpacred.Credential{}, errors.New("CPA OAuth grant identity mismatch")
	}
	if err := h.checkCPAOAuthSourceRevision(ctx, targetID, revision); err != nil {
		return cpacred.Credential{}, err
	}
	payload := cpacred.DeliveryPayload{
		RefreshToken: oauth.RefreshToken, AccessToken: oauth.AccessToken, IDToken: oauth.IDToken,
		ExpiresIn: int(oauth.ExpiresIn), Scope: oauth.Scope, WorkspaceID: oauth.WorkspaceID,
		PlatformSubjectID: oauth.PlatformSubjectID,
	}
	credential, err := cpacred.BuildCodexCredential(payload, email, time.Now())
	if err != nil {
		return cpacred.Credential{}, err
	}
	if email != "" && credential.Email != "" && !strings.EqualFold(strings.TrimSpace(email), credential.Email) {
		return cpacred.Credential{}, errors.New("CPA OAuth identity mismatch")
	}
	credential.Name = name
	if h.targetRoutes != nil {
		if err := h.targetRoutes.Validate(ctx, targetID); err != nil {
			return cpacred.Credential{}, err
		}
		enabled, err := h.targetRoutes.Enabled(ctx)
		if err != nil {
			return cpacred.Credential{}, err
		}
		if enabled {
			return h.targetRoutes.WithCredential(ctx, targetID, credential)
		}
	}
	return credential, nil
}

func (h *OwnerAuthHandler) checkCPAOAuthSourceRevision(ctx context.Context, targetID uuid.UUID, expected int64) error {
	var current int64
	err := h.pool.QueryRow(ctx, `SELECT c.secret_revision FROM public.tsw_target_credentials c JOIN public.tsw_target_accounts a ON a.id=c.target_account_id AND a.status='active' WHERE c.target_account_id=$1 AND c.materials_sealed AND c.material_status='complete'`, targetID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return err
	}
	if current != expected {
		return errCPAReauthorizationSuperseded
	}
	return nil
}
