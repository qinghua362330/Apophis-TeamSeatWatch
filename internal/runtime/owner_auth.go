package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountroute"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/mothersecret"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/task"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/workspace"
)

// OwnerAuthConfig contains the deployment-only dependencies for Owner authentication.
type OwnerAuthConfig struct {
	Context                 context.Context
	DatabaseURL             string
	KeyRing                 auth.KeyRing
	Origins                 auth.OriginPolicy
	Egress                  *egress.Manager
	DestinationProbe        DestinationProbe
	ChannelDelivery         ChannelDeliveryAdapter
	Discovery               platform.DiscoveryAdapter
	PersonalRefresh         platform.PersonalSessionRefresher
	SelectedWorkspaceReader platform.SelectedWorkspaceReader
	WorkspaceTokenExchanger platform.WorkspaceTokenExchanger
	WorkspaceMemberRemover  platform.WorkspaceMemberRemoval
	CPAWebhookSecret        string
	CPAManagementURL        string
	CPAManagementKey        string
}

// OwnerAuthHandler owns the HTTP boundary for the Ticket 03 Owner security API.
type OwnerAuthHandler struct {
	pool                       *pgxpool.Pool
	serviceContext             context.Context
	keyRing                    auth.KeyRing
	origins                    auth.OriginPolicy
	dummyPasswordHash          string
	workspaceFacts             *workspace.Service
	workspaceTasks             *task.Store
	egress                     *egress.Manager
	destinationProbe           DestinationProbe
	channelDelivery            ChannelDeliveryAdapter
	discovery                  platform.DiscoveryAdapter
	personalRefresh            platform.PersonalSessionRefresher
	selectedWorkspaceReader    platform.SelectedWorkspaceReader
	workspaceTokenExchanger    platform.WorkspaceTokenExchanger
	rotationCapability         rotationCapability // read-only evidence adapter; never performs platform mutation
	workspaceMemberRemover     platform.WorkspaceMemberRemoval
	rotationJoinEgress         func(context.Context) (rotationJoinEgress, error)
	rotationJoinAdapters       func(platform.DiscoveryClient) rotationJoinAdapters
	rotationCredentialAdapters func(platform.DiscoveryClient) platform.RotationCredentialAdapter
	rotationUsageAdapters      func(platform.DiscoveryClient) platform.RotationUsageReader
	proxyPool                  *proxyControl
	secureCookies              bool
	cpaWebhookSecret           []byte
	// cpaCredentials is nil unless the deployment attaches CPA management. A nil
	// port keeps every remote CPA step disabled rather than partially executed.
	targetRoutes       *accountroute.Store
	cpaCredentials     cpaCredentialPort
	cpaOAuthIssuer     func(context.Context, uuid.UUID, string, string, string) (cpacred.Credential, error)
	cpaProxyAssignment func(context.Context, uuid.UUID, cpacred.Credential) (cpacred.Credential, error)
}

type ownerContext struct {
	OwnerID           string
	SessionID         string
	Username          string
	Token             string
	AuthVersion       int64
	PasswordChangedAt time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

type sessionRow struct {
	ID                string
	Current           bool
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

type dbOwner struct {
	ID           string
	PasswordHash string
	AuthVersion  int64
}

type rateSubject struct {
	kind  string
	value string
}

var _ ownerapi.ServerInterface = (*OwnerAuthHandler)(nil)

// OwnerControl exposes the HTTP routes and their shared scoped invitation factory.
type OwnerControl struct {
	http.Handler
	Joiner           task.JoinerFactory
	OperationRemover task.OperationRemoverFactory
	TargetRoutes     *accountroute.Store
}

// NewOwnerAuthHandler builds the Owner routes and their database pool.
func NewOwnerAuthHandler(config OwnerAuthConfig) (*OwnerControl, func(), error) {
	if config.DatabaseURL == "" || config.KeyRing == nil {
		return nil, func() {}, errors.New("owner auth configuration is incomplete")
	}
	// A real Argon2id hash keeps unknown-account timing on the password-verification path.
	dummy, err := auth.HashPassword("invalid-account-password")
	if err != nil {
		return nil, func() {}, errors.New("initialize owner authentication")
	}
	pool, err := pgxpool.New(context.Background(), config.DatabaseURL)
	if err != nil {
		return nil, func() {}, err
	}
	// Both source mother and target materials must be sealed before Owner routes open.
	if err = mothersecret.Migrate(context.Background(), pool, config.KeyRing); err != nil {
		pool.Close()
		return nil, func() {}, err
	}
	if err = sealExistingTargetMaterials(context.Background(), pool, config.KeyRing); err != nil {
		pool.Close()
		return nil, func() {}, err
	}
	runtimeContext := config.Context
	if runtimeContext == nil {
		runtimeContext = context.Background()
	}
	serviceContext, cancelService := context.WithCancel(runtimeContext)
	handler := &OwnerAuthHandler{
		pool:                    pool,
		serviceContext:          serviceContext,
		keyRing:                 config.KeyRing,
		origins:                 config.Origins,
		dummyPasswordHash:       dummy,
		workspaceFacts:          workspace.NewService(pool, config.KeyRing),
		workspaceTasks:          task.NewStore(pool, config.KeyRing),
		egress:                  config.Egress,
		proxyPool:               newProxyControl(pool, config.KeyRing, config.Egress),
		destinationProbe:        config.DestinationProbe,
		channelDelivery:         config.ChannelDelivery,
		discovery:               config.Discovery,
		personalRefresh:         config.PersonalRefresh,
		selectedWorkspaceReader: config.SelectedWorkspaceReader,
		workspaceTokenExchanger: config.WorkspaceTokenExchanger,
		workspaceMemberRemover:  config.WorkspaceMemberRemover,
		secureCookies:           config.Origins.SecureCookies(),
		cpaWebhookSecret:        []byte(config.CPAWebhookSecret),
	}
	handler.targetRoutes = &accountroute.Store{Pool: pool, KeyRing: config.KeyRing, Manager: config.Egress}
	// An unattached CPA management endpoint leaves every remote stage off rather
	// than running half of one.
	if credentialClient, credentialErr := cpacred.New(cpacred.Config{BaseURL: config.CPAManagementURL, APIKey: config.CPAManagementKey}); credentialErr == nil {
		handler.cpaCredentials = credentialClient
	} else if config.CPAManagementURL != "" || config.CPAManagementKey != "" || !errors.Is(credentialErr, cpacred.ErrNotConfigured) {
		cancelService()
		pool.Close()
		return nil, func() {}, credentialErr
	}
	proxyDone := make(chan struct{})
	cpaAutomationDone := make(chan struct{})
	handler.rotationJoinEgress = func(ctx context.Context) (rotationJoinEgress, error) {
		if target := egress.Target(ctx); target != "" && handler.targetRoutes != nil {
			if borrowed, ok := egress.BorrowedLease(ctx, target); ok {
				return borrowedTargetRoute{borrowed}, nil
			}
			if enabled, err := handler.targetRoutes.Enabled(ctx); err != nil {
				return nil, err
			} else if enabled {
				id, err := uuid.Parse(target)
				if err != nil {
					return nil, err
				}
				return handler.targetRoutes.Acquire(ctx, id)
			}
		}
		if handler.egress == nil {
			return nil, platform.ErrRotationJoinUnavailable
		}
		return handler.egress.Acquire(ctx)
	}
	handler.cpaOAuthIssuer = handler.acquireCPAOAuth
	handler.cpaProxyAssignment = handler.assignCPACredentialProxy
	handler.rotationJoinAdapters = officialRotationJoinAdapters
	handler.rotationCredentialAdapters = func(client platform.DiscoveryClient) platform.RotationCredentialAdapter {
		return platform.OfficialRotationCredentialAdapter{Client: client}
	}
	handler.rotationUsageAdapters = func(client platform.DiscoveryClient) platform.RotationUsageReader {
		return platform.OfficialRotationUsageReader{Client: client}
	}
	if handler.selectedWorkspaceReader != nil {
		handler.rotationCapability = officialRotationCapability{handler: handler}
	}
	if err := handler.proxyPool.restoreSettings(runtimeContext); err != nil {
		cancelService()
		pool.Close()
		return nil, func() {}, err
	}
	if enabled, err := handler.targetRoutes.Enabled(runtimeContext); err != nil {
		cancelService()
		pool.Close()
		return nil, func() {}, err
	} else if enabled {
		// PinLease needs admitted candidates even when generic work uses direct mode.
		if _, err := handler.proxyPool.verifyLocked(runtimeContext, false, ""); err != nil {
			cancelService()
			pool.Close()
			return nil, func() {}, err
		}
	}
	// Existing CPA accounts must adopt their current proxy before workers start.
	if enabled, err := handler.targetRoutes.Enabled(runtimeContext); err != nil {
		cancelService()
		pool.Close()
		return nil, func() {}, err
	} else if enabled && handler.cpaCredentials != nil {
		files, err := handler.cpaCredentials.List(runtimeContext)
		if err == nil {
			err = handler.reconcileCPATargetRoutes(runtimeContext, files)
		}
		if err != nil {
			cancelService()
			pool.Close()
			return nil, func() {}, err
		}
	}
	go func() {
		defer close(proxyDone)
		handler.proxyPool.loop(serviceContext)
	}()
	go func() {
		defer close(cpaAutomationDone)
		handler.runCPAAutomationLoop(serviceContext)
	}()
	cpaSyncDone := make(chan struct{})
	go func() {
		defer close(cpaSyncDone)
		handler.runCPASyncLoop(serviceContext)
	}()
	cpaReauthorizationDone := make(chan struct{})
	go func() {
		defer close(cpaReauthorizationDone)
		handler.runCPAReauthorizationLoop(serviceContext)
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/cpa/degradation-events", handler.receiveCPADegradationEvent)
	ownerHandler := ownerapi.HandlerWithOptions(handler, ownerapi.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			// Generated binding details are collapsed into the stable public problem vocabulary.
			if isCSRFBindingError(err) {
				writeProblem(w, r, http.StatusForbidden, "csrf_rejected", "Forbidden", "Origin or CSRF validation failed", 0)
				return
			}
			writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid Request", "The request parameters are invalid", 0)
		},
	})

	noStore := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ownerHandler.ServeHTTP(w, r)
	})
	return &OwnerControl{Handler: noStore, Joiner: handler.operationJoiner, OperationRemover: handler.operationRemover, TargetRoutes: handler.targetRoutes}, func() {
		cancelService()
		<-proxyDone
		<-cpaAutomationDone
		<-cpaSyncDone
		<-cpaReauthorizationDone
		pool.Close()
	}, nil
}

func isCSRFBindingError(err error) bool {
	var required *ownerapi.RequiredHeaderError
	if errors.As(err, &required) && strings.EqualFold(required.ParamName, auth.CSRFHeaderName) {
		return true
	}
	var repeated *ownerapi.TooManyValuesForParamError
	if errors.As(err, &repeated) && strings.EqualFold(repeated.ParamName, auth.CSRFHeaderName) {
		return true
	}
	var invalid *ownerapi.InvalidParamFormatError
	return errors.As(err, &invalid) && strings.EqualFold(invalid.ParamName, auth.CSRFHeaderName)
}

func (h *OwnerAuthHandler) GetOwnerCsrf(w http.ResponseWriter, r *http.Request) {
	token, err := auth.NewCSRFToken(w, r, h.secureCookies)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "csrf_initialization_failed", "Internal Server Error", "Unable to initialize CSRF protection", 0)
		return
	}
	writeJSON(w, http.StatusOK, ownerapi.CsrfToken{Token: token})
}

func (h *OwnerAuthHandler) LoginOwner(w http.ResponseWriter, r *http.Request, _ ownerapi.LoginOwnerParams) {
	if !h.requireMutation(w, r) {
		return
	}
	var request ownerapi.LoginOwnerJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLoginRequest(request) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_login", "Invalid Login", "The login request is invalid", 0)
		return
	}

	username := strings.ToLower(strings.TrimSpace(request.Username))
	const loginMethod = "password"
	const limitPrefix = "login"
	subjects := []rateSubject{
		{kind: "login_account", value: username},
		{kind: "login_ip", value: remoteIP(r)},
	}

	// Bucket row locks serialize the authoritative check and increment across concurrent attempts.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rate_limit_unavailable", "Internal Server Error", "Unable to evaluate authentication", 0)
		return
	}
	defer tx.Rollback(r.Context())
	if err = lockRateSubjects(r.Context(), tx, subjects); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rate_limit_unavailable", "Internal Server Error", "Unable to evaluate authentication", 0)
		return
	}
	retry, err := retryAfterTx(r.Context(), tx, subjects)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "rate_limit_unavailable", "Internal Server Error", "Unable to evaluate authentication", 0)
		return
	}
	if retry > 0 {
		if err = h.recordAuthenticationFailure(r.Context(), tx, username, loginMethod, limitPrefix, subjects, true, r); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record authentication", 0)
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record authentication", 0)
			return
		}
		writeProblem(w, r, http.StatusTooManyRequests, "authentication_rate_limited", "Too Many Requests", "Authentication is temporarily unavailable", retry)
		return
	}

	owner, found, err := findOwnerTx(r.Context(), tx, username)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "authentication_unavailable", "Internal Server Error", "Unable to evaluate authentication", 0)
		return
	}
	passwordHash := h.dummyPasswordHash
	if found {
		passwordHash = owner.PasswordHash
	}
	if !auth.VerifyPassword(request.Password, passwordHash) || !found {
		h.authenticationFailed(w, r, tx, username, loginMethod, limitPrefix, subjects)
		return
	}

	token, sessionID, idleExpiresAt, source, err := insertSessionTx(r.Context(), tx, owner.ID, owner.AuthVersion, time.Time{}, r)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_creation_failed", "Internal Server Error", "Unable to create a session", 0)
		return
	}
	_, err = audit.Write(r.Context(), tx, audit.Event{
		Type:              audit.LoginSucceeded,
		Actor:             audit.ActorAnonymous,
		OwnerID:           owner.ID,
		EntityType:        "owner_session",
		EntityID:          sessionID,
		Outcome:           audit.OutcomeSucceeded,
		CorrelationID:     correlation(r),
		SourceFingerprint: source[:],
		Details:           audit.LoginDetails{Factor: loginMethod},
		IdempotencyKey:    sessionID + ":login",
	})
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record authentication", 0)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_creation_failed", "Internal Server Error", "Unable to create a session", 0)
		return
	}
	auth.SetSessionCookie(w, token, idleExpiresAt, h.secureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func findOwnerTx(ctx context.Context, tx pgx.Tx, username string) (dbOwner, bool, error) {
	var owner dbOwner
	err := tx.QueryRow(ctx, `
		SELECT id, password_hash, auth_version
		FROM tsw_owners WHERE username = $1`, username).Scan(
		&owner.ID, &owner.PasswordHash, &owner.AuthVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbOwner{}, false, nil
	}
	return owner, err == nil, err
}

func (h *OwnerAuthHandler) authenticationFailed(w http.ResponseWriter, r *http.Request, tx pgx.Tx, username, method, limitPrefix string, subjects []rateSubject) {
	// Rate-limit mutation and its audit event either both commit or both disappear.
	if err := h.recordAuthenticationFailure(r.Context(), tx, username, method, limitPrefix, subjects, false, r); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record authentication", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record authentication", 0)
		return
	}
	writeProblem(w, r, http.StatusUnauthorized, "authentication_failed", "Authentication Failed", "The supplied credentials are invalid", 0)
}

func insertSessionTx(ctx context.Context, tx pgx.Tx, ownerID string, authVersion int64, absoluteExpiresAt time.Time, r *http.Request) (string, string, time.Time, [32]byte, error) {
	token, hash, err := auth.NewSessionToken()
	if err != nil {
		return "", "", time.Time{}, [32]byte{}, err
	}
	source := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
	var sessionID string
	var idleExpiresAt time.Time
	if absoluteExpiresAt.IsZero() {
		err = tx.QueryRow(ctx, `
			INSERT INTO tsw_owner_sessions (
				owner_id, token_hash, auth_version, idle_expires_at, absolute_expires_at
			) VALUES ($1, $2, $3, now() + interval '8 hours', now() + interval '24 hours')
			RETURNING id, idle_expires_at`, ownerID, hash[:], authVersion).Scan(&sessionID, &idleExpiresAt)
	} else {
		// Rotation replaces the credential but never extends the original 24-hour lifetime.
		err = tx.QueryRow(ctx, `
			INSERT INTO tsw_owner_sessions (
				owner_id, token_hash, auth_version, idle_expires_at, absolute_expires_at
			) VALUES ($1, $2, $3, LEAST(now() + interval '8 hours', $4), $4)
			RETURNING id, idle_expires_at`, ownerID, hash[:], authVersion, absoluteExpiresAt).Scan(&sessionID, &idleExpiresAt)
	}
	return token, sessionID, idleExpiresAt, source, err
}

func (h *OwnerAuthHandler) LogoutOwner(w http.ResponseWriter, r *http.Request, _ ownerapi.LogoutOwnerParams) {
	if !h.requireMutation(w, r) {
		return
	}
	owner, err := h.session(r, false)
	if err != nil {
		auth.ClearSessionCookie(w, h.secureCookies)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "logout_failed", "Internal Server Error", "Unable to end the session", 0)
		return
	}
	defer tx.Rollback(r.Context())
	result, err := tx.Exec(r.Context(), `
		UPDATE tsw_owner_sessions SET revoked_at = now(), revocation_reason = 'logout'
		WHERE id = $1 AND revoked_at IS NULL`, owner.SessionID)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "logout_failed", "Internal Server Error", "Unable to end the session", 0)
		return
	}
	if result.RowsAffected() == 1 {
		source := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
		_, err = audit.Write(r.Context(), tx, audit.Event{
			Type:              audit.SessionRevoked,
			Actor:             audit.ActorOwner,
			OwnerID:           owner.OwnerID,
			EntityType:        "owner_session",
			EntityID:          owner.SessionID,
			Outcome:           audit.OutcomeSucceeded,
			CorrelationID:     correlation(r),
			SourceFingerprint: source[:],
			Details:           audit.SessionDetails{Reason: "logout"},
			IdempotencyKey:    owner.SessionID + ":logout",
		})
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to end the session", 0)
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "logout_failed", "Internal Server Error", "Unable to end the session", 0)
		return
	}
	auth.ClearSessionCookie(w, h.secureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func (h *OwnerAuthHandler) GetOwnerAuthStatus(w http.ResponseWriter, r *http.Request) {
	owner, err := h.session(r, false)
	if err != nil {
		writeProblem(w, r, http.StatusUnauthorized, "session_expired", "Session Expired", "Authentication is required", 0)
		return
	}
	auth.SetSessionCookie(w, owner.Token, owner.IdleExpiresAt, h.secureCookies)
	writeJSON(w, http.StatusOK, ownerapi.AuthStatus{
		Authenticated:     true,
		Username:          owner.Username,
		PasswordChangedAt: owner.PasswordChangedAt,
	})
}

func (h *OwnerAuthHandler) GetProxyPool(w http.ResponseWriter, r *http.Request, params ownerapi.GetProxyPoolParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, pageSize := 1, 20
	if params.Page != nil {
		page = *params.Page
	}
	if params.PageSize != nil {
		pageSize = *params.PageSize
	}
	state, kind := "", ""
	if params.State != nil {
		state = string(*params.State)
	}
	if params.SourceKind != nil {
		kind = string(*params.SourceKind)
	}
	view, err := h.proxyPool.filteredView(r.Context(), page, pageSize, state, kind)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "proxy_pool_unavailable", "Internal Server Error", "代理池状态读取失败", 0)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) PutProxySource(w http.ResponseWriter, r *http.Request, _ ownerapi.PutProxySourceParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.PutProxySourceJSONRequestBody
	if !decodeJSON(w, r, &request) {
		return
	}
	view, err := h.proxyPool.putSource(r.Context(), request)
	if err != nil {
		if errors.Is(err, errInvalidProxySource) {
			writeProblem(w, r, http.StatusBadRequest, "invalid_proxy_source", "Invalid Request", "代理来源参数无效，请检查填写内容", 0)
		} else {
			writeProblem(w, r, http.StatusInternalServerError, "proxy_source_unavailable", "Internal Server Error", "代理来源配置未保存，请稍后重试", 0)
		}
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) TestProxySource(w http.ResponseWriter, r *http.Request, _ ownerapi.TestProxySourceParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.ProxySourceRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := h.proxyPool.testSource(r.Context(), request)
	if err != nil {
		if errors.Is(err, errInvalidProxySource) {
			writeProblem(w, r, 400, "invalid_proxy_source", "Invalid Request", "代理来源参数无效，请检查填写内容", 0)
		} else {
			writeProblem(w, r, 500, "proxy_source_unavailable", "Internal Server Error", "代理来源测试未完成，请稍后重试", 0)
		}
		return
	}
	writeJSON(w, 200, result)
}
func (h *OwnerAuthHandler) ProbeProxyNode(w http.ResponseWriter, r *http.Request, nodeID openapi_types.UUID, _ ownerapi.ProbeProxyNodeParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	result, err := h.proxyPool.probeNode(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, errInvalidProxyNode) {
			writeProblem(w, r, 409, "proxy_node_unavailable", "Conflict", "该节点已退役或不可用，请刷新列表", 0)
		} else {
			writeProblem(w, r, 502, "proxy_probe_failed", "Proxy Probe Failed", "代理验证未完成，请重试", 0)
		}
		return
	}
	writeJSON(w, 200, result)
}

func (h *OwnerAuthHandler) SyncProxyPool(w http.ResponseWriter, r *http.Request, _ ownerapi.SyncProxyPoolParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	view, err := h.proxyPool.synchronize(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "proxy_sync_failed", "Proxy Sync Failed", "代理补齐失败，请检查来源后重试", 0)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) ImportProxyNodes(w http.ResponseWriter, r *http.Request, _ ownerapi.ImportProxyNodesParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.ImportProxyNodesJSONRequestBody
	if !decodeJSON(w, r, &request) {
		return
	}
	view, err := h.proxyPool.importNodes(r.Context(), request)
	if err != nil {
		if errors.Is(err, errInvalidProxyNodes) || errors.Is(err, errInvalidProxyNode) {
			writeProblem(w, r, http.StatusBadRequest, "invalid_proxy_node", "Invalid Request", "代理格式无效，请使用带端口的代理地址", 0)
		} else {
			writeProblem(w, r, http.StatusInternalServerError, "proxy_pool_unavailable", "Internal Server Error", "代理节点未保存，请稍后重试", 0)
		}
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) ProbeProxyPool(w http.ResponseWriter, r *http.Request, _ ownerapi.ProbeProxyPoolParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	view, err := h.proxyPool.probe(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "proxy_probe_failed", "Proxy Probe Failed", "代理验证未完成，请稍后重试", 0)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) RemoveProxyNode(w http.ResponseWriter, r *http.Request, nodeID openapi_types.UUID, _ ownerapi.RemoveProxyNodeParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	view, err := h.proxyPool.removeNode(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, egress.ErrNodeInUse) {
			writeProblem(w, r, http.StatusConflict, "proxy_node_in_use", "Proxy Node In Use", "正在使用的代理不能删除", 0)
		} else {
			writeProblem(w, r, http.StatusInternalServerError, "proxy_remove_failed", "Internal Server Error", "代理移除未完成，请重试", 0)
		}
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) UpdateProxyPoolSettings(w http.ResponseWriter, r *http.Request, _ ownerapi.UpdateProxyPoolSettingsParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.UpdateProxyPoolSettingsJSONRequestBody
	if !decodeJSON(w, r, &request) {
		return
	}
	view, err := h.proxyPool.updateSettings(r.Context(), request)
	if err != nil {
		if errors.Is(err, errInvalidProxySettings) {
			writeProblem(w, r, http.StatusBadRequest, "invalid_proxy_settings", "Invalid Request", "并发或补位参数超出范围", 0)
		} else {
			writeProblem(w, r, http.StatusInternalServerError, "proxy_pool_unavailable", "Internal Server Error", "运行参数未保存，请稍后重试", 0)
		}
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *OwnerAuthHandler) RefreshOwnerSession(w http.ResponseWriter, r *http.Request, _ ownerapi.RefreshOwnerSessionParams) {
	if !h.requireMutation(w, r) {
		return
	}
	owner, err := h.session(r, true)
	if err != nil {
		writeProblem(w, r, http.StatusUnauthorized, "session_expired", "Session Expired", "Authentication is required", 0)
		return
	}
	auth.SetSessionCookie(w, owner.Token, owner.IdleExpiresAt, h.secureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func (h *OwnerAuthHandler) ListOwnerSessions(w http.ResponseWriter, r *http.Request) {
	owner, err := h.session(r, false)
	if err != nil {
		writeProblem(w, r, http.StatusUnauthorized, "session_expired", "Session Expired", "Authentication is required", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT id, id = $2, created_at, last_seen_at, idle_expires_at, absolute_expires_at
		FROM tsw_owner_sessions
		WHERE owner_id = $1 AND auth_version = $3 AND revoked_at IS NULL
		  AND idle_expires_at > now() AND absolute_expires_at > now()
		ORDER BY last_seen_at DESC`, owner.OwnerID, owner.SessionID, owner.AuthVersion)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_list_failed", "Internal Server Error", "Unable to list sessions", 0)
		return
	}
	defer rows.Close()
	result := ownerapi.SessionList{Sessions: []ownerapi.Session{}}
	for rows.Next() {
		var item sessionRow
		if err := rows.Scan(&item.ID, &item.Current, &item.CreatedAt, &item.LastSeenAt, &item.IdleExpiresAt, &item.AbsoluteExpiresAt); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "session_list_failed", "Internal Server Error", "Unable to list sessions", 0)
			return
		}
		id, err := uuid.Parse(item.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "session_list_failed", "Internal Server Error", "Unable to list sessions", 0)
			return
		}
		result.Sessions = append(result.Sessions, ownerapi.Session{
			Id: id, Current: item.Current, CreatedAt: item.CreatedAt, LastSeenAt: item.LastSeenAt,
			IdleExpiresAt: item.IdleExpiresAt, AbsoluteExpiresAt: item.AbsoluteExpiresAt,
		})
	}
	if err := rows.Err(); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_list_failed", "Internal Server Error", "Unable to list sessions", 0)
		return
	}
	auth.SetSessionCookie(w, owner.Token, owner.IdleExpiresAt, h.secureCookies)
	writeJSON(w, http.StatusOK, result)
}

func (h *OwnerAuthHandler) RevokeOwnerSession(w http.ResponseWriter, r *http.Request, sessionID openapi_types.UUID, _ ownerapi.RevokeOwnerSessionParams) {
	if !h.requireMutation(w, r) {
		return
	}
	owner, err := h.session(r, false)
	if err != nil {
		writeProblem(w, r, http.StatusUnauthorized, "session_expired", "Session Expired", "Authentication is required", 0)
		return
	}
	targetID := sessionID.String()
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_revoke_failed", "Internal Server Error", "Unable to revoke the session", 0)
		return
	}
	defer tx.Rollback(r.Context())

	var revokedID string
	err = tx.QueryRow(r.Context(), `
		UPDATE tsw_owner_sessions
		SET revoked_at = now(), revocation_reason = 'owner_request'
		WHERE owner_id = $1 AND id::text = $2 AND revoked_at IS NULL
		RETURNING id`, owner.OwnerID, targetID).Scan(&revokedID)
	if errors.Is(err, pgx.ErrNoRows) {
		auth.SetSessionCookie(w, owner.Token, owner.IdleExpiresAt, h.secureCookies)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_revoke_failed", "Internal Server Error", "Unable to revoke the session", 0)
		return
	}
	source := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
	_, err = audit.Write(r.Context(), tx, audit.Event{
		Type:              audit.SessionRevoked,
		Actor:             audit.ActorOwner,
		OwnerID:           owner.OwnerID,
		EntityType:        "owner_session",
		EntityID:          revokedID,
		Outcome:           audit.OutcomeSucceeded,
		CorrelationID:     correlation(r),
		SourceFingerprint: source[:],
		Details:           audit.SessionDetails{Reason: "owner_request"},
		IdempotencyKey:    revokedID + ":owner_request",
	})
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to revoke the session", 0)
		return
	}

	if revokedID == owner.SessionID {
		if err = tx.Commit(r.Context()); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "session_revoke_failed", "Internal Server Error", "Unable to revoke the session", 0)
			return
		}
		auth.ClearSessionCookie(w, h.secureCookies)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Revoking another session is permission-sensitive, so the caller's token is replaced in the same transaction.
	token, idleExpiresAt, err := h.rotateSessionTx(r.Context(), tx, owner, "session_revocation", r)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_rotation_failed", "Internal Server Error", "Unable to rotate the current session", 0)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "session_revoke_failed", "Internal Server Error", "Unable to revoke the session", 0)
		return
	}
	auth.SetSessionCookie(w, token, idleExpiresAt, h.secureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func (h *OwnerAuthHandler) rotateSessionTx(ctx context.Context, tx pgx.Tx, owner ownerContext, reason string, r *http.Request) (string, time.Time, error) {
	result, err := tx.Exec(ctx, `
		UPDATE tsw_owner_sessions SET revoked_at = now(), revocation_reason = 'rotation'
		WHERE id = $1 AND revoked_at IS NULL`, owner.SessionID)
	if err != nil || result.RowsAffected() != 1 {
		return "", time.Time{}, errors.New("current session cannot be rotated")
	}
	token, newSessionID, idleExpiresAt, source, err := insertSessionTx(ctx, tx, owner.OwnerID, owner.AuthVersion, owner.AbsoluteExpiresAt, r)
	if err != nil {
		return "", time.Time{}, err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type:              audit.SessionRevoked,
		Actor:             audit.ActorOwner,
		OwnerID:           owner.OwnerID,
		EntityType:        "owner_session",
		EntityID:          owner.SessionID,
		Outcome:           audit.OutcomeSucceeded,
		CorrelationID:     correlation(r),
		SourceFingerprint: source[:],
		Details:           audit.SessionDetails{Reason: "rotation"},
		IdempotencyKey:    owner.SessionID + ":rotation",
	})
	if err != nil {
		return "", time.Time{}, err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type:              audit.SessionRotated,
		Actor:             audit.ActorOwner,
		OwnerID:           owner.OwnerID,
		EntityType:        "owner_session",
		EntityID:          newSessionID,
		Outcome:           audit.OutcomeSucceeded,
		CorrelationID:     correlation(r),
		SourceFingerprint: source[:],
		Details:           audit.SessionDetails{Reason: reason, PredecessorSessionID: owner.SessionID},
		IdempotencyKey:    owner.SessionID + ":rotated:" + newSessionID,
	})
	return token, idleExpiresAt, err
}

func (h *OwnerAuthHandler) session(r *http.Request, refresh bool) (ownerContext, error) {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return ownerContext{}, err
	}
	hash, err := auth.HashSessionToken(cookie.Value)
	if err != nil {
		return ownerContext{}, err
	}
	var owner ownerContext
	owner.Token = cookie.Value
	// Read-only endpoints validate without extending the idle deadline. Only the
	// CSRF-protected refresh endpoint mutates session activity using database time.
	query := `
		SELECT owner.id, session.id, session.auth_version, owner.username,
			owner.password_changed_at, session.idle_expires_at, session.absolute_expires_at
		FROM tsw_owner_sessions AS session
		JOIN tsw_owners AS owner ON owner.id = session.owner_id
		WHERE session.token_hash = $1
		  AND session.auth_version = owner.auth_version
		  AND session.revoked_at IS NULL
		  AND session.idle_expires_at > now()
		  AND session.absolute_expires_at > now()`
	if refresh {
		query = `
			UPDATE tsw_owner_sessions AS session
			SET last_seen_at = now(),
				idle_expires_at = LEAST(now() + interval '8 hours', session.absolute_expires_at)
			FROM tsw_owners AS owner
			WHERE session.owner_id = owner.id
			  AND session.token_hash = $1
			  AND session.auth_version = owner.auth_version
			  AND session.revoked_at IS NULL
			  AND session.idle_expires_at > now()
			  AND session.absolute_expires_at > now()
			RETURNING owner.id, session.id, session.auth_version, owner.username,
				owner.password_changed_at, session.idle_expires_at, session.absolute_expires_at`
	}
	err = h.pool.QueryRow(r.Context(), query, hash[:]).Scan(
		&owner.OwnerID, &owner.SessionID, &owner.AuthVersion, &owner.Username,
		&owner.PasswordChangedAt, &owner.IdleExpiresAt, &owner.AbsoluteExpiresAt,
	)
	return owner, err
}

func (h *OwnerAuthHandler) requireMutation(w http.ResponseWriter, r *http.Request) bool {
	if err := auth.VerifyCSRF(r, h.origins); err != nil {
		writeProblem(w, r, http.StatusForbidden, "csrf_rejected", "Forbidden", "Origin or CSRF validation failed", 0)
		return false
	}
	return true
}

func lockRateSubjects(ctx context.Context, tx pgx.Tx, subjects []rateSubject) error {
	for _, subject := range subjects {
		_, err := tx.Exec(ctx, `
			INSERT INTO tsw_rate_limit_buckets (
				kind, subject_hash, window_started_at, window_ends_at,
				count, blocked_until, expires_at
			) VALUES (
				$1, $2, date_bin('15 minutes', now(), timestamptz 'epoch'),
				date_bin('15 minutes', now(), timestamptz 'epoch') + interval '15 minutes',
				0, NULL, date_bin('15 minutes', now(), timestamptz 'epoch') + interval '7 days'
			)
			ON CONFLICT ON CONSTRAINT tsw_rate_limit_buckets_window_uq DO NOTHING`,
			subject.kind, subjectHash(subject.kind, subject.value))
		if err != nil {
			return err
		}
		var lockedID string
		err = tx.QueryRow(ctx, `
			SELECT id FROM tsw_rate_limit_buckets
			WHERE kind = $1 AND subject_hash = $2
			  AND window_started_at = date_bin('15 minutes', now(), timestamptz 'epoch')
			FOR UPDATE`, subject.kind, subjectHash(subject.kind, subject.value)).Scan(&lockedID)
		if err != nil {
			return err
		}
	}
	return nil
}

func retryAfterTx(ctx context.Context, tx pgx.Tx, subjects []rateSubject) (int, error) {
	maximum := 0
	for _, subject := range subjects {
		var seconds int
		err := tx.QueryRow(ctx, `
			SELECT GREATEST(0, CEIL(EXTRACT(EPOCH FROM (blocked_until - now()))))::int
			FROM tsw_rate_limit_buckets
			WHERE kind = $1 AND subject_hash = $2 AND blocked_until > now()
			ORDER BY window_started_at DESC LIMIT 1`, subject.kind, subjectHash(subject.kind, subject.value)).Scan(&seconds)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if seconds > maximum {
			maximum = seconds
		}
	}
	return maximum, nil
}

func (h *OwnerAuthHandler) recordAuthenticationFailure(ctx context.Context, tx pgx.Tx, username, method, limitPrefix string, subjects []rateSubject, denied bool, r *http.Request) error {
	var ownerID string
	if err := tx.QueryRow(ctx, `SELECT id FROM tsw_owners WHERE singleton`).Scan(&ownerID); err != nil {
		return err
	}
	if !denied {
		for _, subject := range subjects {
			_, err := tx.Exec(ctx, `
				UPDATE tsw_rate_limit_buckets
				SET count = LEAST(5, count + 1),
					blocked_until = CASE
						WHEN count >= 4 THEN now() + interval '15 minutes'
						ELSE blocked_until
					END
				WHERE kind = $1 AND subject_hash = $2
				  AND window_started_at = date_bin('15 minutes', now(), timestamptz 'epoch')`,
				subject.kind, subjectHash(subject.kind, subject.value))
			if err != nil {
				return err
			}
		}
	}

	outcome := audit.OutcomeFailed
	rateLimitKind := ""
	if denied {
		outcome = audit.OutcomeDenied
		rateLimitKind = limitPrefix
	}
	source := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
	accountFingerprint := fmt.Sprintf("%x", subjectHash(limitPrefix+"_account", username))
	attemptID, err := newOpaqueID()
	if err != nil {
		return err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type:              audit.LoginFailed,
		Actor:             audit.ActorAnonymous,
		OwnerID:           ownerID,
		EntityType:        "owner",
		EntityID:          ownerID,
		Outcome:           outcome,
		CorrelationID:     correlation(r),
		SourceFingerprint: source[:],
		Details:           audit.LoginFailureDetails{Factor: method, RateLimitKind: rateLimitKind},
		IdempotencyKey:    "authentication-failure:" + attemptID + ":" + accountFingerprint,
	})
	return err
}

func subjectHash(kind, value string) []byte {
	// Including the bucket kind prevents account/IP and login/recovery linkage in stored hashes.
	sum := sha256.Sum256([]byte("teamseatwatch:rate-limit:v1\x00" + kind + "\x00" + value))
	return sum[:]
}

func validLoginRequest(request ownerapi.LoginOwnerJSONRequestBody) bool {
	usernameLength := utf8.RuneCountInString(strings.TrimSpace(request.Username))
	return usernameLength >= 1 && usernameLength <= 254 &&
		len(request.Password) >= 1 && len(request.Password) <= 1024
}

func correlation(r *http.Request) string {
	if value := CorrelationIDFromContext(r.Context()); value != "" {
		return value
	}
	return requestID(r)
}

func requestID(r *http.Request) string {
	if value := RequestIDFromContext(r.Context()); value != "" {
		return value
	}
	return "owner-auth"
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value interface{}) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return false
	}
	var trailing interface{}
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string, retry int) {
	w.Header().Set("Content-Type", "application/problem+json")
	if retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(retry))
	}
	w.WriteHeader(status)
	detailValue := detail
	var retryValue *int
	if retry > 0 {
		retryValue = &retry
	}
	_ = json.NewEncoder(w).Encode(ownerapi.Problem{
		Type:              "urn:teamseatwatch:problem:" + code,
		Title:             title,
		Status:            status,
		Code:              code,
		RequestId:         requestID(r),
		Detail:            &detailValue,
		RetryAfterSeconds: retryValue,
	})
}
