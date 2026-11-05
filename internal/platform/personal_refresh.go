package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/browserenv"
)

type PersonalWebRefresher struct {
	Client  DiscoveryClient
	Browser PersonalBrowserFactory
}

// This local denial stays distinguishable through net/http's url.Error wrapper.
type personalRequestDenial string

func (e personalRequestDenial) Error() string { return string(e) }

func personalRequestFailure(err error) PersonalRefreshResult {
	failure := &PersonalRefreshFailure{Code: "login_request_failed"}
	var rejected *authHTTPError
	var network net.Error
	var request *url.Error
	var denied personalRequestDenial
	switch {
	case errors.As(err, &denied):
	// Keep the existing login_request_failed outcome for an intentional local refusal.
	case errors.As(err, &rejected):
		failure.HTTPStatus = rejected.status
		switch {
		case rejected.browserChallenge:
			failure.Code = "platform_browser_challenge"
		case rejected.status == http.StatusForbidden:
			failure.Code = "platform_access_denied"
		case rejected.status == http.StatusTooManyRequests:
			failure.Code = "platform_rate_limited"
		case rejected.status >= 500:
			failure.Code = "platform_unavailable"
		}
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout():
		failure.Code = "network_timeout"
	case errors.As(err, &request):
		failure.Code = "network_error"
	}
	return PersonalRefreshResult{Status: "refresh_failed", Failure: failure}
}

// Only the two first-party hosts are permitted, including every continuation
// returned by the remote service. The checked transport also guards shared
// helpers that resolve absolute redirect URLs without validating their host.
type personalHostGuard struct{ next http.RoundTripper }

func validatePersonalRequest(req *http.Request) error {
	if req == nil {
		return personalRequestDenial("personal login request missing")
	}
	u := req.URL
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		(u.Hostname() != "chatgpt.com" && u.Hostname() != "auth.openai.com") ||
		(req.Host != "" && req.Host != u.Host) {
		return personalRequestDenial("personal login URL is not first-party HTTPS")
	}
	path := u.Path
	if personalChoiceRequest(req) {
		return nil
	}
	if authorization, _ := req.Context().Value(personalAuthorizationContextKey{}).(*personalAuthorization); authorization.allows(req.Method, u) {
		return nil
	}
	if strings.Contains(path, "/workspace/select") || strings.Contains(path, "/session/select") ||
		strings.Contains(path, "/consent") || strings.HasPrefix(path, "/oauth/") ||
		strings.HasPrefix(path, "/backend-api/") || strings.Contains(path, "/invites/") {
		return personalRequestDenial("personal login path is not permitted")
	}
	if req.Method == http.MethodPost {
		target := u.Hostname() + path
		if target != "chatgpt.com/api/auth/signin/openai" &&
			target != "auth.openai.com/api/accounts/password/verify" &&
			target != "auth.openai.com/api/accounts/mfa/verify" {
			return personalRequestDenial("personal login POST is not permitted")
		}
	} else if req.Method != http.MethodGet {
		return personalRequestDenial("personal login method is not permitted")
	}
	return nil
}

func (g personalHostGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := validatePersonalRequest(req); err != nil {
		return nil, err
	}
	return g.next.RoundTrip(req)
}

// RefreshPersonal authenticates a fresh Personal-only session. Its first-party
// Web authorization never grants a Workspace or delivery OAuth capability.
// A multi-account login may select its independently identified Personal account.
func (p PersonalWebRefresher) RefreshPersonal(ctx context.Context, material MotherMaterial) (PersonalRefreshResult, error) {
	failed := PersonalRefreshResult{Status: "refresh_failed"}
	if err := material.Environment.Validate(); err != nil {
		return failed, err
	}
	if p.Client == nil || strings.TrimSpace(material.LoginIdentifier) == "" || material.Password == "" || material.TOTPSecret == "" {
		return failed, nil
	}
	if _, err := auth.TOTPCode(material.TOTPSecret, time.Now()); err != nil {
		return failed, nil
	}
	source, release, err := p.Client(ctx)
	if err != nil {
		return personalRequestFailure(err), nil
	}
	if release != nil {
		defer release()
	}
	// Admission waiting uses only caller cancellation; execution starts here.
	ctx, stopExecution := context.WithTimeout(ctx, 120*time.Second)
	defer stopExecution()
	if source == nil || source.Transport == nil || source.Timeout <= 0 {
		return failed, nil
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return failed, nil
	}
	factory := p.Browser
	if factory == nil {
		factory = NewPersonalBrowser
	}
	transport, closeBrowser, err := factory(ctx, source, jar, material.Environment)
	if err != nil {
		return personalRequestFailure(err), nil
	}
	defer closeBrowser()
	client := *source
	if client.Timeout < 35*time.Second {
		client.Timeout = 35 * time.Second
	}
	client.Transport = personalHostGuard{next: transport}
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r := &HTTPReader{client: &client}
	deviceID := material.Environment.DeviceID
	loggingID, err := newBrowserID()
	if err != nil {
		return failed, nil
	}
	loginURL, err := r.beginAccountLogin(ctx, material.LoginIdentifier, deviceID, loggingID)
	if err != nil {
		return personalRequestFailure(err), nil
	}
	authorization, err := personalAuthorizationFromLoginURL(loginURL)
	if err != nil {
		return personalRequestFailure(err), nil
	}
	if authorization != nil {
		ctx = context.WithValue(ctx, personalAuthorizationContextKey{}, authorization)
	}
	pageURL, page, err := r.followBrowserRedirect(ctx, jar, loginURL, officialChatBase+"/login")
	if err != nil {
		return personalRequestFailure(err), nil
	}
	if authorization.completedAt(pageURL) {
		return r.readPersonalSession(ctx, jar, deviceID, false, material.LoginIdentifier)
	}
	// A persisted browser login can finish authentication at Personal account
	// selection. Restarting the password step here destroys the valid auth state.
	if landing, parseErr := url.Parse(pageURL); parseErr == nil && landing.Scheme == "https" && landing.Host == "auth.openai.com" && landing.Path == "/workspace" {
		if err := r.finishPersonalChoice(ctx, jar, pageURL); err != nil {
			return personalRequestFailure(err), nil
		}
		return r.readPersonalSession(ctx, jar, deviceID, false, material.LoginIdentifier)
	}
	if !strings.Contains(strings.ToLower(pageURL+" "+string(page)), "log-in/password") {
		pageURL, page, err = r.followBrowserRedirect(ctx, jar, officialAuthBase+"/log-in/password", pageURL)
		if err != nil {
			return personalRequestFailure(err), nil
		}
		if !strings.Contains(strings.ToLower(pageURL+" "+string(page)), "log-in/password") {
			return failed, nil
		}
	}
	continueURL, err := r.submitPassword(ctx, jar, material.Password)
	if err != nil {
		var rejected *authHTTPError
		if errors.As(err, &rejected) && rejected.status == http.StatusUnauthorized {
			return PersonalRefreshResult{Status: "invalid_login"}, nil
		}
		return personalRequestFailure(err), nil
	}
	if continueURL == "" {
		return failed, nil
	}

	continuation, err := http.NewRequestWithContext(ctx, http.MethodGet, continueURL, nil)
	if err != nil || validatePersonalRequest(continuation) != nil {
		return failed, nil
	}
	challenge := extractMFAChallenge(continueURL, nil)
	pageURL = continueURL
	// The password response normally identifies the TOTP challenge directly.
	// Only read the continuation when it does not yet contain that identifier.
	if challenge == "" {
		pageURL, page, err = r.followBrowserRedirect(ctx, jar, continueURL, officialAuthBase+"/log-in/password")
		if err != nil {
			return personalRequestFailure(err), nil
		}
		if !requiresTOTP(pageURL, page) {
			return failed, nil
		}
		challenge = extractMFAChallenge(pageURL, page)
	}
	if challenge == "" {
		return failed, nil
	}
	code, err := auth.TOTPCode(material.TOTPSecret, time.Now())
	if err != nil {
		return failed, nil
	}
	body, _ := json.Marshal(map[string]string{"code": code, "type": "totp", "id": challenge})
	verified, err := r.authJSONWithJar(ctx, jar, http.MethodPost, officialAuthBase+"/api/accounts/mfa/verify", body, pageURL)
	if err != nil {
		var rejected *authHTTPError
		if errors.As(err, &rejected) && rejected.status == http.StatusUnauthorized {
			return PersonalRefreshResult{Status: "invalid_login"}, nil
		}
		return personalRequestFailure(err), nil
	}
	if next := continueURLFromJSON(verified); next != "" {
		if pageURL, _, err = r.followBrowserRedirect(ctx, jar, next, pageURL); err != nil {
			return personalRequestFailure(err), nil
		}
	}
	if err = r.finishPersonalChoice(ctx, jar, pageURL); err != nil {
		return personalRequestFailure(err), nil
	}
	return r.readPersonalSession(ctx, jar, deviceID, false, "")
}

// RenewPersonal checks the saved session on the same fixed first-party endpoint.
func (p PersonalWebRefresher) RenewPersonal(ctx context.Context, saved PersonalSession, environment browserenv.Environment) (PersonalRefreshResult, error) {
	failed := PersonalRefreshResult{Status: "refresh_failed"}
	if err := environment.Validate(); err != nil {
		return failed, err
	}
	if p.Client == nil || !validPersonalCookies(saved) {
		return failed, nil
	}
	source, release, err := p.Client(ctx)
	if err != nil {
		return personalRequestFailure(err), nil
	}
	if release != nil {
		defer release()
	}
	ctx, stopExecution := context.WithTimeout(ctx, 120*time.Second)
	defer stopExecution()
	if source == nil || source.Transport == nil || source.Timeout <= 0 {
		return failed, nil
	}
	saved.DeviceID = environment.DeviceID
	jar, err := personalCookieJar(saved)
	if err != nil {
		return failed, nil
	}
	factory := p.Browser
	if factory == nil {
		factory = NewPersonalBrowser
	}
	transport, closeBrowser, err := factory(ctx, source, jar, environment)
	if err != nil {
		return personalRequestFailure(err), nil
	}
	defer closeBrowser()
	client := *source
	if client.Timeout < 35*time.Second {
		client.Timeout = 35 * time.Second
	}
	client.Transport = personalHostGuard{next: transport}
	client.Jar = jar
	return (&HTTPReader{client: &client}).readPersonalSession(ctx, jar, environment.DeviceID, true, "")
}

func personalCookieJar(saved PersonalSession) (http.CookieJar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	for _, cookie := range saved.Cookies {
		host := cookie.Host
		if host == "" {
			host = "chatgpt.com"
		}
		u, _ := url.Parse("https://" + host + "/")
		jar.SetCookies(u, []*http.Cookie{{Name: cookie.Name, Value: cookie.Value, Path: "/", Secure: true}})
	}
	u, _ := url.Parse(officialChatBase + "/")
	jar.SetCookies(u, []*http.Cookie{{Name: "oai-did", Value: saved.DeviceID, Path: "/", Secure: true}})
	return jar, nil
}

func (r *HTTPReader) readPersonalSession(ctx context.Context, jar http.CookieJar, deviceID string, renewal bool, expectedIdentifier string) (PersonalRefreshResult, error) {
	failed := PersonalRefreshResult{Status: "refresh_failed"}
	sessionBody, err := r.authJSONWithJar(ctx, jar, http.MethodGet, officialChatBase+"/api/auth/session", nil, officialChatBase+"/")
	if err != nil {
		var rejected *authHTTPError
		if renewal && errors.As(err, &rejected) && rejected.status == http.StatusUnauthorized {
			return PersonalRefreshResult{Status: "invalid_login"}, nil
		}
		return personalRequestFailure(err), nil
	}
	var snapshot struct {
		AccessToken string `json:"accessToken"`
		Expires     string `json:"expires"`
		User        struct {
			Email string `json:"email"`
			ID    string `json:"id"`
		} `json:"user"`
	}
	if json.Unmarshal(sessionBody, &snapshot) != nil {
		return failed, nil
	}
	if snapshot.AccessToken == "" {
		// Only an explicit empty session object proves the user is logged out.
		var fields map[string]json.RawMessage
		if renewal && json.Unmarshal(sessionBody, &fields) == nil && fields != nil && len(fields) == 0 {
			return PersonalRefreshResult{Status: "invalid_login"}, nil
		}
		return failed, nil
	}
	now := time.Now().UTC()
	tokenExpiry, err := postTOTPPersonalExpiry(snapshot.AccessToken, now)
	if err != nil {
		return failed, nil
	}
	sessionExpiry, err := time.Parse(time.RFC3339, snapshot.Expires)
	if err != nil || !sessionExpiry.After(now.Add(time.Minute)) {
		return failed, nil
	}
	if sessionExpiry.Before(tokenExpiry) {
		tokenExpiry = sessionExpiry
	}
	stored := make([]SessionCookie, 0)
	for _, host := range []string{"chatgpt.com", "auth.openai.com"} {
		u, _ := url.Parse("https://" + host + "/")
		for _, cookie := range jar.Cookies(u) {
			stored = append(stored, SessionCookie{Name: cookie.Name, Value: cookie.Value, Host: host})
		}
	}
	result := PersonalRefreshResult{Status: "ready", Session: PersonalSession{AccessToken: snapshot.AccessToken, Cookies: stored, DeviceID: deviceID, ExpiresAt: tokenExpiry, SessionExpiresAt: sessionExpiry}}
	if !ValidatePersonalRefresh(result, now) {
		return failed, nil
	}
	if expectedIdentifier != "" {
		identity, err := personalBearerIdentity(result.Session, snapshot.User.Email, snapshot.User.ID, now)
		if err != nil || !strings.EqualFold(identity.Identifier, strings.TrimSpace(expectedIdentifier)) {
			return failed, nil
		}
	}
	return result, nil
}
