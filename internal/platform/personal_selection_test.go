package platform

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

const personalChoiceFixtureID = "00000000-0000-4000-8000-000000000001"
const personalChoiceFixtureBody = `{"client_auth_session":{"workspaces":[{"id":"team-1","kind":"organization"},{"id":"` + personalChoiceFixtureID + `","kind":"personal"}]}}`

func TestPersonalLoginCompletesMultiAccountSelectionWithoutChoosingTeam(t *testing.T) {
	fixture := &personalFlowFixture{token: personalFixtureToken(time.Now(), nil), mfaContinue: officialAuthBase + "/workspace"}
	selections := 0
	client := &http.Client{Timeout: time.Second, Transport: accountsRoundTrip(func(req *http.Request) (*http.Response, error) {
		respond := func(body string) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		}
		switch req.URL.Path {
		case "/workspace":
			return respond("choose a workspace")
		case "/api/accounts/client_auth_session_dump":
			return respond(personalChoiceFixtureBody)
		case "/api/accounts/workspace/select":
			body, _ := io.ReadAll(req.Body)
			if req.Method != http.MethodPost || !personalChoiceBody(body, &personalChoice{id: personalChoiceFixtureID}) {
				t.Fatal("login chose a Team account")
			}
			selections++
			return respond(`{"continue_url":"https://auth.openai.com/after-totp"}`)
		default:
			return fixture.RoundTrip(req)
		}
	})}
	result, err := (PersonalWebRefresher{Client: func(context.Context) (*http.Client, func(), error) { return client, func() {}, nil }, Browser: fixturePersonalBrowser}).RefreshPersonal(t.Context(), MotherMaterial{Environment: fixtureEnvironment, LoginIdentifier: "mother@example.test", Password: "password", TOTPSecret: "JBSWY3DPEHPK3PXP"})
	if err != nil || result.Status != "ready" || selections != 1 {
		t.Fatalf("multi-account login status=%s selections=%d error=%v", result.Status, selections, err)
	}
}

func TestPersonalChoiceRejectsMissingConflictingAndMalformedEvidence(t *testing.T) {
	for _, body := range []string{`{}`, `{"client_auth_session":{"workspaces":[{"id":"team","kind":"organization"}]}}`, `{"client_auth_session":{"workspaces":[{"id":"bad","kind":"personal"}]}}`, `{"client_auth_session":{"workspaces":[{"id":"` + personalChoiceFixtureID + `","kind":"personal"},{"id":"00000000-0000-4000-8000-000000000002","kind":"personal"}]}}`} {
		if _, err := personalChoiceFromSession([]byte(body)); err == nil {
			t.Fatal("invalid evidence authorized a choice")
		}
	}
	choice, err := personalChoiceFromSession([]byte(personalChoiceFixtureBody))
	if err != nil {
		t.Fatal(err)
	}
	transport := &personalBrowserTransport{}
	req := &network.Request{URL: officialAuthBase + "/api/accounts/workspace/select", Method: http.MethodPost, PostDataEntries: []*network.PostDataEntry{{Bytes: []byte(`{"workspace_id":"` + personalChoiceFixtureID + `"}`)}}}
	if transport.allowedRequest(req) {
		t.Fatal("background script selected an account")
	}
	transport.choice.Store(choice)
	if !transport.allowedRequest(req) {
		t.Fatal("proven Personal choice blocked")
	}
	for _, body := range []string{`{"workspace_id":"team-1"}`, `{"workspace_id":"` + personalChoiceFixtureID + `","extra":"field"}`} {
		req.PostDataEntries = []*network.PostDataEntry{{Bytes: []byte(body)}}
		if transport.allowedRequest(req) {
			t.Fatal("unproven selection permitted")
		}
	}
}

func TestPersonalLoginResumesAuthenticatedSelectionBeforePassword(t *testing.T) {
	fixture := &personalFlowFixture{token: personalFixtureToken(time.Now(), func(c map[string]any) { c["sub"] = "user-fixture"; c["email"] = "mother@example.test" }), redirect: officialAuthBase + "/workspace"}
	selections := 0
	client := &http.Client{Timeout: time.Second, Transport: accountsRoundTrip(func(req *http.Request) (*http.Response, error) {
		respond := func(body string) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		}
		switch req.URL.Path {
		case "/workspace":
			return respond("choose a workspace")
		case "/api/accounts/client_auth_session_dump":
			return respond(personalChoiceFixtureBody)
		case "/api/accounts/workspace/select":
			body, _ := io.ReadAll(req.Body)
			if req.Method != http.MethodPost || !personalChoiceBody(body, &personalChoice{id: personalChoiceFixtureID}) {
				t.Fatal("login chose a Team account")
			}
			selections++
			return respond(`{"continue_url":"https://auth.openai.com/after-totp"}`)
		case "/api/accounts/password/verify", "/api/accounts/mfa/verify":
			t.Fatal("authenticated selection restarted password or TOTP")
			return nil, nil
		default:
			return fixture.RoundTrip(req)
		}
	})}
	result, err := (PersonalWebRefresher{Client: func(context.Context) (*http.Client, func(), error) { return client, func() {}, nil }, Browser: fixturePersonalBrowser}).RefreshPersonal(t.Context(), MotherMaterial{Environment: fixtureEnvironment, LoginIdentifier: "mother@example.test", Password: "password", TOTPSecret: "JBSWY3DPEHPK3PXP"})
	if err != nil || result.Status != "ready" || selections != 1 {
		t.Fatalf("multi-account login status=%s selections=%d error=%v", result.Status, selections, err)
	}
}
