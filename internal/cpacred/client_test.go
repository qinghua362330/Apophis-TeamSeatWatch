package cpacred

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "0123456789abcdef0123456789abcdef"

type fakeCPA struct {
	mu                    sync.Mutex
	files                 map[string]map[string]any
	order                 []string
	redirect              bool
	lieAbout              bool
	omitAccount           bool
	accountOverride       string
	omitRevision          bool
	revisionOverride      string
	authorizationOverride string
	authFiles             map[string][]byte
}

func newFakeCPA() *fakeCPA {
	return &fakeCPA{files: map[string]map[string]any{}, authFiles: map[string][]byte{}}
}

func (f *fakeCPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.redirect {
		http.Redirect(w, r, "http://example.com/", http.StatusFound)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files":
		files := make([]map[string]any, 0, len(f.order))
		for _, name := range f.order {
			files = append(files, f.files[name])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
	case r.Method == http.MethodPatch && r.URL.Path == "/v0/management/auth-files/status":
		var body struct {
			Name     string `json:"name"`
			Disabled *bool  `json:"disabled"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Disabled == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		entry, ok := f.files[body.Name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		entry["disabled"] = *body.Disabled
		if f.lieAbout {
			entry["disabled"] = !*body.Disabled
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "disabled": *body.Disabled})
	case r.Method == http.MethodPost && r.URL.Path == "/v0/management/auth-files":
		name := r.URL.Query().Get("name")
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if json.Unmarshal(raw, &payload) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := f.files[name]; !ok {
			f.order = append(f.order, name)
		}
		entry := map[string]any{
			"id": name, "name": name, "auth_index": "idx-" + name, "provider": "codex",
			"email": payload["email"], "account": payload["account_id"], "status": "active", "disabled": false,
		}
		if !f.omitRevision {
			entry["credential_revision"] = payload["credential_revision"]
			if f.revisionOverride != "" {
				entry["credential_revision"] = f.revisionOverride
			}
		}
		if f.omitAccount {
			delete(entry, "account")
		} else if f.accountOverride != "" {
			entry["account"] = f.accountOverride
		}
		f.files[name] = entry
		f.authFiles[name] = append([]byte(nil), raw...)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files/download":
		raw, ok := f.authFiles[r.URL.Query().Get("name")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var downloaded map[string]any
		if json.Unmarshal(raw, &downloaded) == nil {
			if f.omitAccount {
				delete(downloaded, "account_id")
			}
			if f.authorizationOverride != "" {
				downloaded["headers"] = map[string]string{"authorization": f.authorizationOverride}
			}

			if f.accountOverride != "" {
				downloaded["account_id"] = f.accountOverride
			}
			if f.revisionOverride != "" {
				downloaded["credential_revision"] = f.revisionOverride
			}
			raw, _ = json.Marshal(downloaded)
		}
		_, _ = w.Write(raw)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeCPA) seed(name, email string, disabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[name]; !ok {
		f.order = append(f.order, name)
	}
	f.files[name] = map[string]any{
		"id": name, "name": name, "auth_index": "idx-" + name, "provider": "codex",
		"email": email, "status": "active", "disabled": disabled,
	}
}

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{BaseURL: server.URL, APIKey: testKey})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestNewRejectsUnconfiguredAndNonLoopback(t *testing.T) {
	cases := []struct {
		name   string
		config Config
	}{
		{"empty", Config{}},
		{"key only", Config{APIKey: testKey}},
		{"base only", Config{BaseURL: "http://127.0.0.1:8318"}},
		{"invalid header key", Config{BaseURL: "http://127.0.0.1:8318", APIKey: "bad\nheader"}},
		{"remote host", Config{BaseURL: "http://10.0.0.5:8318", APIKey: testKey}},
		{"missing port", Config{BaseURL: "http://127.0.0.1", APIKey: testKey}},
		{"userinfo", Config{BaseURL: "http://user:pass@127.0.0.1:8318", APIKey: testKey}},
		{"wrong scheme", Config{BaseURL: "ftp://127.0.0.1:8318", APIKey: testKey}},
	}
	for _, test := range cases {
		if _, err := New(test.config); err == nil {
			t.Fatalf("%s: expected configuration rejection", test.name)
		}
	}
}

func TestNewAcceptsLoopbackForms(t *testing.T) {
	for _, base := range []string{"http://127.0.0.1:8318", "http://localhost:8318", "https://[::1]:8318/"} {
		if _, err := New(Config{BaseURL: base, APIKey: testKey}); err != nil {
			t.Fatalf("%s rejected: %v", base, err)
		}
	}
}

func TestListAndLookup(t *testing.T) {
	fake := newFakeCPA()
	fake.omitAccount = true
	fake.seed("codex-a.json", "a@example.com", false)
	fake.seed("codex-b.json", "b@example.com", true)
	client := newTestClient(t, fake)
	ctx := context.Background()

	files, err := client.List(ctx)
	if err != nil || len(files) != 2 {
		t.Fatalf("list files=%d err=%v", len(files), err)
	}
	if files[0].Provider != "codex" || files[1].Disabled != true {
		t.Fatalf("unexpected listing: %+v", files)
	}
	file, err := client.Lookup(ctx, "idx-codex-b.json")
	if err != nil || file.Name != "codex-b.json" {
		t.Fatalf("lookup by auth index: %+v err=%v", file, err)
	}
	file, err = client.Lookup(ctx, "name:codex-b.json#index:idx-codex-b.json")
	if err != nil || file.Name != "codex-b.json" {
		t.Fatalf("lookup by inventory identity: %+v err=%v", file, err)
	}
	if _, err = client.Lookup(ctx, "missing.json"); err == nil {
		t.Fatal("expected missing credential error")
	}
}

func TestSetDisabledVerifiesReadback(t *testing.T) {
	fake := newFakeCPA()
	fake.seed("codex-a.json", "a@example.com", false)
	client := newTestClient(t, fake)

	receipt, err := client.SetDisabled(context.Background(), "codex-a.json", true)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if receipt.Name != "codex-a.json" || receipt.Operation != "status" || receipt.StatusCode != http.StatusOK {
		t.Fatalf("receipt=%+v", receipt)
	}

	fake.mu.Lock()
	fake.lieAbout = true
	fake.mu.Unlock()
	if _, err = client.SetDisabled(context.Background(), "codex-a.json", false); err == nil {
		t.Fatal("expected readback disagreement to fail")
	}
}

func TestSetDisabledRejectsInvalidName(t *testing.T) {
	client := newTestClient(t, newFakeCPA())
	for _, name := range []string{"", "codex.json.bak", "../escape.json", "nested/codex.json", "no-extension"} {
		if _, err := client.SetDisabled(context.Background(), name, true); err == nil {
			t.Fatalf("%q: expected name rejection", name)
		}
	}
}

func TestUploadRegistersAndReadsBack(t *testing.T) {
	fake := newFakeCPA()
	client := newTestClient(t, fake)
	credential, err := BuildCodexCredential(DeliveryPayload{
		AccessToken: "a", RefreshToken: "r", IDToken: "i", WorkspaceID: "acct",
	}, "new@example.com", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	authFile := credential.AuthFile

	receipt, err := client.Upload(context.Background(), "codex-new.json", authFile)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if receipt.Operation != "upload" || receipt.Name != "codex-new.json" {
		t.Fatalf("receipt=%+v", receipt)
	}
	file, err := client.Lookup(context.Background(), "codex-new.json")
	if err != nil || file.Disabled || file.Email != "new@example.com" {
		t.Fatalf("readback: %+v err=%v", file, err)
	}
}

func TestUploadRejectsUnverifiedMaterial(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		revision string
	}{
		{"different_revision", strings.Repeat("0", 64)},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fake := newFakeCPA()
			fake.revisionOverride = scenario.revision
			client := newTestClient(t, fake)
			credential, err := BuildCodexCredential(DeliveryPayload{
				AccessToken: "a", RefreshToken: "r", IDToken: "i", WorkspaceID: "acct",
			}, "new@example.com", time.Unix(0, 0))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Upload(context.Background(), credential.Name, credential.AuthFile); !errors.Is(err, ErrCredentialIdentityMismatch) {
				t.Fatalf("unverified material must not return a success receipt: %v", err)
			}
		})
	}
}

func TestUploadRejectsTamperedMaterialBeforeWrite(t *testing.T) {
	fake := newFakeCPA()
	client := newTestClient(t, fake)
	credential, err := BuildCodexCredential(DeliveryPayload{
		AccessToken: "a", RefreshToken: "r", IDToken: "i", WorkspaceID: "acct",
	}, "new@example.com", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(credential.AuthFile, &payload); err != nil {
		t.Fatal(err)
	}
	payload["access_token"] = "changed"
	changed, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Upload(context.Background(), credential.Name, changed); !errors.Is(err, ErrCredentialIdentityMismatch) {
		t.Fatalf("tampered material accepted: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.files) != 0 {
		t.Fatal("tampered credential was uploaded")
	}
}

func TestListDoesNotConflateRevisionContracts(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]any{{
			"name": "codex.json", "provider": "codex", "revision": "opaque-version",
			"sha256": strings.Repeat("a", 64),
		}}})
	}))
	files, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Revision != "" {
		t.Fatal("unrelated revision treated as material digest")
	}
}

func TestUploadRejectsSameNameWrongIdentity(t *testing.T) {
	fake := newFakeCPA()
	client := newTestClient(t, fake)
	fake.seed("codex-new.json", "new@example.com", false)
	fake.accountOverride = "different-account"
	authFile := []byte(`{"type":"codex","access_token":"a","refresh_token":"r","id_token":"i","account_id":"expected-account","email":"new@example.com"}`)
	if _, err := client.Upload(context.Background(), "codex-new.json", authFile); !errors.Is(err, ErrCredentialIdentityMismatch) {
		t.Fatalf("wrong identity error=%v", err)
	}
}

func TestUploadRejectsUnidentifiableReadback(t *testing.T) {
	fake := newFakeCPA()
	fake.omitAccount = true
	client := newTestClient(t, fake)
	authFile := []byte(`{"type":"codex","access_token":"a","refresh_token":"r","id_token":"i","account_id":"expected-account","email":"new@example.com"}`)
	if _, err := client.Upload(context.Background(), "codex-new.json", authFile); !errors.Is(err, ErrCredentialIdentityMismatch) {
		t.Fatalf("missing identity error=%v", err)
	}
}

func TestUploadRejectsUnsafePayload(t *testing.T) {
	client := newTestClient(t, newFakeCPA())
	for _, payload := range [][]byte{nil, []byte(""), []byte("not json"), []byte(`{"a":1}`)} {
		if _, err := client.Upload(context.Background(), "codex-x.json", payload); err == nil {
			t.Fatalf("payload %q accepted", payload)
		}
	}
}

func TestRedirectIsRefused(t *testing.T) {
	fake := newFakeCPA()
	fake.redirect = true
	client := newTestClient(t, fake)
	if _, err := client.List(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
}

func TestBuildCodexCredentialUsesTokenIdentity(t *testing.T) {
	idToken := "header." + base64URL(`{"email":"User@Example.com","https://api.openai.com/auth":{"chatgpt_account_id":"acct-1"}}`) + ".signature"
	credential, err := BuildCodexCredential(DeliveryPayload{
		AccessToken: "access", RefreshToken: "refresh", IDToken: idToken,
		ExpiresIn: 1800, WorkspaceID: "workspace-1",
	}, "fallback@example.com", time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if credential.Email != "user@example.com" || !strings.HasPrefix(credential.Name, "codex-") || !strings.HasSuffix(credential.Name, ".json") {
		t.Fatalf("credential identity=%+v", credential)
	}
	var decoded map[string]any
	if err = json.Unmarshal(credential.AuthFile, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["account_id"] != "acct-1" || decoded["type"] != "codex" || decoded["expired"] != "2026-11-04T12:30:00Z" {
		t.Fatalf("auth file=%v", decoded)
	}
	if len(credential.Revision) != 64 || decoded["credential_revision"] != credential.Revision {
		t.Fatal("auth file must carry the expected material digest")
	}
}

func TestBuildCodexCredentialFallsBackToWorkspace(t *testing.T) {
	credential, err := BuildCodexCredential(DeliveryPayload{
		AccessToken: "access", RefreshToken: "refresh", IDToken: "header.payload.signature",
		WorkspaceID: "workspace-9",
	}, "fallback@example.com", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(credential.AuthFile, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["account_id"] != "workspace-9" || decoded["email"] != "fallback@example.com" {
		t.Fatalf("fallbacks not applied: %v", decoded)
	}
}

func TestBuildCodexCredentialFailsClosed(t *testing.T) {
	cases := []DeliveryPayload{
		{},
		{AccessToken: "a", RefreshToken: "r"},
		{AccessToken: "a", RefreshToken: "r", IDToken: "i"},
	}
	for index, payload := range cases {
		if _, err := BuildCodexCredential(payload, "", time.Now()); err == nil {
			t.Fatalf("case %d: expected rejection", index)
		}
	}
}

func TestBuildCodexPATCredential(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	expires := now.Add(365 * 24 * time.Hour)
	credential, err := BuildCodexPATCredential("session-jwt", "pat-token", "acct-1", "User@Example.com", expires, now)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(credential.AuthFile, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["access_token"] != "session-jwt" || decoded["refresh_token"] != nil || decoded["id_token"] != nil {
		t.Fatalf("unexpected PAT fields: %#v", decoded)
	}
	headers, ok := decoded["headers"].(map[string]any)
	if !ok || headers["authorization"] != "pat-token" {
		t.Fatalf("missing authorization header: %#v", decoded["headers"])
	}
	if decoded["expired"] != expires.Format(time.RFC3339) || credential.Email != "user@example.com" {
		t.Fatalf("unexpected expiry/identity: %#v", decoded)
	}
	if !validAuthFile(credential.AuthFile) {
		t.Fatal("PAT auth file rejected")
	}
}

func TestFileUnauthorizedIsStrict(t *testing.T) {
	for _, file := range []File{
		{StatusCode: http.StatusUnauthorized},
		{StatusMessage: "HTTP 401 unauthorized"},
		{LastError: "invalid_token"},
		{StatusMessage: "unauthorized (refresh token invalid)"},
		{StatusMessage: "Access token expired"},
	} {
		if !file.Unauthorized() {
			t.Fatalf("expected unauthorized: %#v", file)
		}
	}
	for _, file := range []File{
		{StatusMessage: "HTTP 429 rate limited"},
		{StatusMessage: "HTTP 403 forbidden"},
		{StatusMessage: "error 4010"},
		{StatusMessage: "not unauthorized"},
	} {
		if file.Unauthorized() {
			t.Fatalf("false unauthorized: %#v", file)
		}
	}
}

func TestCredentialNameIsStable(t *testing.T) {
	payload := DeliveryPayload{AccessToken: "a", RefreshToken: "r", IDToken: "i", WorkspaceID: "w"}
	first, err := BuildCodexCredential(payload, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCodexCredential(payload, "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != second.Name || first.Revision != second.Revision {
		t.Fatal("identical material must produce identical names")
	}
}

func base64URL(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func TestNewAcceptsExistingManagementKey(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://127.0.0.1:8318", APIKey: strings.Repeat("k", 15)}); err != nil {
		t.Fatalf("existing CPA key rejected: %v", err)
	}
	for _, key := range []string{"", "bad\nheader"} {
		if _, err := New(Config{BaseURL: "http://127.0.0.1:8318", APIKey: key}); err == nil {
			t.Fatal("invalid management key accepted")
		}
	}
}

func TestPATUploadVerifiesActualAuthorizationMaterial(t *testing.T) {
	fake := newFakeCPA()
	client := newTestClient(t, fake)
	credential, err := BuildCodexPATCredential("session-fixture", "pat-fixture", "workspace-fixture", "member@example.test", time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Upload(t.Context(), credential.Name, credential.AuthFile); err != nil {
		t.Fatal(err)
	}
	identity, err := client.CredentialIdentity(t.Context(), credential.Name)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AccountID != "workspace-fixture" || identity.Revision != credential.Revision {
		t.Fatal("authoritative identity mismatch")
	}
	fake.mu.Lock()
	fake.authorizationOverride = "wrong-pat-fixture"
	fake.mu.Unlock()
	if _, err = client.Upload(t.Context(), credential.Name, credential.AuthFile); !errors.Is(err, ErrCredentialIdentityMismatch) {
		t.Fatalf("wrong PAT accepted: %v", err)
	}
}
