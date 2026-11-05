package cpacred

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWithProxyEmbedsProxyAndChangesRevision(t *testing.T) {
	original, err := BuildCodexCredential(DeliveryPayload{AccessToken: "a", RefreshToken: "r", IDToken: testIDToken(), WorkspaceID: "acct", ExpiresIn: 3600}, "u@example.com", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := WithProxy(original, "socks5://127.0.0.1:19080")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != original.Name || updated.Revision == original.Revision {
		t.Fatal("proxy must preserve name and change revision")
	}
	var payload map[string]any
	if err := json.Unmarshal(updated.AuthFile, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["proxy_url"] != "socks5://127.0.0.1:19080" || payload["credential_revision"] != updated.Revision {
		t.Fatalf("proxy payload not committed: %#v", payload)
	}
	if unchanged, err := WithProxy(original, ""); err != nil || unchanged.Revision != original.Revision {
		t.Fatal("empty proxy must preserve legacy credential")
	}
}

func TestWithProxyRejectsUnsupportedOrUnsafeURL(t *testing.T) {
	credential := Credential{AuthFile: []byte(`{"access_token":"a","account_id":"acct"}`)}
	for _, proxy := range []string{"vless://host:443", "socks5://host:1080/path", "http://host:8080?secret=x", "http://host" + "\n"} {
		if _, err := WithProxy(credential, proxy); err == nil {
			t.Fatalf("expected rejection for %q", proxy)
		}
	}
}

func testIDToken() string {
	return "eyJhbGciOiJub25lIn0.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdCJ9fQ.sig"
}
