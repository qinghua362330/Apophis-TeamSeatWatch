package runtime

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
)

func TestCPAReplacementBindsExpectedIdentity(t *testing.T) {
	for _, test := range []struct {
		name, email, workspace string
		valid                  bool
	}{
		{"correct", "spare@example.com", "workspace-1", true},
		{"wrong member", "other@example.com", "workspace-1", false},
		{"wrong workspace", "spare@example.com", "workspace-2", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"email":"spare@example.com","https://api.openai.com/auth":{"chatgpt_account_id":"workspace-1"}}`)) + ".signature"
			raw, err := json.Marshal(cpacred.DeliveryPayload{AccessToken: "access", RefreshToken: "refresh", IDToken: token, WorkspaceID: test.workspace})
			if err != nil {
				t.Fatal(err)
			}
			_, err = buildCPAReplacement(raw, test.email)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}
