package cpacred

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestVerifyRequiresSuccessfulUpstreamAndSupportsLegacyEndpoint(t *testing.T) {
	for _, upstreamStatus := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(upstreamStatus), func(t *testing.T) {
			legacyCalls := 0
			fallbackCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v0/management/auth-files" {
					_, _ = w.Write([]byte(`{"files":[{"name":"acct.json","auth_index":"idx-1","provider":"codex","account_id":"acct","disabled":false}]}`))
					return
				}
				if r.URL.Path == "/v0/management/auth-files/download" {
					_, _ = w.Write([]byte(`{"type":"codex","account_id":"acct","email":"user@example.com","access_token":"secret-access","refresh_token":"secret-refresh","id_token":"secret-id"}`))
					return
				}
				if r.URL.Path == "/v0/management/api-call" {
					legacyCalls++
					if upstreamStatus == http.StatusOK {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_, _ = w.Write([]byte(`{"status_code":` + strconv.Itoa(upstreamStatus) + `}`))
					return
				}
				if r.URL.Path == "/v0/management/requests/api-call" {
					fallbackCalls++
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					raw, _ := json.Marshal(body)
					if strings.Contains(string(raw), "secret-access") {
						t.Error("verification request leaked credential material")
					}
					_, _ = w.Write([]byte(`{"status_code":200}`))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			client, err := New(Config{BaseURL: server.URL, APIKey: testKey})
			if err != nil {
				t.Fatal(err)
			}
			err = client.Verify(context.Background(), "acct.json")
			if upstreamStatus == http.StatusOK {
				if err != nil {
					t.Fatal(err)
				}
				if legacyCalls != 1 || fallbackCalls != 1 {
					t.Fatalf("calls = %d/%d, want legacy fallback", legacyCalls, fallbackCalls)
				}
			} else if err == nil {
				t.Fatalf("status %d unexpectedly verified", upstreamStatus)
			}
		})
	}
}

func TestVerifyTreatsListingAccountAsDisplayLabel(t *testing.T) {
	for _, tc := range []struct {
		name, accountID string
		wantOK          bool
	}{
		{"email display label", "", true},
		{"explicit matching identity", "workspace-fixture", true},
		{"explicit different identity", "different-workspace", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v0/management/auth-files":
					_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]any{{"name": "acct.json", "auth_index": "idx-1", "provider": "codex", "account": "user@example.test", "account_id": tc.accountID, "disabled": false}}})
				case "/v0/management/auth-files/download":
					_, _ = w.Write([]byte(`{"type":"codex","account_id":"workspace-fixture","email":"user@example.test","access_token":"fixture-access","refresh_token":"fixture-refresh","id_token":"fixture-id"}`))
				case "/v0/management/api-call":
					calls++
					var payload struct {
						Header map[string]string `json:"header"`
					}
					_ = json.NewDecoder(r.Body).Decode(&payload)
					if payload.Header["Chatgpt-Account-Id"] != "workspace-fixture" {
						t.Error("verification used the display label as workspace identity")
					}
					_, _ = w.Write([]byte(`{"status_code":200}`))
				default:
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			client, err := New(Config{BaseURL: server.URL, APIKey: testKey})
			if err != nil {
				t.Fatal(err)
			}
			err = client.Verify(t.Context(), "acct.json")
			if (err == nil) != tc.wantOK {
				t.Fatalf("Verify error=%v wantOK=%v", err, tc.wantOK)
			}
			if !tc.wantOK && calls != 0 {
				t.Fatal("mismatched explicit identity reached upstream")
			}
		})
	}
}
