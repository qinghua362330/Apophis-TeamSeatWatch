package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type selectedTransport struct {
	mu     sync.Mutex
	calls  []string
	answer func(*http.Request) (int, string, http.Header)
}

func (t *selectedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "chatgpt.com" || !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") ||
		!strings.Contains(req.Header.Get("Cookie"), "__Secure-next-auth.session-token=saved-cookie") ||
		(strings.HasSuffix(req.URL.Path, "/invites") && req.Header.Get("Oai-Session-Id") == "") {
		panic("unexpected platform operation or credential")
	}
	t.mu.Lock()
	t.calls = append(t.calls, req.URL.String())
	t.mu.Unlock()
	status, body, headers := t.answer(req)
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}
func workspaceFixtureTokenWithClaims(claims map[string]any) string {
	claims["exp"] = time.Now().Add(2 * time.Hour).Unix()
	payload, _ := json.Marshal(claims)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
func workspaceFixtureToken(workspaceID string) string {
	return workspaceFixtureTokenWithClaims(map[string]any{"https://api.openai.com/auth": map[string]any{
		"chatgpt_account_id": workspaceID, "chatgpt_plan_type": "team", "scp": []string{"organization.read"}}})
}
func selectedSession() WorkspaceAccess {
	return WorkspaceAccess{AccessToken: workspaceFixtureToken("canonical-space"), WorkspaceID: "canonical-space", DeviceID: "saved-device", SessionID: uuid.NewString(), Cookies: []SessionCookie{
		{Name: "__Secure-next-auth.session-token", Value: "saved-cookie"}, {Name: "_account", Value: "canonical-space"}, {Name: "oai-workspace", Value: "canonical-space"}}, ExpiresAt: time.Now().Add(time.Hour)}
}
func readerFixture(t *selectedTransport) OfficialSelectedWorkspaceReader {
	return OfficialSelectedWorkspaceReader{Client: func(context.Context) (*http.Client, func(), error) {
		return &http.Client{Transport: t, Timeout: time.Second}, func() {}, nil
	}}
}
func selectedOK(req *http.Request) (int, string, http.Header) {
	path := req.URL.Path
	query := req.URL.Query()
	switch {
	case path == "/backend-api/subscriptions" && query.Get("account_id") == "canonical-space":
		return 200, `{"active_until":"2027-11-02T00:00:00Z","seats_in_use":4,"seats_entitled":3,"seat_capacity":[{"type":"default","paid":3}]}`, nil
	case path == "/backend-api/accounts/canonical-space/users/seat_type_counts":
		return 200, `{"seat_type_counts":{"default":2,"usage_based":0,"automation":0,"prolite":0}}`, nil
	case path == "/backend-api/accounts/canonical-space/users" && query.Get("offset") == "0" && query.Get("limit") == "100" && query.Has("query"):
		return 200, `{"total":2,"limit":100,"offset":0,"items":[{"id":"user-a","email":"a@example.test","role":"owner","seat_type":"prolite"}]}`, nil
	case path == "/backend-api/accounts/canonical-space/users" && query.Get("offset") == "1":
		return 200, `{"total":2,"limit":100,"offset":1,"items":[{"id":"user-b","email":"b@example.test","role":"standard-user","seat_type":"default"}]}`, nil
	case path == "/backend-api/accounts/canonical-space/invites" && query.Get("offset") == "0" && query.Get("limit") == "100" && req.Header.Get("chatgpt-account-id") == "canonical-space":
		return 200, `{"total":2,"limit":100,"offset":0,"items":[{"email_address":"c@example.test","seat_type":"default","status":2}]}`, nil
	case path == "/backend-api/accounts/canonical-space/invites" && query.Get("offset") == "1":
		return 200, `{"total":2,"limit":100,"offset":1,"items":[{"email":"d@example.test","status":"pending","seat_type":"prolite"}]}`, nil
	default:
		panic("unexpected endpoint: " + req.URL.String())
	}
}

func TestSelectedWorkspaceSubscriptionStatusUsesBillingFlags(t *testing.T) {
	for _, scenario := range []struct{ name, flags, status string }{
		{"delinquent_despite_active_future_expiry", `,"is_active":true,"is_delinquent":true`, "delinquent"},
		{"active_with_explicit_healthy_billing", `,"is_active":true,"is_delinquent":false`, "active"},
		{"inactive", `,"is_active":false,"is_delinquent":false`, "inactive"},
		{"missing_billing", `,"is_active":true`, "unknown"},
		{"missing_active", `,"is_delinquent":false`, "unknown"},
		{"missing_flags", ``, "unknown"},
		{"null_billing", `,"is_active":true,"is_delinquent":null`, "unknown"},
	} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/partial=%t", scenario.name, partial), func(t *testing.T) {
				transport := &selectedTransport{answer: func(req *http.Request) (int, string, http.Header) {
					if req.URL.Path == "/backend-api/subscriptions" {
						return 200, `{"active_until":"2027-11-02T00:00:00Z","seats_in_use":4,"seats_entitled":3,"seat_capacity":[{"type":"default","paid":3}]` + scenario.flags + `}`, nil
					}
					if partial && strings.HasSuffix(req.URL.Path, "/users") {
						return 503, `{}`, nil
					}
					return selectedOK(req)
				}}
				facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), selectedSession(), "mother-id", "canonical-space")
				if err != nil || facts.Result.SubscriptionStatus != scenario.status || facts.Result.ActiveUntil == nil || (facts.Result.Completeness == Partial) != partial {
					t.Fatalf("billing state lost or guessed: %+v err=%v", facts.Result, err)
				}
			})
		}
	}
	delinquent, active := true, true
	expired := time.Now().Add(-time.Hour)
	if subscriptionStatus(&delinquent, &active, &expired, time.Now()) != "delinquent" {
		t.Fatal("expiry overrode delinquency")
	}
	delinquent = false
	if subscriptionStatus(&delinquent, &active, &expired, time.Now()) != "expired" {
		t.Fatal("expired subscription shown active")
	}
}
func TestOfficialSelectedWorkspaceReaderPagedFactsAndReadOnlyBoundary(t *testing.T) {
	transport := &selectedTransport{answer: selectedOK}
	facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), selectedSession(), "mother-id", "canonical-space")
	if err != nil || facts.Permission != "read" || facts.Result.Outcome != OutcomeOperational || facts.Result.Completeness != Complete ||
		facts.Result.SeatLimit == nil || *facts.Result.SeatLimit != 3 || facts.Result.MemberCount == nil || *facts.Result.MemberCount != 2 ||
		facts.Result.PendingInviteCount == nil || *facts.Result.PendingInviteCount != 2 || len(facts.Result.Members) != 4 || len(facts.Sources) != 4 ||
		facts.Result.SeatTypeCounts["default"] != 2 || facts.Result.SeatTypeCounts["prolite"] != 0 || facts.Result.Members[0].SeatType != "prolite" || facts.Result.Members[2].SeatType != "default" || facts.Result.Members[3].SeatType != "prolite" {
		t.Fatalf("paired/paged fact result=%+v err=%v", facts, err)
	}
	for _, evidence := range facts.Sources {
		if evidence.Permission != "read" || evidence.Completeness != Complete || evidence.ObservedAt.IsZero() {
			t.Fatalf("source missing: %+v", evidence)
		}
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.calls) != 6 {
		t.Fatalf("expected six GETs, got %v", transport.calls)
	}
}

func TestOfficialSelectedWorkspaceReaderProvesOwnerManagement(t *testing.T) {
	transport := &selectedTransport{answer: selectedOK}
	access := selectedSession()
	access.AccessToken = workspaceFixtureTokenWithClaims(map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "canonical-space",
			"chatgpt_user_id":    "user-a",
			"chatgpt_plan_type":  "team",
			"scp":                []string{"organization.read"},
		},
	})
	facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), access, "mother-id", "canonical-space")
	if err != nil || facts.Permission != "manage" || facts.Result.Completeness != Complete {
		t.Fatalf("owner identity was not bound to management evidence: facts=%+v err=%v", facts, err)
	}
	access.AccessToken = workspaceFixtureTokenWithClaims(map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "canonical-space",
			"chatgpt_user_id":    "user-b",
			"chatgpt_plan_type":  "team",
			"scp":                []string{"organization.read"},
		},
	})
	facts, err = readerFixture(&selectedTransport{answer: selectedOK}).VerifySelectedWorkspace(context.Background(), access, "mother-id", "canonical-space")
	if err != nil || facts.Permission != "read" {
		t.Fatalf("non-owner identity gained management evidence: facts=%+v err=%v", facts, err)
	}
}

func TestSelectedWorkspaceEntitlementsAreSubscriptionFacts(t *testing.T) {
	for _, scenario := range []struct {
		name, capacity string
		premiumKnown   bool
		complete       bool
	}{
		{"ordinary_and_premium", `[{"type":"default","paid":2},{"type":"prolite","paid":9}]`, true, true},
		{"missing_premium_is_unknown", `[{"type":"default","paid":2}]`, false, true},
		{"duplicate_class_is_ambiguous", `[{"type":"default","paid":2},{"type":"prolite","paid":9},{"type":"prolite","paid":8}]`, false, false},
		{"negative_amount_is_invalid", `[{"type":"default","paid":2},{"type":"prolite","paid":-1}]`, false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			transport := &selectedTransport{answer: func(req *http.Request) (int, string, http.Header) {
				if req.URL.Path == "/backend-api/subscriptions" {
					return 200, `{"active_until":"2027-11-02T00:00:00Z","seats_in_use":4,"seats_entitled":11,"seat_capacity":` + scenario.capacity + `}`, nil
				}
				return selectedOK(req)
			}}
			facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), selectedSession(), "mother-id", "canonical-space")
			if err != nil || (facts.Result.Completeness == Complete) != scenario.complete {
				t.Fatalf("completeness=%s err=%v", facts.Result.Completeness, err)
			}
			premium, known := facts.Result.SeatEntitlements["prolite"]
			if known != scenario.premiumKnown || known && premium != 9 || scenario.complete && facts.Result.SeatEntitlements["default"] != 2 || !scenario.complete && len(facts.Result.SeatEntitlements) != 0 {
				t.Fatalf("subscription amounts must not use members, totals, or guesses: %v", facts.Result.SeatEntitlements)
			}
		})
	}

	transport := &selectedTransport{answer: func(req *http.Request) (int, string, http.Header) {
		if req.URL.Path == "/backend-api/subscriptions" {
			return 200, `{"active_until":"2027-11-02T00:00:00Z","seats_in_use":11,"seats_entitled":11,"seat_capacity":[{"type":"default","paid":2},{"type":"prolite","paid":9}]}`, nil
		}
		if strings.HasSuffix(req.URL.Path, "/users") {
			return 200, `{"total":1,"limit":100,"offset":0,"items":[{"id":"undisclosed-user","email":null,"role":"standard-user","seat_type":"prolite"}]}`, nil
		}
		return selectedOK(req)
	}}
	facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), selectedSession(), "mother-id", "canonical-space")
	if err != nil || facts.Result.Completeness != Partial || facts.Permission == "read" || facts.Result.SeatEntitlements["default"] != 2 || facts.Result.SeatEntitlements["prolite"] != 9 || facts.Result.SeatTypeCounts["default"] != 2 {
		t.Fatalf("independent amounts must survive an incomplete roster without granting authority: %+v err=%v", facts, err)
	}
}

func TestSelectedWorkspaceUsesConfirmedIdentityForUndisclosedMember(t *testing.T) {
	for _, scenario := range []struct {
		name, identifier string
		failed, complete bool
	}{
		{"confirmed_account", "child@example.test", false, true},
		{"unmapped_is_unknown", "", false, false},
		{"duplicate_identity_is_ambiguous", "a@example.test", false, false},
		{"registry_read_failure", "child@example.test", true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			transport := &selectedTransport{answer: func(req *http.Request) (int, string, http.Header) {
				if strings.HasSuffix(req.URL.Path, "/users") {
					return 200, `{"total":2,"limit":100,"offset":0,"items":[{"id":"owner","email":"a@example.test","role":"owner","seat_type":"default"},{"id":"undisclosed-user","email":null,"role":"standard-user","seat_type":"prolite"}]}`, nil
				}
				return selectedOK(req)
			}}
			reader := readerFixture(transport)
			reader.ResolveMemberIdentifiers = func(_ context.Context, ids []string) (map[string]string, error) {
				if len(ids) != 1 || ids[0] != "undisclosed-user" {
					t.Fatalf("identity query expanded beyond undisclosed IDs: %v", ids)
				}
				if scenario.failed {
					return nil, fmt.Errorf("registry unavailable")
				}
				return map[string]string{"undisclosed-user": scenario.identifier}, nil
			}
			facts, err := reader.VerifySelectedWorkspace(context.Background(), selectedSession(), "mother-id", "canonical-space")
			if err != nil || (facts.Result.Completeness == Complete) != scenario.complete || (facts.Permission == "read") != scenario.complete {
				t.Fatalf("resolved facts=%+v err=%v", facts, err)
			}
			if scenario.complete && facts.Result.Members[1].Identifier != "child@example.test" {
				t.Fatal("confirmed recipient was not restored")
			}
		})
	}
}
func TestOfficialSelectedWorkspaceReaderRejectsPartialForbiddenAndRedirect(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		override   func(*http.Request) (int, string, http.Header)
		status     Outcome
		permission string
	}{
		{"incomplete_invite_page", func(req *http.Request) (int, string, http.Header) {
			if strings.Contains(req.URL.Path, "/invites") && req.URL.Query().Get("offset") == "1" {
				return 200, `{"total":2,"limit":100,"offset":1,"items":[]}`, nil
			}
			return selectedOK(req)
		}, OutcomeIncomplete, "unknown"},
		{"forbidden_members", func(req *http.Request) (int, string, http.Header) {
			if strings.HasSuffix(req.URL.Path, "/users") {
				return 403, `{}`, nil
			}
			return selectedOK(req)
		}, OutcomeForbidden, "denied"},
		{"redirect_subscriptions", func(req *http.Request) (int, string, http.Header) {
			if req.URL.Path == "/backend-api/subscriptions" {
				return 302, "", http.Header{"Location": []string{"https://attacker.example/steal"}}
			}
			return selectedOK(req)
		}, OutcomeIncomplete, "unknown"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			transport := &selectedTransport{answer: scenario.override}
			facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), selectedSession(), "mother-id", "canonical-space")
			if err != nil || facts.Result.Outcome != scenario.status || facts.Permission != scenario.permission || (facts.Result.ActiveUntil != nil) != (scenario.name == "incomplete_invite_page") || facts.Result.SeatLimit != nil || len(facts.Result.Members) != 0 || len(facts.Sources) != 4 {
				t.Fatalf("partial/denied facts=%+v err=%v", facts, err)
			}
		})
	}
}
func TestOfficialSelectedWorkspaceReaderRejectsInvalidPersonalSessionWithoutIO(t *testing.T) {
	transport := &selectedTransport{answer: selectedOK}
	facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), WorkspaceAccess{}, "mother-id", "canonical-space")
	if err != nil || facts.Permission != "unknown" || len(transport.calls) != 0 {
		t.Fatalf("invalid session used transport: %+v %v", facts, err)
	}
}

func TestOfficialSelectedWorkspaceReaderMemberBoundary999(t *testing.T) {
	for _, declared := range []int{999, 1000} {
		t.Run(strconv.Itoa(declared), func(t *testing.T) {
			transport := &selectedTransport{answer: func(r *http.Request) (int, string, http.Header) {
				if strings.HasSuffix(r.URL.Path, "/users") {
					offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
					items := []map[string]string{}
					// The rejected 1000 declaration has no members: this fixture never
					// constructs a Workspace containing more than 999 actual members.
					if declared == 999 {
						for i := offset; i < min(offset+100, 999); i++ {
							items = append(items, map[string]string{"id": fmt.Sprintf("member-%d", i), "email": fmt.Sprintf("member%d@boundary.test", i), "role": "member", "seat_type": "prolite"})
						}
					}
					raw, _ := json.Marshal(map[string]any{"total": declared, "limit": 100, "offset": offset, "items": items})
					return 200, string(raw), nil
				}
				return selectedOK(r)
			}}
			facts, err := readerFixture(transport).VerifySelectedWorkspace(context.Background(), selectedSession(), "mother", "canonical-space")
			if err != nil {
				t.Fatal(err)
			}
			if declared == 999 && (facts.Result.Outcome != OutcomeOperational || facts.Result.MemberCount == nil || *facts.Result.MemberCount != 999) {
				t.Fatalf("999 members rejected: %+v", facts)
			}
			if declared == 1000 && facts.Result.Completeness == Complete {
				t.Fatal("over-limit declared membership reported complete")
			}
		})
	}
}

func TestSelectedWorkspaceRepeatedPendingInvitesKeepCompletePagination(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		fixture := &selectedTransport{answer: func(req *http.Request) (int, string, http.Header) {
			if strings.HasSuffix(req.URL.Path, "/invites") {
				if req.URL.Query().Get("offset") == "0" {
					seat := "default"
					if conflict {
						seat = "prolite"
					}
					return 200, `{"total":3,"limit":100,"offset":0,"items":[{"email_address":"a@example.test","status":2,"seat_type":"default"},{"email_address":"a@example.test","status":2,"seat_type":"` + seat + `"}]}`, nil
				}
				if req.URL.Query().Get("offset") == "2" {
					return 200, `{"total":3,"limit":100,"offset":2,"items":[{"email_address":"b@example.test","status":2,"seat_type":"default"}]}`, nil
				}
				t.Fatal("invitation pagination skipped raw records")
			}
			return selectedOK(req)
		}}
		facts, err := readerFixture(fixture).VerifySelectedWorkspace(t.Context(), selectedSession(), "mother", "canonical-space")
		if err != nil {
			t.Fatal(err)
		}
		if conflict {
			if facts.Result.Completeness == Complete {
				t.Fatal("conflicting invitation seat facts accepted")
			}
		} else if facts.Result.Completeness != Complete || facts.Result.PendingInviteCount == nil || *facts.Result.PendingInviteCount != 2 {
			t.Fatalf("repeated invitations blocked complete distinct-account snapshot: %+v", facts.Result)
		}
	}
}
