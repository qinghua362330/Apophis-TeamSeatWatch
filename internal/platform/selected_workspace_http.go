package platform

import (
	"context"
	"encoding/json"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/browserenv"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const selectedWorkspaceOrigin = "https://chatgpt.com"
const selectedPageLimit = 100
const selectedMaxEntries = 1000
const selectedMaxMembers = 999

// OfficialSelectedWorkspaceReader uses only the four sourced GET capabilities
// with an explicitly exchanged Workspace bearer. Client must hand it an admitted
// egress-lease client; redirects and cookie jars are disabled on the copy.
type OfficialSelectedWorkspaceReader struct {
	Client DiscoveryClient
	// ResolveMemberIdentifiers supplies only identities previously confirmed by
	// authenticated joining in this selected workspace. It cannot infer members.
	ResolveMemberIdentifiers func(context.Context, []string) (map[string]string, error)
}

func (OfficialSelectedWorkspaceReader) Source() string { return "official_readonly" }

func (r OfficialSelectedWorkspaceReader) VerifySelectedWorkspace(ctx context.Context, access WorkspaceAccess, _, workspaceID string) (SelectedWorkspaceFacts, error) {
	facts := SelectedWorkspaceFacts{Permission: "unknown", Result: Result{ObservedAt: time.Now().UTC(), Completeness: Unknown, Outcome: OutcomeIncomplete}, Sources: []ReadEvidence{}}
	if r.Client == nil || !ValidateWorkspaceAccess(access, workspaceID, time.Now()) ||
		strings.TrimSpace(workspaceID) == "" || len(workspaceID) > 255 || strings.ContainsAny(workspaceID, "\r\n\x00") {
		return facts, nil
	}
	base, release, err := r.Client(ctx)
	if release != nil {
		defer release()
	}
	if err != nil || base == nil || base.Transport == nil || base.Timeout <= 0 {
		return facts, nil
	}
	client := *base
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	access.SessionID = uuid.NewString() // trusted, fresh per fact attempt
	read := selectedHTTPRead{client: &client, access: access, workspaceID: workspaceID, resolveMemberIdentifiers: r.ResolveMemberIdentifiers}
	var activeUntil *time.Time
	var paid *int
	var entitlements map[string]int
	var seatTypeCounts map[string]int
	var memberList, inviteList []Member
	var subOK, countsOK, membersOK, invitesOK bool
	var denied bool
	activeUntil, paid, entitlements, subOK = read.subscription(ctx, &facts)
	seatTypeCounts, countsOK = read.counts(ctx, &facts)
	memberList, membersOK = read.members(ctx, &facts)
	inviteList, invitesOK = read.invites(ctx, &facts)
	for _, source := range facts.Sources {
		if source.Permission == "denied" {
			denied = true
		}
	}
	facts.Result.ObservedAt = time.Now().UTC()
	if denied {
		facts.Permission = "denied"
		facts.Result.Outcome = OutcomeForbidden
		return facts, nil
	}
	// Each summary retains its own successful source. An incomplete roster must
	// not erase explicit subscription entitlements or imply management authority.
	if subOK {
		facts.Result.SeatEntitlements = entitlements
		facts.Result.ActiveUntil = activeUntil
	}
	if countsOK {
		facts.Result.SeatTypeCounts = seatTypeCounts
	}
	if !subOK || !countsOK || !membersOK || !invitesOK {
		facts.Result.Completeness = Partial
		return facts, nil
	}
	members, invites := len(memberList), len(inviteList)
	facts.Permission = "read"
	// A complete read is elevated to management only when the exchanged
	// bearer subject is present in the same fresh roster as an owner/admin.
	// Roster visibility alone never grants this; both identities must match.
	claimedWorkspace, subjectID := WorkspaceAccessIdentity(access)
	if claimedWorkspace == workspaceID && subjectID != "" {
		for _, member := range memberList {
			role := NormalizeWorkspaceRole(member.Role)
			if (role == "owner" || role == "admin") &&
				(member.PlatformMemberID == subjectID || member.PlatformAccountUserID == subjectID) {
				facts.Permission = "manage"
				break
			}
		}
	}
	facts.Result = Result{Outcome: OutcomeOperational, Completeness: Complete, ObservedAt: facts.Result.ObservedAt,
		ActiveUntil: activeUntil, SeatLimit: paid, MemberCount: &members, PendingInviteCount: &invites,
		SubscriptionStatus: facts.Result.SubscriptionStatus,
		SeatTypeCounts:     seatTypeCounts, SeatEntitlements: entitlements, Members: append(memberList, inviteList...)}
	return facts, nil
}

type selectedHTTPRead struct {
	client                   *http.Client
	access                   WorkspaceAccess
	workspaceID              string
	resolveMemberIdentifiers func(context.Context, []string) (map[string]string, error)
}

// No arbitrary URL reaches the transport. These are the entire request set.
func (r selectedHTTPRead) get(ctx context.Context, endpoint string) ([]byte, Outcome) {
	var raw string
	encoded := url.PathEscape(r.workspaceID)
	switch endpoint {
	case "subscriptions":
		raw = selectedWorkspaceOrigin + "/backend-api/subscriptions?account_id=" + url.QueryEscape(r.workspaceID)
	case "seat_type_counts":
		raw = selectedWorkspaceOrigin + "/backend-api/accounts/" + encoded + "/users/seat_type_counts"
	default:
		return nil, OutcomeIncomplete
	}
	return r.request(ctx, raw, endpoint)
}

func (r selectedHTTPRead) page(ctx context.Context, endpoint string, offset int) ([]byte, Outcome) {
	if offset < 0 || offset >= selectedMaxEntries {
		return nil, OutcomeIncomplete
	}
	var raw string
	encoded := url.PathEscape(r.workspaceID)
	switch endpoint {
	case "workspace_members":
		raw = selectedWorkspaceOrigin + "/backend-api/accounts/" + encoded + "/users?offset=" + strconv.Itoa(offset) + "&limit=100&query="
	case "outbound_invites":
		raw = selectedWorkspaceOrigin + "/backend-api/accounts/" + encoded + "/invites?limit=100&offset=" + strconv.Itoa(offset)
	default:
		return nil, OutcomeIncomplete
	}
	return r.request(ctx, raw, endpoint)
}

func (r selectedHTTPRead) request(ctx context.Context, raw, endpoint string) ([]byte, Outcome) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil || req.URL.Scheme != "https" || req.URL.Host != "chatgpt.com" || req.URL.User != nil || req.URL.Fragment != "" || req.Method != http.MethodGet {
		return nil, OutcomeIncomplete
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.access.AccessToken)
	req.Header.Set("Origin", selectedWorkspaceOrigin)
	req.Header.Set("Referer", selectedWorkspaceOrigin+"/admin/members")
	req.Header.Set("User-Agent", browserAuthUA)
	req.Header.Set("Accept-Language", browserenv.AcceptLanguage)
	req.Header.Set("Oai-Device-Id", r.access.DeviceID)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	if endpoint == "outbound_invites" {
		req.Header.Set("chatgpt-account-id", r.workspaceID)
		req.Header.Set("Oai-Session-Id", r.access.SessionID)
		req.Header.Set("Oai-Client-Build-Number", "9432397")
		req.Header.Set("Oai-Client-Version", "prod-1b777b39db92d7476d69bf3cd407f6b9a41f7410")
		req.Header.Set("Oai-Language", "zh-CN")
		req.Header.Set("X-Oai-Is-Client-Observation", "null")
		req.Header.Set("X-Oai-Is-Pending-Updates", `{"v":3,"updates":[]}`)
		req.Header.Set("X-OpenAI-Target-Path", "/backend-api/accounts/"+url.PathEscape(r.workspaceID)+"/invites")
		req.Header.Set("X-OpenAI-Target-Route", "/backend-api/accounts/{account_id}/invites")
	}
	for _, cookie := range r.access.Cookies {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	response, err := r.client.Do(req)
	if err != nil {
		return nil, Classify(0, "", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return nil, OutcomeUnauthorized
	}
	if response.StatusCode == http.StatusForbidden {
		return nil, OutcomeForbidden
	}
	if response.StatusCode != http.StatusOK {
		return nil, OutcomeIncomplete
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil || len(body) > maxResponseBody {
		return nil, OutcomeIncomplete
	}
	return body, OutcomeOperational
}

func appendReadSource(facts *SelectedWorkspaceFacts, endpoint string, observed time.Time, outcome Outcome) {
	completeness, permission := Unknown, "unknown"
	if outcome == OutcomeOperational {
		completeness, permission = Complete, "read"
	}
	if outcome == OutcomeUnauthorized || outcome == OutcomeForbidden {
		permission = "denied"
	}
	facts.Sources = append(facts.Sources, ReadEvidence{Source: endpoint, ObservedAt: observed, Outcome: outcome, Completeness: completeness, Permission: permission})
}

func (r selectedHTTPRead) subscription(ctx context.Context, facts *SelectedWorkspaceFacts) (*time.Time, *int, map[string]int, bool) {
	observed := time.Now().UTC()
	body, outcome := r.get(ctx, "subscriptions")
	var payload struct {
		ActiveUntil   string `json:"active_until"`
		IsActive      *bool  `json:"is_active"`
		IsDelinquent  *bool  `json:"is_delinquent"`
		SeatsInUse    *int   `json:"seats_in_use"`
		SeatsEntitled *int   `json:"seats_entitled"`
		SeatCapacity  []struct {
			Type string `json:"type"`
			Paid *int   `json:"paid"`
		} `json:"seat_capacity"`
	}
	var expiry *time.Time
	var paid *int
	entitlements := map[string]int{}
	if outcome == OutcomeOperational {
		if json.Unmarshal(body, &payload) != nil {
			outcome = OutcomeIncomplete
		} else {
			parsed, err := time.Parse(time.RFC3339, payload.ActiveUntil)
			if err == nil {
				utc := parsed.UTC()
				expiry = &utc
			}
			for _, item := range payload.SeatCapacity {
				seat, known := selectedSeatType(item.Type)
				if !known {
					continue
				}
				if _, duplicate := entitlements[seat]; duplicate || item.Paid == nil || *item.Paid < 0 {
					outcome = OutcomeIncomplete
					break
				}
				entitlements[seat] = *item.Paid
				if seat == "default" {
					paid = item.Paid
				}
			}
			if expiry == nil || paid == nil || *paid < 0 || payload.SeatsEntitled == nil || *payload.SeatsEntitled < 0 || payload.SeatsInUse == nil || *payload.SeatsInUse < 0 {
				outcome = OutcomeIncomplete
			}
		}
	}
	appendReadSource(facts, "subscriptions", observed, outcome)
	if outcome != OutcomeOperational {
		return nil, nil, nil, false
	}
	facts.Result.SubscriptionStatus = subscriptionStatus(payload.IsDelinquent, payload.IsActive, expiry, observed)
	return expiry, paid, entitlements, true
}

// Billing delinquency takes precedence over an active flag or future renewal.
// Missing platform flags never imply a healthy subscription.
func subscriptionStatus(delinquent, active *bool, expiry *time.Time, now time.Time) string {
	if delinquent != nil && *delinquent {
		return "delinquent"
	}
	if delinquent == nil || active == nil || expiry == nil {
		return "unknown"
	}
	if !*active {
		return "inactive"
	}
	if !expiry.After(now) {
		return "expired"
	}
	return "active"
}

func (r selectedHTTPRead) counts(ctx context.Context, facts *SelectedWorkspaceFacts) (map[string]int, bool) {
	observed := time.Now().UTC()
	body, outcome := r.get(ctx, "seat_type_counts")
	var payload struct {
		Counts struct {
			Default    *int `json:"default"`
			UsageBased *int `json:"usage_based"`
			Automation *int `json:"automation"`
			Prolite    *int `json:"prolite"`
		} `json:"seat_type_counts"`
	}
	if outcome == OutcomeOperational {
		if json.Unmarshal(body, &payload) != nil || payload.Counts.Default == nil || payload.Counts.UsageBased == nil || payload.Counts.Automation == nil || payload.Counts.Prolite == nil ||
			*payload.Counts.Default < 0 || *payload.Counts.UsageBased < 0 || *payload.Counts.Automation < 0 || *payload.Counts.Prolite < 0 {
			outcome = OutcomeIncomplete
		}
	}
	appendReadSource(facts, "seat_type_counts", observed, outcome)
	if outcome != OutcomeOperational {
		return nil, false
	}
	return map[string]int{
		"default": *payload.Counts.Default, "usage_based": *payload.Counts.UsageBased,
		"automation": *payload.Counts.Automation, "prolite": *payload.Counts.Prolite,
	}, true
}

type selectedPage[T any] struct {
	Items  []T  `json:"items"`
	Total  *int `json:"total"`
	Limit  *int `json:"limit"`
	Offset *int `json:"offset"`
}

func fetchSelectedPages[T any](ctx context.Context, r selectedHTTPRead, endpoint string, convert func(T) (Member, bool)) ([]Member, Outcome) {
	var entries []Member
	seen := map[string]bool{}
	invitationAccounts := map[string]Member{}
	declared := -1
	maximum := selectedMaxEntries
	if endpoint == "workspace_members" {
		maximum = selectedMaxMembers
	}
	for offset := 0; ; {
		body, outcome := r.page(ctx, endpoint, offset)
		if outcome != OutcomeOperational {
			return nil, outcome
		}
		var page selectedPage[T]
		if json.Unmarshal(body, &page) != nil || page.Total == nil || page.Offset == nil || page.Limit == nil || page.Items == nil || *page.Total < 0 || *page.Total > maximum || *page.Offset != offset || *page.Limit != selectedPageLimit || len(page.Items) > *page.Limit || len(page.Items) > *page.Total-offset {
			return nil, OutcomeIncomplete
		}
		if declared < 0 {
			declared = *page.Total
		} else if declared != *page.Total {
			return nil, OutcomeIncomplete
		}
		for _, raw := range page.Items {
			member, ok := convert(raw)
			identityKey := member.Kind + ":identifier:" + strings.ToLower(member.Identifier)
			memberKey := member.Kind + ":member_id:" + strings.ToLower(strings.TrimSpace(member.PlatformMemberID))
			accountUserKey := member.Kind + ":account_user_id:" + strings.ToLower(strings.TrimSpace(member.PlatformAccountUserID))
			if !ok {
				return nil, OutcomeIncomplete
			}
			// Remote invitation IDs are individual attempts. The local snapshot models
			// pending accounts once, while pagination still advances by raw records.
			if endpoint == "outbound_invites" {
				if previous, exists := invitationAccounts[identityKey]; exists {
					if previous != member {
						return nil, OutcomeIncomplete
					}
					continue
				}
				invitationAccounts[identityKey] = member
			}
			if member.Identifier != "" && seen[identityKey] || member.PlatformMemberID != "" && seen[memberKey] || member.PlatformAccountUserID != "" && seen[accountUserKey] {
				return nil, OutcomeIncomplete
			}
			seen[identityKey] = true
			if member.PlatformMemberID != "" {
				seen[memberKey] = true
			}
			if member.PlatformAccountUserID != "" {
				seen[accountUserKey] = true
			}
			entries = append(entries, member)
		}
		offset += len(page.Items)
		if offset == declared {
			return entries, OutcomeOperational
		}
		if len(page.Items) == 0 || offset >= selectedMaxEntries {
			return nil, OutcomeIncomplete
		}
	}
}

func (r selectedHTTPRead) members(ctx context.Context, facts *SelectedWorkspaceFacts) ([]Member, bool) {
	observed := time.Now().UTC()
	entries, outcome := r.memberEntries(ctx)
	missing := []string{}
	for _, entry := range entries {
		if entry.Identifier == "" {
			missing = append(missing, entry.PlatformMemberID)
		}
	}
	if outcome == OutcomeOperational && len(missing) > 0 && r.resolveMemberIdentifiers != nil {
		identifiers, err := r.resolveMemberIdentifiers(ctx, missing)
		identityOutcome := OutcomeOperational
		if err != nil {
			identityOutcome = OutcomeIncomplete
		} else {
			for index := range entries {
				if entries[index].Identifier == "" {
					entries[index].Identifier = strings.ToLower(strings.TrimSpace(identifiers[entries[index].PlatformMemberID]))
				}
			}
		}
		appendReadSource(facts, "confirmed_member_identities", time.Now().UTC(), identityOutcome)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Identifier == "" || len(entry.Identifier) > 254 || strings.ContainsAny(entry.Identifier, "\r\n\x00") || seen[entry.Identifier] {
			outcome = OutcomeIncomplete
			break
		}
		seen[entry.Identifier] = true
	}
	appendReadSource(facts, "workspace_members", observed, outcome)
	return entries, outcome == OutcomeOperational
}

// Member IDs and pagination must be complete. An undisclosed email is retained
// as unknown identity; it cannot prove a recipient absent or support removal.
func (r selectedHTTPRead) memberEntries(ctx context.Context) ([]Member, Outcome) {
	type item struct {
		ID            string          `json:"id"`
		AccountUserID string          `json:"account_user_id"`
		Email         string          `json:"email"`
		Role          string          `json:"role"`
		SeatType      string          `json:"seat_type"`
		Deactivated   json.RawMessage `json:"deactivated_time"`
	}
	entries, outcome := fetchSelectedPages[item](ctx, r, "workspace_members", func(raw item) (Member, bool) {
		identifier := strings.ToLower(strings.TrimSpace(raw.Email))
		id := strings.TrimSpace(raw.ID)
		accountUserID := strings.TrimSpace(raw.AccountUserID)
		if id == "" {
			id = accountUserID
		}
		seatType, seatOK := selectedSeatType(raw.SeatType)
		status := "listed"
		if len(raw.Deactivated) > 0 && string(raw.Deactivated) != "null" {
			status = "deactivated"
		}
		return Member{Kind: "member", PlatformMemberID: id, PlatformAccountUserID: accountUserID, Identifier: identifier, Status: status, Role: raw.Role, SeatType: seatType}, id != "" && len(identifier) <= 254 && len(raw.Role) <= 64 && seatOK
	})
	return entries, outcome
}

func (r selectedHTTPRead) invites(ctx context.Context, facts *SelectedWorkspaceFacts) ([]Member, bool) {
	observed := time.Now().UTC()
	type item struct {
		EmailAddress string          `json:"email_address"`
		Email        string          `json:"email"`
		Status       json.RawMessage `json:"status"`
		SeatType     string          `json:"seat_type"`
	}
	entries, outcome := fetchSelectedPages[item](ctx, r, "outbound_invites", func(raw item) (Member, bool) {
		identifier := strings.ToLower(strings.TrimSpace(raw.EmailAddress))
		if identifier == "" {
			identifier = strings.ToLower(strings.TrimSpace(raw.Email))
		}
		var status string
		if len(raw.Status) == 0 || json.Unmarshal(raw.Status, &status) != nil {
			status = strings.TrimSpace(string(raw.Status))
		}
		if status != "pending" && status != "2" {
			return Member{}, false
		}
		seatType, seatOK := selectedSeatType(raw.SeatType)
		return Member{Kind: "pending_invite", Identifier: identifier, Status: "pending", SeatType: seatType}, identifier != "" && len(identifier) <= 254 && seatOK
	})
	appendReadSource(facts, "outbound_invites", observed, outcome)
	return entries, outcome == OutcomeOperational
}

func selectedSeatType(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "default", "usage_based", "automation", "prolite":
		return strings.ToLower(strings.TrimSpace(value)), true
	default:
		return "", false
	}
}
