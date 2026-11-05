package cpacred

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var errCPAUpstreamVerification = errors.New("CPA credential upstream verification failed")

// Verify proves that CPA can use the named Codex credential against the
// upstream ChatGPT usage endpoint. A management API-call response is only
// successful when both the management request and its upstream request return
// HTTP 200; response bodies are deliberately not included in errors.
func (c *Client) Verify(ctx context.Context, name string) error {
	file, err := c.Lookup(ctx, name)
	if err != nil {
		return err
	}
	if file.Provider != "codex" || file.Disabled || strings.TrimSpace(file.AuthIndex) == "" {
		return errCPAUpstreamVerification
	}
	identity, err := c.CredentialIdentity(ctx, file.Name)
	if err != nil || identity.Provider != "codex" || identity.AccountID == "" || identity.AccountID != file.AccountID && file.AccountID != "" {
		return errCPAUpstreamVerification
	}
	payload := map[string]any{
		"auth_index": file.AuthIndex,
		"method":     http.MethodGet,
		"url":        "https://chatgpt.com/backend-api/wham/usage?workspace_id=" + url.QueryEscape(identity.AccountID),
		"header": map[string]string{
			"Authorization":      "Bearer $TOKEN$",
			"User-Agent":         "codex_cli_rs/0.163.0",
			"Accept":             "application/json",
			"Chatgpt-Account-Id": identity.AccountID,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errCPAUpstreamVerification
	}
	response, status, err := c.do(ctx, http.MethodPost, "/v0/management/api-call", body, "application/json")
	if err != nil {
		return errCPAUpstreamVerification
	}
	if status == http.StatusNotFound {
		response, status, err = c.do(ctx, http.MethodPost, "/v0/management/requests/api-call", body, "application/json")
		if err != nil {
			return errCPAUpstreamVerification
		}
	}
	if status != http.StatusOK {
		return errCPAUpstreamVerification
	}
	var result struct {
		StatusCode int `json:"status_code"`
	}
	if json.Unmarshal(response, &result) != nil || result.StatusCode != http.StatusOK {
		return errCPAUpstreamVerification
	}
	return nil
}
