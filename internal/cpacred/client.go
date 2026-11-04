// Package cpacred speaks to the local CPA management API for credential
// quarantine and replacement delivery.
//
// Every request is pinned to a loopback destination, refuses redirects and
// environment proxies, and never logs or returns credential material. The
// package performs no scheduling: callers own retries and durable receipts.
package cpacred

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxResponseBytes bounds every management response we decode.
	maxResponseBytes = 4 << 20
	// maxUploadBytes bounds one auth-file upload.
	maxUploadBytes = 1 << 20
	defaultTimeout = 15 * time.Second
)

var (
	// ErrNotConfigured reports that no usable management endpoint was provided.
	ErrNotConfigured = errors.New("CPA management endpoint is not configured")
	// ErrInvalidCredentialName reports a name CPA would reject or mis-resolve.
	ErrInvalidCredentialName = errors.New("CPA credential name is invalid")
	// ErrCredentialNotFound reports that CPA has no auth file for the selector.
	ErrCredentialNotFound = errors.New("CPA credential was not found")
	// ErrCredentialIdentityMismatch means CPA accepted an upload but its
	// authoritative inventory does not identify the expected account.
	ErrCredentialIdentityMismatch = errors.New("CPA credential identity readback disagrees")
)

// Config is the deployment-only CPA management attachment.
type Config struct {
	BaseURL string
	APIKey  string
	Timeout time.Duration
}

// File is one auth file as CPA's management API reports it.
type File struct {
	Name      string
	ID        string
	AuthIndex string
	Provider  string
	Email     string
	AccountID string
	Revision  string
	Status    string
	Disabled  bool
}

// Receipt is a durable, non-secret record of one accepted management write.
type Receipt struct {
	Operation  string
	Name       string
	Attempts   int
	StatusCode int
	VerifiedAt time.Time
}

// Client is a loopback-only CPA management client.
type Client struct {
	base  *url.URL
	key   string
	http  *http.Client
	clock func() time.Time
}

// New validates the configuration and builds a client. An empty BaseURL with an
// empty key means the integration is not configured; callers decide whether that
// is fatal.
func New(config Config) (*Client, error) {
	base := strings.TrimSpace(config.BaseURL)
	key := strings.TrimSpace(config.APIKey)
	if base == "" && key == "" {
		return nil, ErrNotConfigured
	}
	if base == "" || key == "" || strings.ContainsAny(key, "\r\n\x00") {
		return nil, ErrNotConfigured
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, ErrNotConfigured
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, ErrNotConfigured
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrNotConfigured
	}
	host := parsed.Hostname()
	if !loopbackHost(host) {
		return nil, fmt.Errorf("%w: management host must be loopback", ErrNotConfigured)
	}
	if parsed.Port() == "" {
		return nil, fmt.Errorf("%w: management port is required", ErrNotConfigured)
	}
	timeout := config.Timeout
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = defaultTimeout
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return &Client{
		base: parsed,
		key:  key,
		http: &http.Client{
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
				DisableKeepAlives:     true,
			},
		},
		clock: time.Now,
	}, nil
}

func loopbackHost(host string) bool {
	trimmed := strings.TrimSuffix(strings.ToLower(host), ".")
	if trimmed == "localhost" {
		return true
	}
	address := net.ParseIP(trimmed)
	return address != nil && address.IsLoopback()
}

// List returns every auth file CPA currently reports.
func (c *Client) List(ctx context.Context) ([]File, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/v0/management/auth-files", nil, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("CPA auth file listing returned %d", status)
	}
	var payload struct {
		Files []struct {
			ID                 string `json:"id"`
			AuthIndex          string `json:"auth_index"`
			Name               string `json:"name"`
			Type               string `json:"type"`
			Provider           string `json:"provider"`
			Email              string `json:"email"`
			AccountID          string `json:"account_id"`
			Account            string `json:"account"`
			CredentialRevision string `json:"credential_revision"`
			Status             string `json:"status"`
			Disabled           bool   `json:"disabled"`
		} `json:"files"`
	}
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, errors.New("CPA auth file listing could not be decoded")
	}
	files := make([]File, 0, len(payload.Files))
	for _, item := range payload.Files {
		provider := strings.TrimSpace(item.Provider)
		if provider == "" {
			provider = strings.TrimSpace(item.Type)
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = strings.TrimSpace(item.ID)
		}
		if name == "" {
			continue
		}
		files = append(files, File{
			Name:      name,
			ID:        strings.TrimSpace(item.ID),
			AuthIndex: strings.TrimSpace(item.AuthIndex),
			Provider:  provider,
			Email:     strings.ToLower(strings.TrimSpace(item.Email)),
			AccountID: firstNonEmpty(item.AccountID, item.Account),
			Revision:  strings.TrimSpace(item.CredentialRevision),
			Status:    strings.TrimSpace(item.Status),
			Disabled:  item.Disabled,
		})
	}
	return files, nil
}

// Lookup resolves one credential selector (file name or auth index) to a file.
func (c *Client) Lookup(ctx context.Context, selector string) (File, error) {
	needle := strings.TrimSpace(selector)
	if needle == "" {
		return File{}, ErrCredentialNotFound
	}
	files, err := c.List(ctx)
	if err != nil {
		return File{}, err
	}
	for _, file := range files {
		inventoryID := "name:" + file.Name
		if file.AuthIndex != "" {
			inventoryID += "#index:" + file.AuthIndex
		}
		if inventoryID == needle || file.Name == needle || (file.AuthIndex != "" && file.AuthIndex == needle) || (file.ID != "" && file.ID == needle) {
			return file, nil
		}
	}
	return File{}, ErrCredentialNotFound
}

// SetDisabled applies and reads back a quarantine state for one credential.
func (c *Client) SetDisabled(ctx context.Context, name string, disabled bool) (Receipt, error) {
	if !validName(name) {
		return Receipt{}, ErrInvalidCredentialName
	}
	body, err := json.Marshal(map[string]any{"name": name, "disabled": disabled})
	if err != nil {
		return Receipt{}, err
	}
	response, status, err := c.do(ctx, http.MethodPatch, "/v0/management/auth-files/status", body, "application/json")
	if err != nil {
		return Receipt{}, err
	}
	if status != http.StatusOK {
		return Receipt{}, fmt.Errorf("CPA status update returned %d", status)
	}
	var result struct {
		Status   string `json:"status"`
		Disabled *bool  `json:"disabled"`
	}
	if err = json.Unmarshal(response, &result); err != nil {
		return Receipt{}, errors.New("CPA status update could not be decoded")
	}
	if result.Status != "ok" || result.Disabled == nil || *result.Disabled != disabled {
		return Receipt{}, errors.New("CPA status update was not confirmed")
	}
	// Read back the listing so the receipt reflects the observed remote state.
	file, err := c.Lookup(ctx, name)
	if err != nil {
		return Receipt{}, err
	}
	if file.Disabled != disabled {
		return Receipt{}, errors.New("CPA status readback disagrees with the applied value")
	}
	return Receipt{Operation: "status", Name: name, StatusCode: status, VerifiedAt: c.clock().UTC()}, nil
}

// Upload writes one auth file and reads it back so a receipt always cites an
// observed remote identity rather than the request.
func (c *Client) Upload(ctx context.Context, name string, authFile []byte) (Receipt, error) {
	if !validName(name) {
		return Receipt{}, ErrInvalidCredentialName
	}
	if !validAuthFile(authFile) {
		return Receipt{}, errors.New("CPA auth file payload is invalid")
	}
	expected, err := authFileIdentity(authFile)
	if err != nil {
		return Receipt{}, err
	}
	path := "/v0/management/auth-files?name=" + url.QueryEscape(name)
	response, status, err := c.do(ctx, http.MethodPost, path, authFile, "application/json")
	if err != nil {
		return Receipt{}, err
	}
	if status != http.StatusOK {
		return Receipt{}, fmt.Errorf("CPA auth upload returned %d", status)
	}
	var result struct {
		Status string `json:"status"`
	}
	if err = json.Unmarshal(response, &result); err != nil || result.Status != "ok" {
		return Receipt{}, errors.New("CPA auth upload was not confirmed")
	}
	file, err := c.Lookup(ctx, name)
	if err != nil {
		return Receipt{}, err
	}
	if file.Disabled {
		return Receipt{}, errors.New("CPA registered the replacement credential as disabled")
	}
	// A same-name listing is insufficient: CPA may have retained an older
	// credential or accepted a file for a different account. Download the
	// authoritative material and compare its stable identity and token digest.
	if file.Provider != "codex" {
		return Receipt{}, ErrCredentialIdentityMismatch
	}
	verified, err := c.download(ctx, name)
	if err != nil {
		return Receipt{}, err
	}
	actual, err := authFileIdentity(verified)
	if err != nil || actual.accountID != expected.accountID ||
		(expected.email != "" && actual.email != expected.email) || actual.revision != expected.revision {
		return Receipt{}, ErrCredentialIdentityMismatch
	}
	return Receipt{Operation: "upload", Name: name, StatusCode: status, VerifiedAt: c.clock().UTC()}, nil
}

// download reads CPA's authoritative auth-file representation after upload.
func (c *Client) download(ctx context.Context, name string) ([]byte, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/v0/management/auth-files/download?name="+url.QueryEscape(name), nil, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("CPA auth download returned %d", status)
	}
	if !validAuthFile(body) {
		return nil, errors.New("CPA auth download was not a valid credential")
	}
	return body, nil
}

type authIdentity struct {
	accountID string
	email     string
	revision  string
}

func authFileIdentity(raw []byte) (authIdentity, error) {
	var payload struct {
		AccountID    string `json:"account_id"`
		Email        string `json:"email"`
		Revision     string `json:"credential_revision"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return authIdentity{}, errors.New("CPA auth file payload is invalid")
	}
	accountID := strings.TrimSpace(payload.AccountID)
	if accountID == "" {
		return authIdentity{}, ErrCredentialIdentityMismatch
	}
	material := credentialMaterialDigest(strings.TrimSpace(payload.AccessToken), strings.TrimSpace(payload.RefreshToken), strings.TrimSpace(payload.IDToken), accountID)
	revision := hex.EncodeToString(material[:])
	if payload.Revision != "" && payload.Revision != revision {
		return authIdentity{}, ErrCredentialIdentityMismatch
	}
	return authIdentity{accountID: accountID, email: strings.ToLower(strings.TrimSpace(payload.Email)), revision: revision}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, int, error) {
	if c == nil || c.base == nil {
		return nil, 0, ErrNotConfigured
	}
	target := *c.base
	target.Path = c.base.Path + strings.SplitN(path, "?", 2)[0]
	if query := strings.SplitN(path, "?", 2); len(query) == 2 {
		target.RawQuery = query[1]
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, 0, errors.New("CPA management request could not be built")
	}
	request.Header.Set("Authorization", "Bearer "+c.key)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, 0, errors.New("CPA management request failed")
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || len(payload) > maxResponseBytes {
		return nil, response.StatusCode, errors.New("CPA management response could not be read")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, response.StatusCode, errors.New("CPA management redirect was refused")
	}
	return payload, response.StatusCode, nil
}

// validAuthFile requires the structural fields CPA needs to load a Codex
// credential, so a malformed upload fails here instead of inside CPA.
func validAuthFile(authFile []byte) bool {
	if len(authFile) == 0 || len(authFile) > maxUploadBytes || !json.Valid(authFile) {
		return false
	}
	var decoded struct {
		Type         string `json:"type"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if json.Unmarshal(authFile, &decoded) != nil {
		return false
	}
	return decoded.Type == "codex" &&
		strings.TrimSpace(decoded.AccessToken) != "" &&
		strings.TrimSpace(decoded.RefreshToken) != "" &&
		strings.TrimSpace(decoded.IDToken) != ""
}

func validName(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed != name || trimmed == "" || len(trimmed) > 200 {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(trimmed), ".json") {
		return false
	}
	return !strings.ContainsAny(trimmed, "/\\\x00")
}
