package cpacred

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// WithProxy returns the same CPA credential material with an explicit
// per-credential proxy. The original credential is returned unchanged when
// proxyURL is empty, preserving the legacy revision contract.
func WithProxy(credential Credential, proxyURL string) (Credential, error) {
	if strings.ContainsAny(proxyURL, "\r\n\t\x00") {
		return Credential{}, errors.New("invalid CPA proxy URL")
	}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return credential, nil
	}
	if err := validateProxyURL(proxyURL); err != nil {
		return Credential{}, err
	}
	var payload map[string]any
	if err := json.Unmarshal(credential.AuthFile, &payload); err != nil || payload == nil {
		return Credential{}, errors.New("CPA auth file payload is invalid")
	}
	payload["proxy_url"] = proxyURL

	access, _ := payload["access_token"].(string)
	accountID, _ := payload["account_id"].(string)
	access = strings.TrimSpace(access)
	accountID = strings.TrimSpace(accountID)
	if access == "" || accountID == "" {
		return Credential{}, errors.New("CPA auth file identity is incomplete")
	}
	authorization := ""
	if headers, ok := payload["headers"].(map[string]any); ok {
		authorization, _ = headers["authorization"].(string)
	}
	var digest [32]byte
	if strings.TrimSpace(authorization) != "" {
		digest = sha256.Sum256([]byte(strings.Join([]string{access, strings.TrimSpace(authorization), accountID, proxyURL}, "\x00")))
	} else {
		refresh, _ := payload["refresh_token"].(string)
		idToken, _ := payload["id_token"].(string)
		digest = sha256.Sum256([]byte(strings.Join([]string{access, strings.TrimSpace(refresh), strings.TrimSpace(idToken), accountID, proxyURL}, "\x00")))
	}
	revision := hex.EncodeToString(digest[:])
	payload["credential_revision"] = revision
	authFile, err := json.Marshal(payload)
	if err != nil {
		return Credential{}, err
	}
	credential.AuthFile = authFile
	credential.Revision = revision
	return credential, nil
}

func validateProxyURL(raw string) error {
	if len(raw) > 4096 || strings.ContainsAny(raw, "\r\n\t\x00") {
		return errors.New("invalid CPA proxy URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User == nil && u.Hostname() == "" {
		return errors.New("invalid CPA proxy URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return errors.New("unsupported CPA proxy URL scheme")
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("invalid CPA proxy URL")
	}
	if (strings.EqualFold(u.Scheme, "socks5") || strings.EqualFold(u.Scheme, "socks5h")) && u.Port() == "" {
		return errors.New("invalid CPA proxy URL")
	}
	return nil
}
