package cpacred

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// DeliveryPayload is the immutable credential version this service publishes for
// one membership. It mirrors the columns stored in tsw_delivery_versions.
type DeliveryPayload struct {
	RefreshToken      string `json:"refresh_token"`
	AccessToken       string `json:"access_token"`
	IDToken           string `json:"id_token"`
	ExpiresIn         int    `json:"expires_in"`
	Scope             string `json:"scope"`
	WorkspaceID       string `json:"workspace_id"`
	PlatformSubjectID string `json:"platform_subject_id"`
}

// Credential is one CPA auth file ready for upload.
type Credential struct {
	// Name is the CPA auth file name. It is derived from the file digest so a
	// repeated delivery of identical material is idempotent.
	Name     string
	AuthFile []byte
	// Revision identifies the delivered material, never the token itself.
	Revision string
	Email    string
}

// ParseDeliveryPayload decodes one stored credential version.
func ParseDeliveryPayload(raw []byte) (DeliveryPayload, error) {
	var payload DeliveryPayload
	if len(raw) == 0 {
		return payload, errors.New("credential payload is empty")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&payload); err != nil {
		return DeliveryPayload{}, errors.New("credential payload could not be decoded")
	}
	if strings.TrimSpace(payload.AccessToken) == "" || strings.TrimSpace(payload.RefreshToken) == "" || strings.TrimSpace(payload.IDToken) == "" {
		return DeliveryPayload{}, errors.New("credential payload is incomplete")
	}
	return payload, nil
}

// BuildCodexCredential renders the CPA auth file for one Codex delivery.
//
// CPA refreshes from refresh_token and needs account_id for workspace routing;
// both are required, so an unidentifiable payload fails closed instead of
// producing a file CPA would load but never authorize.
func BuildCodexCredential(payload DeliveryPayload, fallbackEmail string, now time.Time) (Credential, error) {
	access := strings.TrimSpace(payload.AccessToken)
	refresh := strings.TrimSpace(payload.RefreshToken)
	idToken := strings.TrimSpace(payload.IDToken)
	if access == "" || refresh == "" || idToken == "" {
		return Credential{}, errors.New("credential payload is incomplete")
	}
	claims := idTokenClaims(idToken)
	accountID := strings.TrimSpace(claims.accountID)
	if accountID == "" {
		accountID = strings.TrimSpace(payload.WorkspaceID)
	}
	if accountID == "" {
		return Credential{}, errors.New("credential payload carries no account identity")
	}
	email := strings.ToLower(strings.TrimSpace(claims.email))
	if email == "" {
		email = strings.ToLower(strings.TrimSpace(fallbackEmail))
	}
	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 || expiresIn > 24*3600 {
		expiresIn = 3600
	}
	stamp := now.UTC()
	// Only credential material participates in the revision, never retry timestamps.
	material := credentialMaterialDigest(access, refresh, idToken, accountID)
	revision := hex.EncodeToString(material[:])
	authFile, err := json.Marshal(map[string]any{
		"credential_revision": revision,
		"type":                "codex",
		"id_token":            idToken,
		"access_token":        access,
		"refresh_token":       refresh,
		"account_id":          accountID,
		"email":               email,
		"last_refresh":        stamp.Format(time.RFC3339),
		"expired":             stamp.Add(time.Duration(expiresIn) * time.Second).Format(time.RFC3339),
	})
	if err != nil {
		return Credential{}, err
	}
	// The name and revision commit to the delivered material only. Volatile
	// timestamps must not change either, or a retry would register a second file
	// for the same credential.
	return Credential{
		Name:     "codex-" + hex.EncodeToString(material[:8]) + ".json",
		AuthFile: authFile,
		Revision: revision,
		Email:    email,
	}, nil
}

func credentialMaterialDigest(access, refresh, idToken, accountID string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{access, refresh, idToken, accountID}, "\x00")))
}

type tokenClaims struct {
	email     string
	accountID string
}

// idTokenClaims reads the two identity claims this package needs. It performs no
// signature verification: the token was already validated when it was published.
func idTokenClaims(token string) tokenClaims {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return tokenClaims{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil || len(raw) == 0 {
		return tokenClaims{}
	}
	var decoded struct {
		Email      string `json:"email"`
		OpenAIAuth struct {
			ChatGPTAccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(raw, &decoded) != nil {
		return tokenClaims{}
	}
	return tokenClaims{email: decoded.Email, accountID: decoded.OpenAIAuth.ChatGPTAccountID}
}
