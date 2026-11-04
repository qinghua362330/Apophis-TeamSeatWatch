package platform

import (
	"context"
	"time"
)

// SelectedWorkspaceReader uses only the explicitly exchanged Workspace bearer.
// It must not log in, mutate membership, or infer write permission from visibility.
type SelectedWorkspaceReader interface {
	Source() string
	VerifySelectedWorkspace(context.Context, WorkspaceAccess, string, string) (SelectedWorkspaceFacts, error)
}

// WorkspaceAccess is sealed at rest and never exposed by an Owner API.
type WorkspaceAccess struct {
	AccessToken string          `json:"accessToken"`
	WorkspaceID string          `json:"workspaceId"`
	Cookies     []SessionCookie `json:"cookies"`
	DeviceID    string          `json:"deviceId"`
	SessionID   string          `json:"sessionId"`
	ExpiresAt   time.Time       `json:"expiresAt"`
}

// WorkspaceAccessIdentity returns the workspace and user identities asserted by
// the exchanged bearer. The token has already been obtained through the
// authenticated workspace exchange; callers use this only to bind the bearer
// subject to a freshly read member role, never as a standalone authorization.
func WorkspaceAccessIdentity(access WorkspaceAccess) (workspaceID, subjectID string) {
	return tokenIdentity(access.AccessToken)
}

type WorkspaceTokenExchanger interface {
	ExchangeWorkspace(context.Context, PersonalSession, string) (WorkspaceAccess, error)
}

// ReadEvidence describes one independently attempted capability. Partial reads
// retain the successful and failed endpoint evidence but never imply a complete roster.
type ReadEvidence struct {
	Source       string       `json:"source"`
	ObservedAt   time.Time    `json:"observedAt"`
	Completeness Completeness `json:"completeness"`
	Permission   string       `json:"permission"`
	Outcome      Outcome      `json:"outcome"`
}

type SelectedWorkspaceFacts struct {
	Permission string // read, denied, unknown
	Result     Result // composite becomes verified only when every source is complete
	Sources    []ReadEvidence
}
