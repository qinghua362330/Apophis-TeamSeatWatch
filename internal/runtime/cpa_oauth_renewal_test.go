package runtime

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
)

func TestAcquireCPAOAuthRequiresConfiguredDependencies(t *testing.T) {
	h := &OwnerAuthHandler{}
	_, err := h.acquireCPAOAuth(context.Background(), uuid.New(), "workspace", "user@example.com", "account.json")
	if err != cpacred.ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}
