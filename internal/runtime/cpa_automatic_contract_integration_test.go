//go:build integration

package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
)

func TestCPAApprovalRouteRemoved(t *testing.T) {
	response := httptest.NewRecorder()
	ownerapi.Handler(&OwnerAuthHandler{}).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/owner/v1/cpa/rotation-cases/"+uuid.NewString()+"/approve", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("removed approval route returned %d", response.Code)
	}
}

func TestCPALegacyApprovalAutomaticallyResumes(t *testing.T) {
	pool, handler, _, ctx := newAutomaticRotationFixture(t)
	port := newFakeCPAPort("legacy-credential", "legacy.json")
	handler.cpaCredentials = port
	eventID := uuid.New()
	assertCPAResponse(t, receiveCPAEvent(t, handler, cpaPayload(eventID, "degraded@example.com", "legacy-credential")), http.StatusAccepted, "pending_rotation")
	if _, err := pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET status='awaiting_approval',last_error_code='owner_approval_required' WHERE event_id=(SELECT id FROM tsw_cpa_degradation_events WHERE event_id=$1)`, eventID); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"quarantining", "removal_queued"} {
		processed, err := handler.reconcileCPAAutomationOnce(ctx)
		if err != nil || !processed {
			t.Fatalf("automatic resume processed=%v err=%v", processed, err)
		}
		if got := rotationCaseStatus(t, ctx, pool, eventID); got != want {
			t.Fatalf("status=%s want=%s", got, want)
		}
	}
}
