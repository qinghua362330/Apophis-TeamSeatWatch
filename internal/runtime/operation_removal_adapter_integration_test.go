//go:build integration

package runtime

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/task"
)

type removalAdapterRoundTrip struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (r *removalAdapterRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req.Clone(req.Context()))
	r.mu.Unlock()
	if req.Method == http.MethodGet {
		body := `{"items":[{"id":"member-` + req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:] + `","email":"target@example.com","role":"member","seat_type":"prolite"}],"total":1,"limit":100,"offset":0}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	}
	if req.Method == http.MethodDelete {
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
	}
	return &http.Response{StatusCode: http.StatusMethodNotAllowed, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
}

func (r *removalAdapterRoundTrip) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func TestOperationRemovalAdapterOfficialBearerIntegration(t *testing.T) {
	p, h, _, ctx := newAutomaticRotationFixture(t)
	var membership, workspace, operation uuid.UUID
	var mother, run, generation, exchange uuid.UUID
	var platformWorkspace, memberID string
	if err := p.QueryRow(ctx, `SELECT membership.id,binding.workspace_id,binding.mother_account_id,
		workspace.platform_workspace_id,membership.platform_member_id
		FROM tsw_batch_memberships membership JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		WHERE membership.platform_member_id IS NOT NULL LIMIT 1`).Scan(&membership, &workspace, &mother, &platformWorkspace, &memberID); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT operation_id FROM tsw_operation_targets WHERE membership_id=$1 LIMIT 1`, membership).Scan(&operation); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `SELECT discovery_run_id,session_generation,token_exchange_id FROM tsw_workspace_verifications WHERE mother_account_id=$1 ORDER BY id DESC LIMIT 1`, mother).Scan(&run, &generation, &exchange); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO tsw_mother_account_credentials(mother_account_id,login_identifier,identifier_hmac,identifier_key_version,password_secret,secret_revision) VALUES($1,'owner@example.com',$2,1,$3,1)`, mother, bytes.Repeat([]byte{0x41}, 32), []byte("sealed-password")); err != nil {
		t.Fatal(err)
	}
	personal := platform.PersonalSession{AccessToken: "fixture-personal-token", DeviceID: "fixture-device", Cookies: []platform.SessionCookie{{Name: "__Secure-next-auth.session-token", Value: "fixture-cookie"}}, ExpiresAt: time.Now().Add(time.Hour)}
	personalKey, personalNonce, personalSealed, err := sealPersonalSession(h.keyRing, mother, 1, personal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO tsw_mother_personal_sessions(mother_account_id,secret_revision,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,1,$2,$3,$4,$5,$6)`, mother, generation, personalKey, personalNonce, personalSealed, personal.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO tsw_mother_discoveries(mother_account_id,run_id,secret_revision,session_generation,status) VALUES($1,$2,1,$3,'discovered')`, mother, run, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO tsw_mother_workspace_visibility(mother_account_id,workspace_id,run_id,access_status) VALUES($1,$2,$3,'readable')`, mother, workspace, run); err != nil {
		t.Fatal(err)
	}
	access := fixtureWorkspaceAccess(platformWorkspace)
	binding := workspaceAccessBinding{motherID: mother, workspaceID: workspace, run: run, generation: generation, revision: 1, attempt: 1, exchangeID: exchange}
	key, nonce, sealed, err := sealWorkspaceAccess(h.keyRing, binding, access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `INSERT INTO tsw_selected_workspace_tokens(mother_account_id,workspace_id,discovery_run_id,session_generation,secret_revision,attempt,exchange_id,status,key_version,nonce,sealed_access,expires_at) VALUES($1,$2,$3,$4,1,1,$5,'ready',$6,$7,$8,$9)`, mother, workspace, run, generation, exchange, key, nonce, sealed, access.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	// The fixture's durable verification is intentionally sourced from this reader.
	h.selectedWorkspaceReader = &selectedFixture{}
	transport := &removalAdapterRoundTrip{}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	target := taskRemovalTarget(operation, membership, workspace, platformWorkspace)
	remover, err := h.operationRemover(ctx, client, target)
	if err != nil {
		t.Fatalf("construct adapter: %v", err)
	}
	snapshot, err := remover.SnapshotMembers(ctx, platformWorkspace)
	if err != nil || snapshot.DeclaredMemberCount != 1 || len(snapshot.Fact.Members) != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("GET count=%d, want 1", got)
	}
	transport.mu.Lock()
	readReq := transport.requests[0]
	transport.mu.Unlock()
	if readReq.Header.Get("Authorization") != "Bearer "+access.AccessToken || readReq.Header.Get("Oai-Device-Id") != access.DeviceID {
		t.Fatalf("missing official read headers: authorization=%q device=%q", readReq.Header.Get("Authorization"), readReq.Header.Get("Oai-Device-Id"))
	}
	result, err := remover.RemoveMember(ctx, platformWorkspace, memberID)
	if err != nil || !result.Accepted || result.HTTPStatus != http.StatusNoContent {
		t.Fatalf("remove=%+v err=%v", result, err)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("DELETE count=%d, want 2 total requests", got)
	}
	transport.mu.Lock()
	deleteReq := transport.requests[1]
	transport.mu.Unlock()
	if got := deleteReq.Header.Get("Authorization"); got != "Bearer "+access.AccessToken {
		t.Fatalf("authorization=%q", got)
	}
	if deleteReq.Header.Get("Chatgpt-Account-Id") != platformWorkspace || deleteReq.Header.Get("Oai-Device-Id") != access.DeviceID {
		t.Fatalf("missing official bearer headers: account=%q device=%q", deleteReq.Header.Get("Chatgpt-Account-Id"), deleteReq.Header.Get("Oai-Device-Id"))
	}
	if _, err = remover.RemoveMember(ctx, platformWorkspace, "wrong-member"); err == nil || transport.count() != 2 {
		t.Fatalf("wrong member was not rejected without HTTP: err=%v requests=%d", err, transport.count())
	}
	if _, err = remover.SnapshotMembers(ctx, "wrong-workspace"); err == nil || transport.count() != 2 {
		t.Fatalf("wrong workspace was not rejected without HTTP: err=%v requests=%d", err, transport.count())
	}
	newExchange := uuid.New()
	newBinding := binding
	newBinding.exchangeID = newExchange
	newKey, newNonce, newSealed, err := sealWorkspaceAccess(h.keyRing, newBinding, access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE tsw_selected_workspace_tokens SET exchange_id=$3,key_version=$4,nonce=$5,sealed_access=$6 WHERE mother_account_id=$1 AND workspace_id=$2`, mother, workspace, newExchange, newKey, newNonce, newSealed); err != nil {
		t.Fatal(err)
	}
	if _, err = remover.SnapshotMembers(ctx, platformWorkspace); err == nil || transport.count() != 2 {
		t.Fatalf("changed token exchange was not rejected without HTTP: err=%v requests=%d", err, transport.count())
	}
}

// Kept local so this test documents the exact operation identity used by the
// worker without depending on unrelated credential fields.
func taskRemovalTarget(operation, membership, workspace uuid.UUID, platformWorkspace string) task.RemovalTarget {
	return task.RemovalTarget{OperationID: operation.String(), MembershipID: membership.String(), WorkspaceID: workspace.String(), PlatformWorkspace: platformWorkspace}
}
