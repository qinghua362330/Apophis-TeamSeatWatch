package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/identity"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

type selectedAttempt struct {
	id, revision, tokenAttempt       int64
	run, generation, tokenExchangeID uuid.UUID
	platformID                       string
	access                           platform.WorkspaceAccess
}

// One current mother discovery plus its Personal generation authorizes this
// space. The joined scope is shared by reservation, completion and GET.
const selectedWorkspaceFromSQL = ` FROM tsw_mother_workspace_visibility visibility
	JOIN tsw_workspaces workspace ON workspace.id=visibility.workspace_id
	JOIN tsw_mother_accounts account ON account.id=visibility.mother_account_id AND account.status='active'
	JOIN tsw_mother_account_credentials credential ON credential.mother_account_id=account.id
	JOIN tsw_mother_discoveries discovery ON discovery.mother_account_id=account.id AND discovery.run_id=visibility.run_id AND discovery.secret_revision=credential.secret_revision AND discovery.status='discovered' AND discovery.observed_at>now()-interval '7 days'
	JOIN tsw_mother_personal_sessions session ON session.mother_account_id=account.id AND session.generation=discovery.session_generation AND session.secret_revision=credential.secret_revision AND session.expires_at>now()
	WHERE visibility.workspace_id=$1 AND visibility.mother_account_id=$2`

func (h *OwnerAuthHandler) GetSelectedWorkspaceVerification(w http.ResponseWriter, r *http.Request, workspaceID openapi_types.UUID, params ownerapi.GetSelectedWorkspaceVerificationParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, valid := pagination(params.Page, params.PageSize)
	if !valid {
		writeProblem(w, r, 422, "invalid_pagination", "Invalid Pagination", "Page and page size are invalid", 0)
		return
	}
	kind := "member"
	if params.EntryKind != nil {
		kind = string(*params.EntryKind)
	}
	if kind != "member" && kind != "pending_invite" {
		writeProblem(w, r, 422, "invalid_entry_kind", "Invalid Entry Kind", "Entry kind is invalid", 0)
		return
	}
	response, err := h.selectedWorkspacePage(r.Context(), workspaceID, params.MotherAccountId, page, size, kind)
	if !h.selectedWorkspaceError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *OwnerAuthHandler) VerifySelectedWorkspace(w http.ResponseWriter, r *http.Request, workspaceID openapi_types.UUID, _ ownerapi.VerifySelectedWorkspaceParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.VerifySelectedWorkspaceJSONRequestBody
	if !decodeJSON(w, r, &request) || !bool(request.Confirmed) {
		writeProblem(w, r, 422, "selection_required", "Selection Required", "Confirm the selected mother and canonical workspace", 0)
		return
	}
	if h.selectedWorkspaceReader == nil {
		writeProblem(w, r, 501, "management_protocol_unavailable", "Unavailable", "No verified Workspace read protocol is configured", 0)
		return
	}
	attempt, err := h.reserveSelectedWorkspace(r.Context(), workspaceID, request.MotherAccountId)
	if errors.Is(err, errWorkspaceTokenRequired) {
		writeProblem(w, r, 409, "workspace_token_required", "Workspace Token Required", "Explicitly exchange the selected Workspace token before verifying facts", 0)
		return
	}
	if !h.selectedWorkspaceError(w, r, err) {
		return
	}
	if attempt.id == 0 {
		writeProblem(w, r, 403, "workspace_permission_denied", "Forbidden", "Verify access through another mother", 0)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	reader := h.selectedWorkspaceReader
	if official, ok := reader.(platform.OfficialSelectedWorkspaceReader); ok {
		official.ResolveMemberIdentifiers = func(ctx context.Context, memberIDs []string) (map[string]string, error) {
			return h.confirmedWorkspaceMemberIdentifiers(ctx, workspaceID, memberIDs)
		}
		reader = official
	}
	facts, readErr := reader.VerifySelectedWorkspace(ctx, attempt.access, request.MotherAccountId.String(), attempt.platformID)
	cancel()
	status, observedAt := "failed", time.Now().UTC()
	var activeUntil *time.Time
	var seats, members, invites *int
	permission, completeness := facts.Permission, string(facts.Result.Completeness)
	if permission != "read" && permission != "manage" && permission != "denied" {
		permission = "unknown"
	}
	if completeness != "complete" && completeness != "partial" {
		completeness = "unknown"
	}
	if readErr == nil {
		observedAt = facts.Result.ObservedAt
		if observedAt.IsZero() || observedAt.After(time.Now()) || observedAt.Before(time.Now().Add(-7*24*time.Hour)) {
			status, observedAt, permission, completeness = "failed", time.Now().UTC(), "unknown", "unknown"
		} else if permission == "denied" || facts.Result.Outcome == platform.OutcomeForbidden || facts.Result.Outcome == platform.OutcomeUnauthorized {
			status, permission = "permission_denied", "denied"
		} else if (permission == "read" || permission == "manage") && facts.Result.Outcome == platform.OutcomeOperational && completeness == "complete" &&
			facts.Result.ActiveUntil != nil && facts.Result.SeatLimit != nil && facts.Result.MemberCount != nil && facts.Result.PendingInviteCount != nil &&
			*facts.Result.SeatLimit >= 0 && *facts.Result.MemberCount >= 0 && *facts.Result.PendingInviteCount >= 0 &&
			validSelectedEntries(facts.Result.Members, *facts.Result.MemberCount, *facts.Result.PendingInviteCount) {
			status = "verified"
			activeUntil, seats, members, invites = facts.Result.ActiveUntil, facts.Result.SeatLimit, facts.Result.MemberCount, facts.Result.PendingInviteCount
		} else if facts.Result.Outcome == platform.OutcomeOperational || facts.Result.Completeness == platform.Partial {
			status, completeness = "partial", "partial"
			if facts.Result.Outcome != platform.OutcomeOperational {
				permission = "unknown"
			}
		} else {
			permission = "unknown"
		}
	} else {
		permission, completeness = "unknown", "unknown"
	}
	if err := h.finishSelectedWorkspace(r.Context(), workspaceID, request.MotherAccountId, attempt, status, permission, completeness, observedAt, activeUntil, seats, members, invites, facts); err != nil {
		if errors.Is(err, errSelectedAttemptSuperseded) {
			writeProblem(w, r, 409, "workspace_read_superseded", "Conflict", "A newer verification or access generation superseded this read", 0)
		} else {
			h.workspaceFailure(w, r, err)
		}
		return
	}
	response, err := h.selectedWorkspace(r.Context(), workspaceID, request.MotherAccountId)
	if !h.selectedWorkspaceError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// refreshCPAEvidenceOnce claims one parked CPA case and runs the same selected
// workspace verification used by the Owner endpoint. It deliberately bypasses
// the generic workspace_read task: that task publishes ordinary read facts and
// cannot establish the owner/manage evidence required before member removal.
func (h *OwnerAuthHandler) refreshCPAEvidenceOnce(ctx context.Context) (bool, error) {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var caseID, workspaceID, motherID string
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('tsw:cpa-evidence-refresh'))`).Scan(&locked); err != nil || !locked {
		return false, errOrCommit(ctx, tx, err)
	}
	err = tx.QueryRow(ctx, `WITH candidates AS (
		SELECT rotation.id::text AS case_id,rotation.workspace_id::text,binding.mother_account_id::text,
			rotation.next_attempt_at AS priority
		FROM tsw_cpa_rotation_cases rotation
		JOIN tsw_batches batch ON batch.id=rotation.source_batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.ended_at IS NULL
		WHERE rotation.status='waiting_evidence' AND rotation.next_attempt_at<=now()
		UNION ALL
		SELECT NULL::text AS case_id,token.workspace_id::text,token.mother_account_id::text,
			event.received_at AS priority
		FROM tsw_cpa_degradation_events event
		JOIN tsw_selected_workspace_tokens token ON true
		JOIN tsw_mother_accounts account ON account.id=token.mother_account_id AND account.status='active'
		JOIN tsw_mother_workspace_visibility visibility ON visibility.workspace_id=token.workspace_id
			AND visibility.mother_account_id=token.mother_account_id
			AND visibility.run_id=token.discovery_run_id AND visibility.access_status='readable'
		WHERE token.status IN ('ready','failed','permission_denied','exchanging')
			AND event.mapping_status IN ('not_found','received') AND event.received_at>now()-interval '30 minutes'
	), ranked AS (
		SELECT DISTINCT ON (workspace_id,mother_account_id) case_id,workspace_id,mother_account_id,priority
		FROM candidates
		WHERE NOT EXISTS (
			SELECT 1 FROM tsw_workspace_verifications verification
			WHERE verification.workspace_id=candidates.workspace_id::uuid
			  AND verification.mother_account_id=candidates.mother_account_id::uuid
			  AND verification.observed_at>now()-interval '2 minutes'
		)
		ORDER BY workspace_id,mother_account_id,priority
	)
	SELECT COALESCE(case_id,''),workspace_id,mother_account_id FROM ranked ORDER BY priority LIMIT 1`).Scan(&caseID, &workspaceID, &motherID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, tx.Commit(ctx)
	}
	if err != nil {
		return false, err
	}
	if caseID != "" {
		if _, err = tx.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now()+interval '2 minutes',last_error_code='evidence_refresh_running',updated_at=now(),version=version+1 WHERE id=$1`, caseID); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	refreshErr := h.verifySelectedWorkspaceForCPA(ctx, uuid.MustParse(workspaceID), uuid.MustParse(motherID))
	if refreshErr != nil && caseID != "" {
		_, updateErr := h.pool.Exec(ctx, `UPDATE tsw_cpa_rotation_cases SET next_attempt_at=now()+interval '2 minutes',last_error_code='evidence_refresh_failed',updated_at=now(),version=version+1 WHERE id=$1 AND status='waiting_evidence'`, caseID)
		if updateErr != nil {
			return true, errors.Join(refreshErr, updateErr)
		}
	}
	return true, refreshErr
}

func (h *OwnerAuthHandler) verifySelectedWorkspaceForCPA(ctx context.Context, workspaceID, motherID uuid.UUID) error {
	attempt, err := h.reserveSelectedWorkspace(ctx, workspaceID, motherID)
	if errors.Is(err, errWorkspaceTokenRequired) {
		if refreshErr := h.exchangeWorkspaceTokenForCPA(ctx, workspaceID, motherID); refreshErr != nil {
			return refreshErr
		}
		attempt, err = h.reserveSelectedWorkspace(ctx, workspaceID, motherID)
	}
	if err != nil {
		return err
	}
	if attempt.id == 0 || h.selectedWorkspaceReader == nil {
		return errors.New("selected workspace access is unavailable")
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	reader := h.selectedWorkspaceReader
	if official, ok := reader.(platform.OfficialSelectedWorkspaceReader); ok {
		official.ResolveMemberIdentifiers = func(ctx context.Context, memberIDs []string) (map[string]string, error) {
			return h.confirmedWorkspaceMemberIdentifiers(ctx, workspaceID, memberIDs)
		}
		reader = official
	}
	facts, readErr := reader.VerifySelectedWorkspace(verifyCtx, attempt.access, motherID.String(), attempt.platformID)
	status, permission, completeness := "failed", "unknown", string(facts.Result.Completeness)
	if permission = facts.Permission; permission != "read" && permission != "manage" && permission != "denied" {
		permission = "unknown"
	}
	observedAt := facts.Result.ObservedAt
	if readErr != nil {
		status, permission, completeness, observedAt = "failed", "unknown", "unknown", time.Now().UTC()
	} else if observedAt.IsZero() || observedAt.After(time.Now()) || observedAt.Before(time.Now().Add(-7*24*time.Hour)) {
		observedAt, permission, completeness = time.Now().UTC(), "unknown", "unknown"
	} else if permission == "denied" || facts.Result.Outcome == platform.OutcomeForbidden || facts.Result.Outcome == platform.OutcomeUnauthorized {
		status, permission = "permission_denied", "denied"
	} else if facts.Result.Outcome == platform.OutcomeOperational && facts.Result.Completeness == platform.Complete &&
		completeness == string(platform.Complete) && facts.Result.ActiveUntil != nil && facts.Result.SeatLimit != nil && facts.Result.MemberCount != nil && facts.Result.PendingInviteCount != nil &&
		validSelectedEntries(facts.Result.Members, *facts.Result.MemberCount, *facts.Result.PendingInviteCount) {
		status = "verified"
	} else if facts.Result.Outcome == platform.OutcomeOperational || facts.Result.Completeness == platform.Partial {
		status, completeness = "partial", "partial"
	} else {
		permission, completeness = "unknown", "unknown"
	}
	return h.finishSelectedWorkspace(ctx, workspaceID, motherID, attempt, status, permission, completeness, observedAt, facts.Result.ActiveUntil, facts.Result.SeatLimit, facts.Result.MemberCount, facts.Result.PendingInviteCount, facts)
}

func (h *OwnerAuthHandler) exchangeWorkspaceTokenForCPA(ctx context.Context, workspaceID, motherID uuid.UUID) error {
	if h.workspaceTokenExchanger == nil {
		return errWorkspaceTokenRequired
	}
	attempt, err := h.reserveWorkspaceTokenExchange(ctx, workspaceID, motherID)
	if err != nil {
		return err
	}
	if attempt.binding.attempt == 0 || attempt.personal.AccessToken == "" {
		return errWorkspaceTokenRequired
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	access, exchangeErr := h.workspaceTokenExchanger.ExchangeWorkspace(exchangeCtx, attempt.personal, attempt.platformID)
	cancel()
	if exchangeErr == nil && !platform.ValidateWorkspaceAccess(access, attempt.platformID, time.Now()) {
		exchangeErr = platform.ErrWorkspaceExchangeUnavailable
	}
	return h.finishWorkspaceTokenExchange(ctx, attempt, access, exchangeErr)
}

var errSelectedAttemptSuperseded = errors.New("selected workspace attempt superseded")

// A current platform member ID can identify a locally confirmed recipient even
// when the platform withholds email. Cross-workspace and ambiguous links cannot.
func (h *OwnerAuthHandler) confirmedWorkspaceMemberIdentifiers(ctx context.Context, workspaceID uuid.UUID, memberIDs []string) (map[string]string, error) {
	rows, err := h.pool.Query(ctx, `SELECT DISTINCT membership.platform_member_id,account.identifier
		FROM tsw_batch_memberships membership
		JOIN tsw_target_accounts account ON account.id=membership.target_account_id
		JOIN tsw_operation_targets target ON target.id=membership.join_operation_target_id AND target.membership_id=membership.id AND target.status='succeeded' AND target.outcome_code='member_confirmed'
		JOIN tsw_operations operation ON operation.id=target.operation_id AND operation.workspace_id=$1 AND operation.operation_type='join'
		WHERE membership.seat_type='prolite' AND membership.platform_member_id=ANY($2)`, workspaceID, memberIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	identifiers := map[string]string{}
	ambiguous := map[string]bool{}
	for rows.Next() {
		var memberID, identifier string
		if err := rows.Scan(&memberID, &identifier); err != nil {
			return nil, err
		}
		if prior, exists := identifiers[memberID]; exists && prior != identifier {
			ambiguous[memberID] = true
		}
		identifiers[memberID] = identifier
	}
	for memberID := range ambiguous {
		delete(identifiers, memberID)
	}
	return identifiers, rows.Err()
}

// Reserve an ordered attempt before I/O, then release all row locks. A newer
// request becomes the only publishable attempt for this mother and space.
func (h *OwnerAuthHandler) reserveSelectedWorkspace(ctx context.Context, workspaceID, motherID uuid.UUID) (selectedAttempt, error) {
	var attempt selectedAttempt
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return attempt, err
	}
	defer tx.Rollback(ctx)
	var access string
	err = tx.QueryRow(ctx, `SELECT visibility.access_status,workspace.platform_workspace_id,discovery.run_id,session.generation,credential.secret_revision`+selectedWorkspaceFromSQL+` FOR SHARE OF account,credential,discovery,session,visibility`, workspaceID, motherID).Scan(&access, &attempt.platformID, &attempt.run, &attempt.generation, &attempt.revision)
	if err != nil {
		return attempt, err
	}
	if access != "readable" {
		return attempt, nil
	}
	binding := workspaceAccessBinding{motherID: motherID, workspaceID: workspaceID, run: attempt.run, generation: attempt.generation, revision: attempt.revision}
	attempt.access, binding, err = h.currentWorkspaceAccessTx(ctx, tx, binding, attempt.platformID, true)
	if err != nil {
		return attempt, err
	}
	attempt.tokenAttempt, attempt.tokenExchangeID = binding.attempt, binding.exchangeID
	source := h.selectedWorkspaceReader.Source()
	if source != "injected_platform_reader" && source != "official_readonly" {
		return attempt, errors.New("workspace reader source invalid")
	}
	err = tx.QueryRow(ctx, `INSERT INTO tsw_workspace_verifications(workspace_id,mother_account_id,discovery_run_id,session_generation,secret_revision,token_attempt,token_exchange_id,source,outcome,permission,completeness,observed_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'verifying','unknown','unknown',now(),now()+interval '7 days') RETURNING id`, workspaceID, motherID, attempt.run, attempt.generation, attempt.revision, attempt.tokenAttempt, attempt.tokenExchangeID, source).Scan(&attempt.id)
	if err != nil {
		return attempt, err
	}
	if err = tx.Commit(ctx); err != nil {
		return attempt, err
	}
	return attempt, nil
}

func (h *OwnerAuthHandler) finishSelectedWorkspace(ctx context.Context, workspaceID, motherID uuid.UUID, attempt selectedAttempt, status, permission, completeness string, observedAt time.Time, until *time.Time, seats, members, invites *int, facts platform.SelectedWorkspaceFacts) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var access string
	var run, generation uuid.UUID
	var revision int64
	err = tx.QueryRow(ctx, `SELECT visibility.access_status,discovery.run_id,session.generation,credential.secret_revision`+selectedWorkspaceFromSQL+` FOR SHARE OF account,credential,discovery,session,visibility`, workspaceID, motherID).Scan(&access, &run, &generation, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return errSelectedAttemptSuperseded
	}
	if err != nil {
		return err
	}
	if access != "readable" || run != attempt.run || generation != attempt.generation || revision != attempt.revision {
		return errSelectedAttemptSuperseded
	}
	binding := workspaceAccessBinding{motherID: motherID, workspaceID: workspaceID, run: run, generation: generation, revision: revision}
	_, binding, err = h.currentWorkspaceAccessTx(ctx, tx, binding, attempt.platformID, true)
	if errors.Is(err, errWorkspaceTokenRequired) {
		return errSelectedAttemptSuperseded
	}
	if err != nil {
		return err
	}
	if binding.attempt != attempt.tokenAttempt || binding.exchangeID != attempt.tokenExchangeID {
		return errSelectedAttemptSuperseded
	}
	if len(facts.Sources) > 8 {
		return errors.New("workspace sources too large")
	}
	if facts.Sources == nil {
		facts.Sources = []platform.ReadEvidence{}
	}
	encoded, err := json.Marshal(facts.Sources)
	if err != nil {
		return err
	}
	seatTypes := facts.Result.SeatTypeCounts
	if seatTypes == nil {
		seatTypes = map[string]int{}
	}
	if !validSelectedSeatTypeCounts(seatTypes) {
		return errors.New("workspace seat type counts invalid")
	}
	encodedSeatTypes, err := json.Marshal(seatTypes)
	if err != nil {
		return err
	}
	entitlements := facts.Result.SeatEntitlements
	if entitlements == nil || status != "verified" && (status != "partial" || !completeSelectedReadSource(facts.Sources, "subscriptions")) {
		entitlements = map[string]int{}
	}
	if !validSelectedSeatTypeCounts(entitlements) {
		return errors.New("workspace seat entitlements invalid")
	}
	encodedEntitlements, err := json.Marshal(entitlements)
	if err != nil {
		return err
	}
	subscriptionStatus := "unknown"
	if (status == "verified" || status == "partial") && completeSelectedReadSource(facts.Sources, "subscriptions") {
		switch facts.Result.SubscriptionStatus {
		case "active", "delinquent", "inactive", "expired":
			subscriptionStatus = facts.Result.SubscriptionStatus
		}
		until = facts.Result.ActiveUntil
	}
	updated, err := tx.Exec(ctx, `UPDATE tsw_workspace_verifications SET outcome=$2,permission=$3,completeness=$4,observed_at=$5,expires_at=$5::timestamptz+interval '7 days',active_until=$6,seat_limit=$7,member_count=$8,pending_invite_count=$9,sources=$10,seat_type_counts=$11,seat_entitlements=$12,subscription_status=$13
		WHERE id=$1 AND outcome='verifying' AND id=(SELECT max(id) FROM tsw_workspace_verifications WHERE workspace_id=$14 AND mother_account_id=$15 AND discovery_run_id=$16 AND session_generation=$17 AND secret_revision=$18 AND token_attempt=$19 AND token_exchange_id=$20)`, attempt.id, status, permission, completeness, observedAt, until, seats, members, invites, encoded, encodedSeatTypes, encodedEntitlements, subscriptionStatus, workspaceID, motherID, attempt.run, attempt.generation, attempt.revision, attempt.tokenAttempt, attempt.tokenExchangeID)
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return errSelectedAttemptSuperseded
	}
	if status == "verified" {
		for _, member := range facts.Result.Members {
			normalized, version, fingerprint, err := identity.Fingerprint(h.keyRing, identity.WorkspaceEntry, member.Identifier)
			if err != nil {
				return err
			}
			var platformMemberID, role *string
			if member.Kind == "member" {
				platformMemberID = &member.PlatformMemberID
			}
			if member.Role != "" {
				role = &member.Role
			}
			var seatType *string
			if member.SeatType != "" {
				seatType = &member.SeatType
			}
			_, err = tx.Exec(ctx, `INSERT INTO tsw_workspace_verification_entries(verification_id,kind,identifier,identifier_hmac,identifier_key_version,status,role,platform_member_id,seat_type) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, attempt.id, member.Kind, normalized, fingerprint[:], version, member.Status, role, platformMemberID, seatType)
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (h *OwnerAuthHandler) selectedWorkspace(ctx context.Context, workspaceID, motherID uuid.UUID) (ownerapi.SelectedWorkspaceVerification, error) {
	return h.selectedWorkspacePage(ctx, workspaceID, motherID, 1, 20, "member")
}

// selectedWorkspaceSnapshotTx is the single scoped fact source for space
// management, operation admission and worker mutation fences.
func (h *OwnerAuthHandler) selectedWorkspaceSnapshotTx(ctx context.Context, tx pgx.Tx, workspaceID, motherID uuid.UUID) (ownerapi.SelectedWorkspaceVerification, int64, platform.WorkspaceAccess, error) {
	response := ownerapi.SelectedWorkspaceVerification{WorkspaceId: workspaceID, MotherAccountId: motherID, Status: "pending", Permission: "unknown", Completeness: "unknown", Members: []ownerapi.SelectedWorkspaceMember{}}
	var id int64
	var access platform.WorkspaceAccess
	if err := tx.QueryRow(ctx, `SELECT display_name FROM tsw_workspaces WHERE id=$1`, workspaceID).Scan(&response.WorkspaceName); err != nil {
		return response, id, access, err
	}
	var platformID string
	var run, generation uuid.UUID
	var revision int64
	err := tx.QueryRow(ctx, `SELECT visibility.access_status,workspace.platform_workspace_id,discovery.run_id,session.generation,credential.secret_revision`+selectedWorkspaceFromSQL, workspaceID, motherID).Scan(&response.AccessStatus, &platformID, &run, &generation, &revision)
	if err != nil {
		return response, id, access, err
	}
	if response.AccessStatus != "readable" {
		response.Status = "permission_denied"
		return response, id, access, nil
	}
	if h.selectedWorkspaceReader == nil {
		return response, id, access, nil
	}
	binding := workspaceAccessBinding{motherID: motherID, workspaceID: workspaceID, run: run, generation: generation, revision: revision}
	access, binding, err = h.currentWorkspaceAccessTx(ctx, tx, binding, platformID, false)
	if errors.Is(err, errWorkspaceTokenRequired) {
		return response, id, access, nil
	}
	if err != nil {
		return response, id, access, err
	}
	response.ExchangeId = &binding.exchangeID
	var source, status, permission, completeness string
	var observed, expires time.Time
	var sources []byte
	err = tx.QueryRow(ctx, `SELECT id,source,outcome,permission,completeness,observed_at,expires_at,sources FROM tsw_workspace_verifications WHERE workspace_id=$1 AND mother_account_id=$2 AND discovery_run_id=$3 AND session_generation=$4 AND secret_revision=$5 AND token_attempt=$6 AND token_exchange_id=$7 ORDER BY id DESC LIMIT 1`, workspaceID, motherID, run, generation, revision, binding.attempt, binding.exchangeID).Scan(&id, &source, &status, &permission, &completeness, &observed, &expires, &sources)
	if errors.Is(err, pgx.ErrNoRows) {
		return response, id, access, nil
	}
	if err != nil {
		return response, id, access, err
	}
	if source != h.selectedWorkspaceReader.Source() {
		return response, id, access, nil
	}
	response.Source, response.ObservedAt, response.ExpiresAt = &source, &observed, &expires
	response.Permission, response.Completeness = ownerapi.SelectedWorkspaceVerificationPermission(permission), ownerapi.SelectedWorkspaceVerificationCompleteness(completeness)
	response.Status = ownerapi.SelectedWorkspaceVerificationStatus(status)
	if !expires.After(time.Now()) {
		response.Status = "stale"
		return response, id, access, nil
	}
	if status == "verifying" {
		if observed.Before(time.Now().Add(-time.Minute)) {
			response.Status = "failed"
		}
		return response, id, access, nil
	}
	var readSources []ownerapi.SelectedWorkspaceReadSource
	if err = json.Unmarshal(sources, &readSources); err != nil {
		return response, id, access, err
	}
	response.ReadSources = &readSources
	if status == "verified" || status == "partial" {
		err = tx.QueryRow(ctx, `SELECT seat_entitlements,seat_type_counts,subscription_status,active_until FROM tsw_workspace_verifications WHERE id=$1`, id).Scan(&response.SeatEntitlements, &response.SeatTypeCounts, &response.SubscriptionStatus, &response.ActiveUntil)
		if err != nil {
			return response, id, access, err
		}
	}
	if status != "verified" {
		return response, id, access, nil
	}
	err = tx.QueryRow(ctx, `SELECT active_until,seat_limit,member_count,pending_invite_count FROM tsw_workspace_verifications WHERE id=$1`, id).Scan(&response.ActiveUntil, &response.SeatLimit, &response.MemberCount, &response.PendingInviteCount)
	if err != nil {
		return response, id, access, err
	}
	role, canManage, err := selectedWorkspaceMotherAuthority(ctx, tx, id, motherID)
	if err != nil {
		return response, id, access, err
	}
	response.MotherRole, response.CanManage = &role, canManage
	members, invites := map[string]int{}, map[string]int{}
	rows, err := tx.Query(ctx, `SELECT kind,COALESCE(seat_type,'unknown'),count(*) FROM tsw_workspace_verification_entries WHERE verification_id=$1 GROUP BY kind,seat_type`, id)
	if err != nil {
		return response, id, access, err
	}
	for rows.Next() {
		var kind, seat string
		var count int
		if err := rows.Scan(&kind, &seat, &count); err != nil {
			rows.Close()
			return response, id, access, err
		}
		if kind == "member" {
			members[seat] = count
		} else {
			invites[seat] = count
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return response, id, access, err
	}
	response.MemberSeatTypeCounts, response.PendingInviteSeatTypeCounts = &members, &invites
	return response, id, access, nil
}

func (h *OwnerAuthHandler) selectedWorkspacePage(ctx context.Context, workspaceID, motherID uuid.UUID, page, size int, kind string) (ownerapi.SelectedWorkspaceVerification, error) {
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ownerapi.SelectedWorkspaceVerification{}, err
	}
	defer tx.Rollback(ctx)
	response, id, _, err := h.selectedWorkspaceSnapshotTx(ctx, tx, workspaceID, motherID)
	if err != nil {
		return response, err
	}
	total := 0
	response.Page, response.PageSize, response.Total = &page, &size, &total
	if response.Status != "verified" {
		return response, tx.Commit(ctx)
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM tsw_workspace_verification_entries WHERE verification_id=$1 AND kind=$2`, id, kind).Scan(&total); err != nil {
		return response, err
	}
	rows, err := tx.Query(ctx, `SELECT entry.kind,entry.identifier,entry.status,entry.role,entry.seat_type,
  (SELECT CASE WHEN count(*)=1 THEN (array_agg(target.id))[1] END FROM tsw_target_accounts target WHERE target.identifier=entry.identifier)
  FROM tsw_workspace_verification_entries entry WHERE entry.verification_id=$1 AND entry.kind=$2 ORDER BY entry.identifier LIMIT $3 OFFSET $4`, id, kind, size, (page-1)*size)
	if err != nil {
		return response, err
	}
	for rows.Next() {
		var member ownerapi.SelectedWorkspaceMember
		if err := rows.Scan(&member.Kind, &member.Identifier, &member.Status, &member.Role, &member.SeatType, &member.ChildAccountId); err != nil {
			rows.Close()
			return response, err
		}
		member.Source, member.ObservedAt = *response.Source, *response.ObservedAt
		member.Completeness, member.Permission, member.LatestVerification = "complete", ownerapi.SelectedWorkspaceMemberPermission(response.Permission), "verified"
		response.Members = append(response.Members, member)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return response, err
	}
	return response, tx.Commit(ctx)
}

// Management authority comes from the selected mother's own verified member
// identity. Read success, visibility, and another member's role cannot grant it.
func selectedWorkspaceMotherAuthority(ctx context.Context, tx pgx.Tx, verificationID int64, motherID uuid.UUID) (string, bool, error) {
	var raw string
	err := tx.QueryRow(ctx, `SELECT COALESCE(entry.role,'') FROM tsw_workspace_verifications facts
	 JOIN tsw_workspace_verification_entries entry ON entry.verification_id=facts.id AND entry.kind='member'
	 JOIN tsw_mother_account_credentials credential ON credential.mother_account_id=facts.mother_account_id AND credential.secret_revision=facts.secret_revision AND entry.identifier=lower(credential.login_identifier)
		WHERE facts.id=$1 AND facts.mother_account_id=$2 AND facts.outcome='verified' AND facts.completeness='complete' AND facts.permission IN ('read','manage') AND facts.expires_at>now()`, verificationID, motherID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return "unknown", false, nil
	}
	if err != nil {
		return "unknown", false, err
	}
	role := platform.NormalizeWorkspaceRole(raw)
	return role, role == "owner" || role == "admin", nil
}

func (h *OwnerAuthHandler) selectedWorkspaceError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 409, "workspace_selection_expired", "Selection Expired", "Discover and select the workspace again", 0)
	} else {
		h.workspaceFailure(w, r, err)
	}
	return false
}

func completeSelectedReadSource(sources []platform.ReadEvidence, name string) bool {
	for _, source := range sources {
		if source.Source == name && source.Completeness == platform.Complete && source.Permission == "read" && source.Outcome == platform.OutcomeOperational {
			return true
		}
	}
	return false
}

func validSelectedSeatTypeCounts(counts map[string]int) bool {
	if len(counts) > 4 {
		return false
	}
	for seatType, count := range counts {
		if count < 0 || (seatType != "default" && seatType != "usage_based" && seatType != "automation" && seatType != "prolite") {
			return false
		}
	}
	return true
}

func validSelectedEntries(members []platform.Member, memberCount, invitationCount int) bool {
	seen := make(map[string]bool, len(members))
	foundMembers, foundInvitations := 0, 0
	for _, member := range members {
		identifier := strings.ToLower(strings.TrimSpace(member.Identifier))
		key := member.Kind + ":" + identifier
		if seen[key] || identifier == "" || utf8.RuneCountInString(identifier) > 254 ||
			utf8.RuneCountInString(member.Status) < 1 || utf8.RuneCountInString(member.Status) > 64 || utf8.RuneCountInString(member.Role) > 64 ||
			!(member.Kind == "member" && member.PlatformMemberID != "" || member.Kind == "pending_invite" && member.PlatformMemberID == "") {
			return false
		}
		seen[key] = true
		if member.Kind == "member" {
			foundMembers++
		} else {
			foundInvitations++
		}
	}
	return foundMembers == memberCount && foundInvitations == invitationCount
}
