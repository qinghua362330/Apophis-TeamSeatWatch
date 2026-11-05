package runtime

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

const joinDispatchReconcileRequired rotationJoinExecutionFailure = "join_reconciliation_required"

type rotationJoinEgress interface {
	Client() *http.Client
	Remeasure(context.Context) error
	Release()
}
type rotationJoinAdapters struct {
	reader    platform.SelectedWorkspaceReader
	discovery platform.DiscoveryAdapter
	identity  platform.PersonalIdentityConfirmer
	members   platform.PersonalMembershipReader
	joiner    platform.RotationCandidateJoiner
}

func officialRotationJoinAdapters(client platform.DiscoveryClient) rotationJoinAdapters {
	return rotationJoinAdapters{reader: platform.OfficialSelectedWorkspaceReader{Client: client}, discovery: platform.AccountsCheckDiscovery{Client: client}, identity: platform.OfficialPersonalIdentityConfirmer{Client: client}, members: platform.OfficialPersonalMembershipReader{Client: client}, joiner: platform.OfficialRotationCandidateJoiner{Client: client}}
}

type joinPersonalBinding struct {
	Revision, Attempt int64
	Generation        uuid.UUID
	KeyVersion        int16
	Nonce, Sealed     []byte
	DBExpiry          time.Time
	Subject           string
}
type joinAdmission struct {
	candidate                         platform.PersonalSession
	binding                           joinPersonalBinding
	access                            platform.WorkspaceAccess
	mother                            platform.PersonalSession
	workspace                         workspaceAccessBinding
	platformID                        string
	motherDBExpiry, workspaceDBExpiry time.Time
}

func (h *OwnerAuthHandler) joinAdmissionLocal(ctx context.Context, tx pgx.Tx, a removalAuthorization, i rotationJoinIntent, owner ownerContext, versions []writerfence.Version) (joinAdmission, error) {
	var out joinAdmission
	fail := func() (joinAdmission, error) { return joinAdmission{}, removalFailure("join_admission_changed") }
	if i.authorizationDigest != a.digest || i.authorizedSession != a.session || rotationHash(i.epochs) != rotationHash(a.epochs) || i.workspaceID != a.preview.WorkspaceId || i.seatType != "prolite" {
		return fail()
	}
	var err error
	out.access, out.mother, out.workspace, out.platformID, err = h.removalLocalFacts(ctx, tx, a, owner, versions)
	if err != nil {
		return out, err
	}
	var originalAccount uuid.UUID
	var member, identifier, seat string
	var evidence uuid.UUID
	err = tx.QueryRow(ctx, `SELECT s.original_account_id,s.platform_member_id,s.identifier,s.seat_type,s.verification_id FROM public.tsw_rotation_released_slots s JOIN public.tsw_rotation_removal_evidence e ON e.id=s.verification_id WHERE s.id=$1 AND s.preview_id=$2 AND s.workspace_id=$3 AND s.candidate_account_id=$4 AND e.authorization_digest=$5 AND e.observed_at<=clock_timestamp()`, i.slotID, i.previewID, i.workspaceID, i.candidateAccountID, i.authorizationDigest).Scan(&originalAccount, &member, &identifier, &seat, &evidence)
	if err != nil {
		return out, err
	}
	if evidence != i.releasedVerificationID || member != i.originalPlatformMemberID || seat != i.seatType {
		return fail()
	}
	matchedSlot, matchedAssignment, matchedCandidate := false, false, false
	for _, s := range a.preview.Slots {
		if s.AccountId == originalAccount && s.PlatformMemberId == member && s.Identifier == identifier && s.SeatType == seat && s.Decision == "replaceable" {
			matchedSlot = true
		}
	}
	for _, s := range a.assignments {
		if s.PlatformMemberId == member && s.AccountId == i.candidateAccountID {
			matchedAssignment = true
		}
	}
	for _, c := range a.preview.Candidates {
		if c.AccountId == i.candidateAccountID && c.Identifier == i.candidateIdentifier && c.SeatType == seat && c.Decision == "eligible" && !c.EverUsed && c.ProtectionStatus == "none" && c.DeliveryStatus == "join_candidate_pending_first_probe" {
			matchedCandidate = true
		}
	}
	if !matchedSlot || !matchedAssignment || !matchedCandidate {
		return fail()
	}
	var eligible bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_target_accounts a JOIN public.tsw_target_credentials c ON c.target_account_id=a.id WHERE a.id=$1 AND a.identifier=$2 AND a.status='active' AND a.version=$3 AND c.version=$4 AND c.material_status='complete' AND c.materials_sealed AND (SELECT count(*) FROM public.tsw_target_accounts same WHERE same.identifier=a.identifier)=1 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_effective_protections p WHERE p.target_account_id=a.id AND p.status<>'none') AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_memberships m JOIN public.tsw_oauth_assets asset ON asset.membership_id=m.id JOIN public.tsw_delivery_versions d ON d.oauth_asset_id=asset.id WHERE m.target_account_id=a.id))`, i.candidateAccountID, i.candidateIdentifier, a.preview.SourceRevisions["account:"+i.candidateAccountID.String()], a.preview.SourceRevisions["credential:"+i.candidateAccountID.String()]).Scan(&eligible)
	if err != nil {
		return out, err
	}
	if !eligible {
		return fail()
	}
	_, clear, err := rotationCandidateLedgerLookup(ctx, tx, i.candidateAccountID, i.workspaceID)
	if err != nil {
		return out, err
	}
	if !clear {
		return fail()
	}
	used, err := rotationPreviouslyUsed(ctx, tx, i.candidateAccountID, i.workspaceID)
	if err != nil {
		return out, err
	}
	if used {
		return fail()
	}
	// A present first-use fact must still be a fresh valid negative. No row is
	// permitted as pre-join absence, never manufactured zero/never_used evidence.
	var historyOK bool
	err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM public.tsw_rotation_usage_ledger WHERE target_account_id=$1 AND (observed_at>clock_timestamp() OR expires_at<=clock_timestamp() OR evidence_id='' OR usage_state<>'never_used' OR ever_used))`, i.candidateAccountID).Scan(&historyOK)
	if err != nil {
		return out, err
	}
	if !historyOK {
		return fail()
	}
	b := &out.binding
	err = tx.QueryRow(ctx, `SELECT s.secret_revision,s.attempt,s.generation,s.key_version,s.nonce,s.sealed_session,s.expires_at,COALESCE(c.platform_subject_id,'') FROM public.tsw_target_credentials c JOIN public.tsw_target_personal_access a ON a.target_account_id=c.target_account_id AND a.secret_revision=c.secret_revision AND a.status='ready' JOIN public.tsw_target_personal_sessions s ON s.target_account_id=a.target_account_id AND s.secret_revision=a.secret_revision AND s.attempt=a.attempt WHERE c.target_account_id=$1 AND s.expires_at>clock_timestamp()+interval '1 minute'`, i.candidateAccountID).Scan(&b.Revision, &b.Attempt, &b.Generation, &b.KeyVersion, &b.Nonce, &b.Sealed, &b.DBExpiry, &b.Subject)
	if err != nil {
		return out, err
	}
	out.candidate, err = openSessionFor("target", h.keyRing, i.candidateAccountID, b.Revision, uint16(b.KeyVersion), b.Nonce, b.Sealed)
	if err != nil || b.Generation == uuid.Nil || !out.candidate.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(b.DBExpiry.UTC()) || !platform.ValidatePersonalRefresh(platform.PersonalRefreshResult{Status: "ready", Session: out.candidate}, time.Now()) {
		return fail()
	}
	err = tx.QueryRow(ctx, `SELECT ms.expires_at,wt.expires_at FROM public.tsw_mother_personal_sessions ms JOIN public.tsw_selected_workspace_tokens wt ON wt.mother_account_id=ms.mother_account_id AND wt.session_generation=ms.generation AND wt.secret_revision=ms.secret_revision WHERE ms.mother_account_id=$1 AND ms.secret_revision=$2 AND ms.generation=$3 AND wt.workspace_id=$4 AND wt.discovery_run_id=$5 AND wt.exchange_id=$6 AND wt.attempt=$7 AND wt.status='ready'`, out.workspace.motherID, out.workspace.revision, out.workspace.generation, out.workspace.workspaceID, out.workspace.run, out.workspace.exchangeID, out.workspace.attempt).Scan(&out.motherDBExpiry, &out.workspaceDBExpiry)
	if err != nil {
		return out, err
	}
	if !out.mother.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(out.motherDBExpiry.UTC()) || !out.access.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(out.workspaceDBExpiry.UTC()) {
		return fail()
	}
	return out, nil
}

func joinRemoteAdmission(ctx context.Context, adapters rotationJoinAdapters, a removalAuthorization, i rotationJoinIntent, p joinAdmission) (platform.PersonalIdentity, time.Time, error) {
	fail := func() (platform.PersonalIdentity, time.Time, error) {
		return platform.PersonalIdentity{}, time.Time{}, removalFailure("join_remote_proof_invalid")
	}
	role, err := adapters.discovery.Discover(ctx, p.mother)
	if err != nil || !platform.ValidateDiscovery(role) || role.Status != "discovered" {
		return fail()
	}
	owner := false
	for _, w := range role.Workspaces {
		if w.PlatformID == p.platformID && w.Access == "readable" && w.Role == "owner" {
			owner = true
		}
	}
	if !owner {
		return fail()
	}
	first, err := adapters.reader.VerifySelectedWorkspace(ctx, p.access, a.preview.MotherAccountId.String(), p.platformID)
	if err != nil {
		return fail()
	}
	second, err := adapters.reader.VerifySelectedWorkspace(ctx, p.access, a.preview.MotherAccountId.String(), p.platformID)
	if err != nil {
		return fail()
	}
	snapshot, ok := compareOfficialRotationSnapshots(first, second)
	if !ok {
		return fail()
	}
	seen := map[string]bool{}
	invite := false
	originalIdentifier := ""
	for _, slot := range a.preview.Slots {
		if slot.PlatformMemberId == i.originalPlatformMemberID {
			originalIdentifier = slot.Identifier
		}
	}
	for _, item := range snapshot.Members {
		identifier := strings.ToLower(strings.TrimSpace(item.Identifier))
		if seen[identifier] {
			return fail()
		}
		seen[identifier] = true
		if item.Kind == "member" && (item.PlatformMemberID == i.originalPlatformMemberID || identifier == originalIdentifier) {
			return fail()
		}
		if identifier == i.candidateIdentifier {
			if item.Kind != "pending_invite" || item.Status != "pending" || item.SeatType != i.seatType {
				return fail()
			}
			invite = true
		}
	}
	if !invite {
		return fail()
	}
	identity, err := adapters.identity.ConfirmPersonalIdentity(ctx, p.candidate)
	now := time.Now().UTC()
	if err != nil || identity.Identifier != i.candidateIdentifier || identity.SubjectID == "" || len(identity.SubjectID) > 255 || p.binding.Subject != "" && identity.SubjectID != p.binding.Subject || identity.ObservedAt.After(now) || identity.ObservedAt.Before(now.Add(-30*time.Second)) || !identity.ExpiresAt.After(now.Add(time.Minute)) || identity.ExpiresAt.After(p.candidate.ExpiresAt) {
		return fail()
	}
	deadline := snapshot.ObservedAt.Add(30 * time.Second)
	if identity.ObservedAt.Add(30 * time.Second).Before(deadline) {
		deadline = identity.ObservedAt.Add(30 * time.Second)
	}
	return identity, deadline, nil
}

// dispatchRotationCandidateJoin consumes only an existing immutable intent. It
// has no route and does not reconcile membership or publish any credentials.
func (h *OwnerAuthHandler) dispatchRotationCandidateJoin(ctx context.Context, owner ownerContext, preview, slot, worker uuid.UUID, duration time.Duration) error {
	i, err := h.loadRotationJoinIntent(ctx, owner, preview, slot)
	if err != nil {
		return err
	}
	l, err := h.claimRotationJoinExecution(ctx, owner, preview, slot, worker, duration)
	if err != nil {
		return err
	}
	if l.reconcileOnly {
		return joinDispatchReconcileRequired
	}
	if h.rotationJoinEgress == nil || h.rotationJoinAdapters == nil {
		return platform.ErrRotationJoinUnavailable
	}
	a, err := loadRemovalAuthorization(ctx, h.pool, i.ownerID, preview)
	if err != nil {
		return err
	}
	keys := rotationAuthorizationKeys(i.ownerID, a.preview)
	bounded, cancel := context.WithDeadline(ctx, minTime(l.expires, time.Now().Add(45*time.Second)))
	defer cancel()
	gate, err := h.lockRemovalGate(bounded, i.workspaceID, keys)
	if err != nil {
		return err
	}
	defer gate.close()
	bounded, releaseTargetRoute, routeBindErr := h.manualTargetRoute(bounded, i.candidateAccountID)
	if routeBindErr != nil {
		return routeBindErr
	}
	defer releaseTargetRoute()
	route, err := h.rotationJoinEgress(bounded)
	if err != nil {
		return platform.ErrRotationJoinUnavailable
	}
	if route == nil {
		return platform.ErrRotationJoinUnavailable
	}
	defer route.Release()
	client := route.Client()
	if client == nil || client.Transport == nil || client.Timeout <= 0 {
		return platform.ErrRotationJoinUnavailable
	}
	factory := func(context.Context) (*http.Client, func(), error) { return client, nil, nil }
	adapters := h.rotationJoinAdapters(factory)
	if adapters.reader == nil || adapters.discovery == nil || adapters.identity == nil || adapters.joiner == nil {
		return platform.ErrRotationJoinUnavailable
	}
	var pinned joinAdmission
	var pinnedIdentity platform.PersonalIdentity
	for index, stage := range []string{"request_join", "accept_join"} {
		if err = checkJoinDispatchGate(bounded, gate); err != nil {
			return err
		}
		tx, versions, err := writerfence.BeginLockedOnConn(bounded, gate.conn, keys)
		if err != nil {
			return err
		}
		current, err := h.joinAdmissionLocal(bounded, tx, a, i, owner, versions)
		rollbackErr := tx.Rollback(bounded)
		if err != nil {
			return err
		}
		if rollbackErr != nil {
			return rollbackErr
		}
		if index == 0 {
			pinned = current
		} else if !sameJoinAdmission(pinned, current) {
			return removalFailure("candidate_generation_changed")
		}
		identity, proofDeadline, err := joinRemoteAdmission(bounded, adapters, a, i, pinned)
		if err != nil {
			return err
		}
		if index == 0 {
			pinnedIdentity = identity
		} else if pinnedIdentity.Identifier != identity.Identifier || pinnedIdentity.SubjectID != identity.SubjectID || !pinnedIdentity.ExpiresAt.Equal(identity.ExpiresAt) {
			return removalFailure("candidate_identity_changed")
		}
		if err = route.Remeasure(bounded); err != nil {
			return platform.ErrRotationJoinUnavailable
		}
		if err = checkJoinDispatchGate(bounded, gate); err != nil {
			return err
		}
		// Recheck sources locally AFTER bounded read-only I/O, then durably mark
		// the individual stage in this same transaction. No network in this tx.
		tx, versions, err = writerfence.BeginLockedOnConn(bounded, gate.conn, keys)
		if err != nil {
			return err
		}
		current, err = h.joinAdmissionLocal(bounded, tx, a, i, owner, versions)
		if err == nil && !sameJoinAdmission(current, pinned) {
			err = removalFailure("candidate_generation_changed")
		}
		var state string
		if err == nil {
			err = tx.QueryRow(bounded, `SELECT state FROM public.tsw_rotation_join_executions WHERE `+joinExecutionCAS+` FOR UPDATE`, l.slotID, l.workerID, l.token, l.epoch, l.owner.SessionID, l.owner.OwnerID).Scan(&state)
		}
		if err == nil {
			guard, args := joinDispatchWriteGuard(i, pinned, pinnedIdentity, proofDeadline)
			if stage == "accept_join" {
				err = requireJoinPersonalBinding(bounded, tx, i, pinned, pinnedIdentity.SubjectID)
			}
			if err == nil {
				err = markRotationJoinStageInTx(bounded, tx, l, state, stage, guard, args)
			}
			if err == nil && stage == "request_join" {
				err = appendJoinPersonalBinding(bounded, tx, l, i, pinned, pinnedIdentity)
			}
		}
		if err != nil {
			_ = tx.Rollback(bounded)
			return err
		}
		if err = tx.Commit(bounded); err != nil {
			return err
		}
		if err = checkJoinDispatchGate(bounded, gate); err != nil {
			return err
		}
		guard, args := joinDispatchWriteGuard(i, pinned, pinnedIdentity, proofDeadline)
		startedState := "request_started"
		if stage == "accept_join" {
			startedState = "accept_started"
		}
		finalArgs := append([]any{l.slotID, l.workerID, l.token, l.epoch, l.owner.SessionID, l.owner.OwnerID, startedState}, args...)
		var admitted bool
		if err = gate.conn.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_executions WHERE `+joinExecutionCAS+guard+` AND state=$7)`, finalArgs...).Scan(&admitted); err != nil || !admitted {
			return joinDispatchReconcileRequired
		}
		var receipt platform.JoinAttemptResult
		if stage == "request_join" {
			receipt, err = adapters.joiner.RequestCandidateJoin(bounded, pinned.candidate, pinned.platformID)
		} else {
			receipt, err = adapters.joiner.AcceptCandidateJoin(bounded, pinned.candidate, pinned.platformID)
		}
		outcome := joinDispatchOutcome(receipt, err)
		// Only bounded enums leave the adapter; no upstream body/code/error text.
		finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
		finishErr := finishRotationJoinStageOn(finishCtx, gate.conn, l, stage, outcome, receipt.RequestMayHaveEffect || receipt.RequestSent)
		finishCancel()
		if finishErr != nil {
			return joinDispatchReconcileRequired
		}
		if outcome != "succeeded" {
			return joinDispatchReconcileRequired
		}
	}
	return joinDispatchReconcileRequired
}
func sameJoinAdmission(a, b joinAdmission) bool {
	return a.workspace == b.workspace && a.platformID == b.platformID && a.motherDBExpiry.Equal(b.motherDBExpiry) && a.workspaceDBExpiry.Equal(b.workspaceDBExpiry) && rotationHash(a.binding) == rotationHash(b.binding) && rotationHash(a.candidate) == rotationHash(b.candidate) && rotationHash(a.mother) == rotationHash(b.mother) && rotationHash(a.access) == rotationHash(b.access)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func joinDispatchOutcome(r platform.JoinAttemptResult, err error) string {
	if err == nil && r.Success && r.RequestSent && r.RequestMayHaveEffect && r.HTTPStatus >= 200 && r.HTTPStatus < 300 && r.ErrorCode == "" && (r.Semantic == "success_true" || r.Semantic == "status_ok" || r.Semantic == "status_success" || r.Semantic == "status_accepted") {
		return "succeeded"
	}
	if err == nil && r.HTTPStatus >= 400 && r.HTTPStatus < 500 && !r.Success {
		return "failed"
	}
	return "uncertain"
}

// Final write-time clocks accompany the original epoch and binding recheck.
// Source/action gates keep the non-clock facts unchanged until dispatch.
func joinDispatchWriteGuard(i rotationJoinIntent, p joinAdmission, identity platform.PersonalIdentity, proof time.Time) (string, []any) {
	b := p.binding
	w := p.workspace
	return ` AND $8::timestamptz>clock_timestamp() AND $9::timestamptz>clock_timestamp()+interval '1 minute' AND $10::timestamptz>clock_timestamp()+interval '1 minute' AND $11::timestamptz>clock_timestamp()+interval '30 seconds'
 AND EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=$12 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM public.tsw_rotation_released_slots WHERE id=$1 AND verification_id=$13)
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_usage_ledger WHERE target_account_id=$14 AND expires_at<=clock_timestamp())
 AND NOT public.tsw_rotation_join_usage_blocks_candidate($14,$26)
 AND EXISTS(SELECT 1 FROM public.tsw_target_personal_sessions s JOIN public.tsw_target_personal_access a ON a.target_account_id=s.target_account_id AND a.secret_revision=s.secret_revision AND a.attempt=s.attempt AND a.status='ready' JOIN public.tsw_target_credentials c ON c.target_account_id=s.target_account_id AND c.secret_revision=s.secret_revision WHERE s.target_account_id=$14 AND s.secret_revision=$15 AND s.attempt=$16 AND s.generation=$17 AND s.key_version=$18 AND s.nonce=$19 AND s.sealed_session=$20 AND s.expires_at=$21 AND s.expires_at>clock_timestamp()+interval '1 minute')
 AND EXISTS(SELECT 1 FROM public.tsw_mother_personal_sessions s WHERE s.mother_account_id=$22 AND s.secret_revision=$23 AND s.generation=$24 AND s.expires_at=$25 AND s.expires_at>clock_timestamp()+interval '1 minute')
 AND EXISTS(SELECT 1 FROM public.tsw_selected_workspace_tokens t WHERE t.mother_account_id=$22 AND t.secret_revision=$23 AND t.session_generation=$24 AND t.workspace_id=$26 AND t.discovery_run_id=$27 AND t.exchange_id=$28 AND t.attempt=$29 AND t.status='ready' AND t.expires_at=$30 AND t.expires_at>clock_timestamp()+interval '30 seconds')`, []any{proof, identity.ExpiresAt, p.mother.ExpiresAt, p.access.ExpiresAt, i.authorizedSession, i.releasedVerificationID, i.candidateAccountID, b.Revision, b.Attempt, b.Generation, b.KeyVersion, b.Nonce, b.Sealed, b.DBExpiry, w.motherID, w.revision, w.generation, p.motherDBExpiry, w.workspaceID, w.run, w.exchangeID, w.attempt, p.workspaceDBExpiry}
}

func checkJoinDispatchGate(ctx context.Context, g *removalGate) error {
	return checkJoinGateLocks(ctx, g, true)
}

// Read-only membership GETs retain the physical session and source action
// locks, but deliberately release Workspace so stop can fence them promptly.
func checkJoinReadGate(ctx context.Context, g *removalGate) error {
	return checkJoinGateLocks(ctx, g, false)
}

func checkJoinGateLocks(ctx context.Context, g *removalGate, requireWorkspace bool) error {
	if g.conn == nil || requireWorkspace && !g.workspaceLocked {
		return removalFailure("dispatch_gate_lost")
	}
	// A healthy connection alone is insufficient: unlock_all on a still-live
	// session must also prohibit egress. Probe every originally held lock.
	scopes := make([]string, 0, len(g.keys))
	for _, key := range g.keys {
		scopes = append(scopes, "tsw.rotation.action."+string(key.Kind)+"/"+key.ID.String())
	}
	if requireWorkspace {
		scopes = append(scopes, "tsw.rotation.workspace."+g.workspace.String())
	}
	var held bool
	err := g.conn.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM unnest($1::text[]) scope WHERE NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.objsubid=1 AND l.classid=((hashtextextended(scope,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(scope,0)&4294967295)::oid))`, scopes).Scan(&held)
	if err != nil || !held {
		return removalFailure("dispatch_gate_lost")
	}
	return nil
}
