package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

const rotationMembershipEvidenceSource = "personal_session_members"

type rotationMembershipObservation struct {
	result, memberID, diagnostic string
}

func classifyRotationMembership(result platform.Result, readErr error, identifier, seat string) rotationMembershipObservation {
	observation := rotationMembershipObservation{result: "unknown", diagnostic: "membership_unknown"}
	if readErr != nil || result.Outcome != platform.OutcomeOperational || result.Completeness != platform.Complete {
		if result.Outcome == platform.OutcomeUnauthorized || result.Outcome == platform.OutcomeForbidden {
			observation.diagnostic = "membership_unauthorized"
		} else if result.Completeness != platform.Complete || result.Outcome == platform.OutcomeIncomplete {
			observation.diagnostic = "membership_incomplete"
		}
		return observation
	}
	canonical := strings.ToLower(strings.TrimSpace(identifier))
	seen := make(map[string]bool, len(result.Members))
	memberIDs := make(map[string]bool, len(result.Members))
	userIDs := make(map[string]bool, len(result.Members))
	matches := make([]platform.Member, 0, 1)
	for _, member := range result.Members {
		key := strings.ToLower(strings.TrimSpace(member.Identifier))
		if key == "" || seen[key] {
			observation.diagnostic = "membership_duplicate_identifier"
			observation.result = "unknown"
			return observation
		}
		seen[key] = true
		if member.PlatformMemberID != "" && memberIDs[member.PlatformMemberID] || member.PlatformAccountUserID != "" && userIDs[member.PlatformAccountUserID] {
			observation.diagnostic = "membership_duplicate_identity"
			return observation
		}
		if member.PlatformMemberID != "" {
			memberIDs[member.PlatformMemberID] = true
		}
		if member.PlatformAccountUserID != "" {
			userIDs[member.PlatformAccountUserID] = true
		}
		if key == canonical {
			matches = append(matches, member)
		}
	}
	if len(matches) == 0 {
		observation.result = "absent"
		observation.diagnostic = "reconcile_absent"
		return observation
	}
	if len(matches) != 1 {
		observation.diagnostic = "membership_duplicate_identifier"
		return observation
	}
	member := matches[0]
	if member.Kind != "member" || (member.Status != "active" && member.Status != "accepted") || member.SeatType != seat || member.PlatformMemberID == "" {
		observation.result = "invalid"
		observation.diagnostic = "member_not_confirmed"
		return observation
	}
	if seat != "prolite" {
		observation.result = "invalid"
		observation.diagnostic = "member_seat_invalid"
		return observation
	}
	observation.result = "confirmed"
	observation.memberID = member.PlatformMemberID
	observation.diagnostic = "member_confirmed"
	return observation
}

// reconcileRotationJoinMembership reads the exact original workspace roster
// with the pinned Personal session and appends bounded evidence. It never
// sends a POST and never changes the execution out of reconcile_required.
func (h *OwnerAuthHandler) reconcileRotationJoinMembership(ctx context.Context, owner ownerContext, previewID, slotID, workerID uuid.UUID, duration time.Duration) error {
	i, err := h.loadRotationJoinIntent(ctx, owner, previewID, slotID)
	if err != nil {
		return err
	}
	var marked bool
	if err = h.pool.QueryRow(ctx, `SELECT state='reconcile_required' OR request_may_have_reached FROM public.tsw_rotation_join_executions WHERE slot_id=$1 AND preview_id=$2 AND owner_id=$3`, slotID, previewID, owner.OwnerID).Scan(&marked); err != nil || !marked {
		return joinExecutionTransition
	}
	lease, err := h.claimRotationJoinExecution(ctx, owner, previewID, slotID, workerID, duration)
	if err != nil {
		return err
	}
	if !lease.reconcileOnly {
		return joinExecutionTransition
	}
	if h.rotationJoinEgress == nil || h.rotationJoinAdapters == nil {
		return platform.ErrRotationJoinUnavailable
	}
	a, err := loadRemovalAuthorization(ctx, h.pool, i.ownerID, previewID)
	if err != nil {
		return err
	}
	keys := rotationAuthorizationKeys(i.ownerID, a.preview)
	bounded, cancel := context.WithDeadline(ctx, minTime(lease.expires, time.Now().Add(45*time.Second)))
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
	if route != nil {
		defer route.Release()
	}
	if err != nil || route == nil || route.Client() == nil || route.Client().Transport == nil || route.Client().Timeout <= 0 {
		return platform.ErrRotationJoinUnavailable
	}
	client := route.Client()
	adapters := h.rotationJoinAdapters(func(context.Context) (*http.Client, func(), error) { return client, nil, nil })
	if adapters.members == nil || adapters.identity == nil {
		return platform.ErrRotationJoinUnavailable
	}
	localAdmission := func() (joinAdmission, error) {
		tx, versions, localErr := writerfence.BeginLockedOnConn(bounded, gate.conn, keys)
		if localErr != nil {
			return joinAdmission{}, localErr
		}
		admission, localErr := h.joinAdmissionLocal(bounded, tx, a, i, owner, versions)
		rollbackErr := tx.Rollback(bounded)
		if localErr != nil {
			return joinAdmission{}, localErr
		}
		if rollbackErr != nil {
			return joinAdmission{}, rollbackErr
		}
		return admission, nil
	}
	// All evidence branches must reacquire Workspace, including invalid identity
	// and unknown reads. No source epoch transaction spans this read phase.
	persistUnknown := func(diagnostic string) error {
		if err := gate.lockWorkspace(bounded); err != nil {
			return err
		}
		if err := checkJoinDispatchGate(bounded, gate); err != nil {
			return err
		}
		return h.persistRotationJoinMembershipEvidence(bounded, gate.conn, keys, lease, i, rotationMembershipObservation{result: "unknown", diagnostic: diagnostic}, time.Now().UTC(), nil)
	}
	admission, err := localAdmission()
	if err != nil {
		return persistUnknown("admission_changed")
	}
	if err = requireJoinPersonalBinding(bounded, gate.conn, i, admission, ""); err != nil {
		return persistUnknown("dispatch_personal_binding_changed")
	}
	if err = checkJoinDispatchGate(bounded, gate); err != nil {
		return err
	}
	if err = gate.unlockWorkspace(bounded); err != nil {
		return err
	}
	if err = checkJoinReadGate(bounded, gate); err != nil {
		return err
	}
	identity, err := adapters.identity.ConfirmPersonalIdentity(bounded, admission.candidate)
	if err != nil || identity.SubjectID == "" || identity.ObservedAt.After(time.Now()) || identity.ObservedAt.Before(time.Now().Add(-30*time.Second)) || !identity.ExpiresAt.After(time.Now().Add(time.Minute)) || identity.Identifier != i.candidateIdentifier || requireJoinPersonalBinding(bounded, gate.conn, i, admission, identity.SubjectID) != nil {
		return persistUnknown("candidate_identity_changed")
	}
	if err = checkJoinReadGate(bounded, gate); err != nil {
		return err
	}
	observationResult, readErr := adapters.members.ReadMembers(bounded, admission.candidate, admission.platformID)
	observation := classifyRotationMembership(observationResult, readErr, i.candidateIdentifier, i.seatType)
	observed := observationResult.ObservedAt
	if observed.IsZero() || observed.After(time.Now()) || observed.Before(time.Now().Add(-30*time.Second)) {
		observation = rotationMembershipObservation{result: "unknown", diagnostic: "membership_stale"}
		observed = time.Now().UTC()
	}
	if err = route.Remeasure(bounded); err != nil {
		return platform.ErrRotationJoinUnavailable
	}
	if err = checkJoinReadGate(bounded, gate); err != nil {
		return err
	}
	if err = gate.lockWorkspace(bounded); err != nil {
		return err
	}
	if err = checkJoinDispatchGate(bounded, gate); err != nil {
		return err
	}
	current, err := localAdmission()
	if err != nil {
		return persistUnknown("admission_changed")
	}
	if !sameJoinAdmission(admission, current) || requireJoinPersonalBinding(bounded, gate.conn, i, current, identity.SubjectID) != nil {
		return persistUnknown("candidate_generation_changed")
	}
	return h.persistRotationJoinMembershipEvidence(bounded, gate.conn, keys, lease, i, observation, observed, &admission)
}

func (h *OwnerAuthHandler) persistRotationJoinMembershipEvidence(ctx context.Context, conn *pgxpool.Conn, keys []writerfence.Key, lease rotationJoinExecutionLease, intent rotationJoinIntent, observation rotationMembershipObservation, observed time.Time, expected *joinAdmission) error {
	// A replay of the same committed attempt is observation-only. A superseded
	// lease or conflicting digest cannot turn an earlier confirmed row into a
	// replacement observation.
	if err := rotationJoinOwnerLegal(ctx, conn, lease.owner); err != nil {
		return err
	}
	var same bool
	err := conn.QueryRow(ctx, `SELECT ev.evidence_digest=public.tsw_rotation_join_membership_digest(ev.slot_id,ev.reconciliation_attempt,$5,ev.source,$6,$7,$8,$9,$10,ev.lease_epoch,$11) FROM public.tsw_rotation_join_membership_evidence ev JOIN public.tsw_rotation_join_executions e USING(slot_id) WHERE ev.slot_id=$1 AND ev.lease_owner=$2 AND ev.lease_token=$3 AND ev.lease_epoch=$4 AND e.lease_epoch=$4`, lease.slotID, lease.workerID, lease.token, lease.epoch, observed, observation.result, observation.memberID, intent.candidateIdentifier, intent.seatType, intent.workspaceID, observation.diagnostic).Scan(&same)
	if err == nil {
		if same {
			return joinDispatchReconcileRequired
		}
		return joinExecutionTransition
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	tx, versions, err := writerfence.BeginLockedOnConn(ctx, conn, keys)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if expected != nil {
		a, localErr := loadRemovalAuthorization(ctx, tx, intent.ownerID, intent.previewID)
		if localErr != nil {
			return localErr
		}
		current, localErr := h.joinAdmissionLocal(ctx, tx, a, intent, lease.owner, versions)
		if localErr != nil || !sameJoinAdmission(*expected, current) || requireJoinPersonalBinding(ctx, tx, intent, current, "") != nil {
			observation = rotationMembershipObservation{result: "unknown", diagnostic: "admission_changed"}
			observed = time.Now().UTC()
		}
	}
	var attempt int
	var started time.Time
	err = tx.QueryRow(ctx, `SELECT a.attempt_no,a.started_at FROM public.tsw_rotation_join_execution_attempts a JOIN public.tsw_rotation_join_executions e ON e.slot_id=a.slot_id WHERE e.slot_id=$1 AND e.lease_owner=$2 AND e.lease_token=$3 AND e.lease_epoch=$4 AND e.lease_expires_at>clock_timestamp() AND e.state='reconcile_required' AND a.slot_id=e.slot_id AND a.lease_epoch=e.lease_epoch AND a.stage='reconcile' AND a.event_kind='started' AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_execution_attempts f WHERE f.start_event_id=a.id) FOR UPDATE OF e,a`, lease.slotID, lease.workerID, lease.token, lease.epoch).Scan(&attempt, &started)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return joinExecutionStale
		}
		return err
	}
	var digest string
	err = tx.QueryRow(ctx, `SELECT public.tsw_rotation_join_membership_digest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, intent.slotID, attempt, observed, rotationMembershipEvidenceSource, observation.result, observation.memberID, intent.candidateIdentifier, intent.seatType, intent.workspaceID, lease.epoch, observation.diagnostic).Scan(&digest)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_membership_evidence(slot_id,reconciliation_attempt,observed_at,source,result,platform_member_id,candidate_identifier,seat_type,workspace_id,lease_epoch,diagnostic,evidence_digest,lease_owner,lease_token,owner_session) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(slot_id,reconciliation_attempt) DO NOTHING`, intent.slotID, attempt, observed, rotationMembershipEvidenceSource, observation.result, observation.memberID, intent.candidateIdentifier, intent.seatType, intent.workspaceID, lease.epoch, observation.diagnostic, digest, lease.workerID, lease.token, lease.owner.SessionID)
	if err != nil {
		return err
	}
	var storedDigest string
	if err = tx.QueryRow(ctx, `SELECT evidence_digest FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1 AND reconciliation_attempt=$2`, intent.slotID, attempt).Scan(&storedDigest); err != nil {
		return err
	}
	if storedDigest != digest {
		return joinExecutionTransition
	}
	var startID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM public.tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND lease_epoch=$2 AND stage='reconcile' AND attempt_no=$3 AND event_kind='started'`, lease.slotID, lease.epoch, attempt).Scan(&startID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_execution_attempts(slot_id,lease_epoch,stage,attempt_no,event_kind,start_event_id,may_have_reached,outcome,started_at,finished_at) VALUES($1,$2,'reconcile',$3,'finished',$4,false,$5,$6,clock_timestamp())`, lease.slotID, lease.epoch, attempt, startID, observation.resultToOutcome(), started)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.tsw_rotation_join_executions SET state='reconcile_required',last_stage='reconcile',last_outcome=$7,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE `+joinExecutionCAS, lease.slotID, lease.workerID, lease.token, lease.epoch, lease.owner.SessionID, lease.owner.OwnerID, observation.resultToOutcome())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return joinExecutionStale
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return joinDispatchReconcileRequired
}

func (o rotationMembershipObservation) resultToOutcome() string {
	if o.result == "confirmed" || o.result == "absent" {
		return "succeeded"
	}
	return "uncertain"
}

// Only a digest of ciphertext is saved; no bearer, cookie, nonce or plaintext
// session crosses this append-only journal boundary.
func appendJoinPersonalBinding(ctx context.Context, tx pgx.Tx, lease rotationJoinExecutionLease, i rotationJoinIntent, p joinAdmission, identity platform.PersonalIdentity) error {
	digest := sha256.Sum256(p.binding.Sealed)
	_, err := tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_personal_bindings(slot_id,candidate_account_id,workspace_id,platform_workspace_id,candidate_identifier,seat_type,secret_revision,attempt,generation,key_version,sealed_digest,db_expiry,decoded_expiry,subject_id,identity_observed_at,source,lease_epoch,lease_owner,lease_token,owner_session) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'personal_identity_confirmation',$16,$17,$18,$19)`, i.slotID, i.candidateAccountID, i.workspaceID, p.platformID, i.candidateIdentifier, i.seatType, p.binding.Revision, p.binding.Attempt, p.binding.Generation, p.binding.KeyVersion, hex.EncodeToString(digest[:]), p.binding.DBExpiry, p.candidate.ExpiresAt.UTC().Truncate(time.Microsecond), identity.SubjectID, identity.ObservedAt, lease.epoch, lease.workerID, lease.token, lease.owner.SessionID)
	return err
}
func requireJoinPersonalBinding(ctx context.Context, db rotationRow, i rotationJoinIntent, p joinAdmission, subject string) error {
	digest := sha256.Sum256(p.binding.Sealed)
	var exact bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_personal_bindings b WHERE slot_id=$1 AND candidate_account_id=$2 AND workspace_id=$3 AND platform_workspace_id=$4 AND candidate_identifier=$5 AND seat_type=$6 AND secret_revision=$7 AND attempt=$8 AND generation=$9 AND key_version=$10 AND sealed_digest=$11 AND db_expiry=$12 AND decoded_expiry=$13 AND ($14::text='' OR subject_id=$14) AND ($15::text='' OR subject_id=$15))`, i.slotID, i.candidateAccountID, i.workspaceID, p.platformID, i.candidateIdentifier, i.seatType, p.binding.Revision, p.binding.Attempt, p.binding.Generation, p.binding.KeyVersion, hex.EncodeToString(digest[:]), p.binding.DBExpiry, p.candidate.ExpiresAt.UTC().Truncate(time.Microsecond), subject, p.binding.Subject).Scan(&exact)
	if err != nil {
		return err
	}
	if !exact {
		return removalFailure("dispatch_personal_binding_changed")
	}
	return nil
}
