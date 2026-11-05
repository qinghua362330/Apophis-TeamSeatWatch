package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

const joinUsageBusy rotationJoinExecutionFailure = "join_usage_busy"
const joinUsageStale rotationJoinExecutionFailure = "join_usage_stale"

type joinUsageAttempt struct {
	id         uuid.UUID
	credential joinCredentialAttempt
	lease      rotationJoinExecutionLease
	state      string
}

// observeRotationJoinUsage only reads the original candidate after its complete
// credential generation. A retry resumes a pending read-only obligation; an
// explicit recheck creates a new attempt after the prior atomic completion.
func (h *OwnerAuthHandler) observeRotationJoinUsage(ctx context.Context, owner ownerContext, preview, slot, worker uuid.UUID, duration time.Duration, recheck bool) error {
	if worker == uuid.Nil || duration <= 0 || h.rotationJoinEgress == nil || h.rotationJoinAdapters == nil || h.rotationUsageAdapters == nil {
		return platform.ErrRotationUsageUnavailable
	}
	i, err := h.loadRotationJoinIntent(ctx, owner, preview, slot)
	if err != nil {
		return err
	}
	auth, err := loadRemovalAuthorization(ctx, h.pool, i.ownerID, preview)
	if err != nil {
		return err
	}
	keys := rotationAuthorizationKeys(i.ownerID, auth.preview)
	bounded, cancel := context.WithTimeout(ctx, min(duration, 45*time.Second))
	defer cancel()
	// Lock order is source/action keys (including target account) before the
	// workspace gate. A source writer therefore waits before taking workspace;
	// it cannot deadlock against this read's later epoch transaction.
	actionKeys := append([]writerfence.Key(nil), keys...)
	gate, err := h.lockRotationUsageGate(bounded, i.workspaceID, actionKeys, i.candidateAccountID)
	if err != nil {
		return err
	}
	defer gate.close()
	var attempt joinUsageAttempt
	var candidate platform.PersonalSession
	var oauth platform.DeliveryCredentialSet
	local := func(fn func(pgx.Tx) error) error {
		if err := gate.lockWorkspace(bounded); err != nil {
			return err
		}
		if err := checkJoinDispatchGate(bounded, gate); err != nil {
			return err
		}
		tx, versions, err := writerfence.BeginLockedOnConn(bounded, gate.conn, keys)
		if err != nil {
			return err
		}
		defer tx.Rollback(bounded)
		if _, _, _, _, err = h.removalLocalFacts(bounded, tx, auth, owner, versions); err != nil {
			return err
		}
		var valid bool
		if err = tx.QueryRow(bounded, `SELECT public.tsw_rotation_join_usage_authority($1,$2)`, slot, owner.SessionID).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return joinUsageStale
		}
		current, err := readJoinCredentialAttempt(bounded, tx, slot)
		if err != nil {
			return err
		}
		if attempt.credential.binding.attempt != uuid.Nil && current.binding != attempt.credential.binding {
			return joinUsageStale
		}
		if _, _, err = h.validateSavedJoinCredentials(bounded, tx, current); err != nil {
			return err
		}
		var saved platform.DeliveryCredentialSet
		if _, err = h.readCredentialComponent(bounded, tx, current, "oauth", &saved); err != nil {
			return err
		}
		oauth = saved
		var key int16
		var nonce, sealed []byte
		var expires time.Time
		if err = tx.QueryRow(bounded, `SELECT s.key_version,s.nonce,s.sealed_session,s.expires_at FROM public.tsw_rotation_join_personal_bindings b JOIN public.tsw_target_personal_sessions s ON s.target_account_id=b.candidate_account_id AND s.secret_revision=b.secret_revision AND s.attempt=b.attempt AND s.generation=b.generation WHERE b.slot_id=$1`, slot).Scan(&key, &nonce, &sealed, &expires); err != nil {
			return err
		}
		candidate, err = openSessionFor("target", h.keyRing, current.binding.target, current.binding.revision, uint16(key), nonce, sealed)
		if err != nil || !candidate.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(expires) || !platform.ValidateRotationCandidatePersonal(candidate, current.subject, time.Now()) {
			return joinUsageStale
		}
		attempt.credential = current
		if attempt.lease.token != uuid.Nil {
			if err = requireUsageLease(bounded, tx, attempt); err != nil {
				return err
			}
		}
		if err = fn(tx); err != nil {
			return err
		}
		return tx.Commit(bounded)
	}
	err = local(func(tx pgx.Tx) error {
		// The credential row is already locked by the epoch transaction; serializing
		// on it also prevents concurrent first attempts on an empty journal.
		if _, err := tx.Exec(bounded, `SELECT 1 FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1 FOR UPDATE`, slot); err != nil {
			return err
		}
		var id uuid.UUID
		var state string
		var busy bool
		err := tx.QueryRow(bounded, `SELECT id,state,COALESCE(lease_expires_at>clock_timestamp(),false) FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=$1 ORDER BY attempt_no DESC LIMIT 1 FOR UPDATE`, slot).Scan(&id, &state, &busy)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if busy {
			return joinUsageBusy
		}
		if err == nil && state == "complete" && !recheck {
			attempt.state = state
			return nil
		}
		if errors.Is(err, pgx.ErrNoRows) || state == "complete" {
			id = uuid.New()
			_, err = tx.Exec(bounded, `INSERT INTO public.tsw_rotation_join_usage_attempts(id,slot_id,attempt_no,credential_attempt_id) SELECT $1,$2,COALESCE(max(attempt_no),0)+1,$3 FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=$2`, id, slot, attempt.credential.binding.attempt)
			if err != nil {
				return err
			}
		}
		attempt.id = id
		return nil
	})
	if err != nil || attempt.state == "complete" {
		return err
	}
	// The accepted read obligation commits before its lease claim. A failed
	// claim cannot roll back the latest pending attempt and revive an old zero.
	err = local(func(tx pgx.Tx) error {
		id := attempt.id
		l := rotationJoinExecutionLease{slotID: slot, workerID: worker, token: uuid.New(), owner: owner}
		err = tx.QueryRow(bounded, `UPDATE public.tsw_rotation_join_usage_attempts SET lease_owner=$2,lease_token=$3,owner_session=$4,lease_epoch=lease_epoch+1,lease_expires_at=LEAST(clock_timestamp()+$5::bigint*interval '1 microsecond',(SELECT LEAST(idle_expires_at,absolute_expires_at) FROM public.tsw_owner_sessions WHERE id=$4)) WHERE id=$1 AND state='pending' AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp()) RETURNING lease_epoch,lease_expires_at`, id, worker, l.token, owner.SessionID, duration.Microseconds()).Scan(&l.epoch, &l.expires)
		attempt.lease = l
		return err
	})
	if err != nil || attempt.state == "complete" {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = gate.conn.Exec(cleanup, `UPDATE public.tsw_rotation_join_usage_attempts SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,owner_session=NULL WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 AND lease_epoch=$4 AND owner_session=$5 AND state='pending' AND lease_expires_at>clock_timestamp()`, usageLeaseArgs(attempt)...)
	}()
	deadline, leaseCancel := context.WithDeadline(bounded, attempt.lease.expires)
	defer leaseCancel()
	bounded = deadline
	evidence := platform.RotationUsageEvidence{Result: "unknown", Scope: "account", Diagnostic: "usage_unknown", Windows: []platform.RotationUsageWindow{}}
	bounded, releaseTargetRoute, bindErr := h.manualTargetRoute(bounded, i.candidateAccountID)
	if bindErr != nil {
		return bindErr
	}
	defer releaseTargetRoute()
	route, routeErr := h.rotationJoinEgress(bounded)
	if route != nil {
		defer route.Release()
	}
	if routeErr == nil && route != nil && route.Client() != nil && route.Client().Transport != nil && route.Client().Timeout > 0 {
		base := route.Client()
		client := *base
		client.Transport = joinCredentialTransport{next: base.Transport, before: func(r *http.Request) error {
			if r.Method != http.MethodGet {
				return platform.ErrRotationUsageUnavailable
			}
			if err := gate.unlockWorkspace(bounded); err != nil {
				return err
			}
			if err := checkJoinReadGate(bounded, gate); err != nil {
				return err
			}
			if err := route.Remeasure(bounded); err != nil {
				return err
			}
			return requireUsageLease(bounded, gate.conn, attempt)
		}}
		factory := func(context.Context) (*http.Client, func(), error) { return &client, nil, nil }
		reads := h.rotationJoinAdapters(factory)
		reader := h.rotationUsageAdapters(factory)
		if reads.members != nil && reader != nil {
			result, readErr := reads.members.ReadMembers(bounded, candidate, attempt.credential.binding.platformWorkspace)
			membership := classifyRotationMembership(result, readErr, i.candidateIdentifier, i.seatType)
			now := time.Now().UTC()
			matchedSubject := true
			for _, member := range result.Members {
				if member.Identifier == i.candidateIdentifier && member.PlatformAccountUserID != "" && member.PlatformAccountUserID != attempt.credential.subject {
					matchedSubject = false
				}
			}
			if membership.result == "confirmed" && membership.memberID == attempt.credential.member && matchedSubject && !result.ObservedAt.After(now) && result.ObservedAt.After(now.Add(-30*time.Second)) {
				measured, readErr := reader.ReadRotationUsage(bounded, oauth, attempt.credential.subject)
				if readErr == nil {
					evidence = measured
				}
			}
		}
	}
	evidence = normalizeRotationUsage(evidence, attempt.credential.binding.platformWorkspace, time.Now().UTC())
	return local(func(tx pgx.Tx) error { return persistUsageEvidence(bounded, tx, attempt, evidence) })
}

func normalizeRotationUsage(in platform.RotationUsageEvidence, workspace string, now time.Time) platform.RotationUsageEvidence {
	unknown := platform.RotationUsageEvidence{Result: "unknown", Scope: "account", Diagnostic: "usage_unknown", ObservedAt: now.Truncate(time.Microsecond), Windows: []platform.RotationUsageWindow{}}
	if in.Scope != "workspace" && in.Scope != "account" || in.Scope == "workspace" && in.WorkspaceID != workspace || in.ObservedAt.IsZero() || in.ObservedAt.After(now) || in.ObservedAt.Before(now.Add(-30*time.Second)) {
		return unknown
	}
	in.ObservedAt = in.ObservedAt.UTC().Truncate(time.Microsecond)
	seen := map[int64]bool{}
	positive := false
	for _, w := range in.Windows {
		if (w.Seconds <= 0 || w.Seconds > 31536000) || seen[w.Seconds] || w.UsedPercent < 0 || w.UsedPercent > 100 || !w.ResetsAt.After(in.ObservedAt) {
			return unknown
		}
		seen[w.Seconds] = true
		positive = positive || w.UsedPercent > 0
	}
	if positive {
		in.Result = "positive"
		in.Diagnostic = "usage_positive"
	} else if in.Result == "zero" && len(seen) == 2 && seen[18000] && seen[604800] {
		in.Diagnostic = "usage_zero"
	} else {
		in.Result = "unknown"
		in.Diagnostic = "usage_unknown"
	}
	if in.Windows == nil {
		in.Windows = []platform.RotationUsageWindow{}
	}
	return in
}
func usageLeaseArgs(a joinUsageAttempt) []any {
	return []any{a.id, a.lease.workerID, a.lease.token, a.lease.epoch, a.lease.owner.SessionID}
}
func requireUsageLease(ctx context.Context, db rotationRow, a joinUsageAttempt) error {
	var ok bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_attempts WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 AND lease_epoch=$4 AND owner_session=$5 AND state='pending' AND lease_expires_at>clock_timestamp() AND public.tsw_rotation_join_usage_authority(slot_id,$5))`, usageLeaseArgs(a)...).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return joinUsageStale
	}
	return nil
}
func persistUsageEvidence(ctx context.Context, tx pgx.Tx, a joinUsageAttempt, e platform.RotationUsageEvidence) error {
	windows, err := json.Marshal(e.Windows)
	if err != nil {
		return err
	}
	expiry := e.ObservedAt.Add(5 * time.Minute)
	for _, w := range e.Windows {
		expiry = minTime(expiry, w.ResetsAt)
	}
	digest := rotationHash(struct {
		Attempt    uuid.UUID
		Credential uuid.UUID
		Evidence   platform.RotationUsageEvidence
	}{a.id, a.credential.binding.generation, e})
	l := a.lease
	_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_usage_evidence(attempt_id,target_account_id,workspace_id,scope,result,diagnostic,windows,evidence_digest,observed_at,expires_at,lease_owner,lease_token,lease_epoch,owner_session) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, a.id, a.credential.binding.target, a.credential.binding.workspace, e.Scope, e.Result, e.Diagnostic, windows, digest, e.ObservedAt, expiry, l.workerID, l.token, l.epoch, l.owner.SessionID)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.tsw_rotation_join_usage_attempts SET state='complete',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,owner_session=NULL WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 AND lease_epoch=$4 AND owner_session=$5 AND state='pending' AND lease_expires_at>clock_timestamp()`, usageLeaseArgs(a)...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return joinUsageStale
	}
	return nil
}

// The candidate lock is exclusive and fail-fast before Workspace. A concurrent
// dispatcher holding candidate shared locks cannot form a Workspace inversion;
// concurrent usage readers cannot both upgrade shared candidate locks.
func (h *OwnerAuthHandler) lockRotationUsageGate(ctx context.Context, workspace uuid.UUID, keys []writerfence.Key, candidate uuid.UUID) (*removalGate, error) {
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	gate := &removalGate{conn: conn, workspace: workspace}
	ordered := append([]writerfence.Key(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool {
		return string(ordered[i].Kind)+ordered[i].ID.String() < string(ordered[j].Kind)+ordered[j].ID.String()
	})
	for _, key := range ordered {
		scope := string(key.Kind) + "/" + key.ID.String()
		if key.Kind == writerfence.TargetAccount && key.ID == candidate {
			var acquired bool
			err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('tsw.rotation.action.'||$1,0))`, scope).Scan(&acquired)
			if err == nil && !acquired {
				err = joinUsageBusy
			}
		} else {
			_, err = conn.Exec(ctx, `SELECT pg_advisory_lock_shared(hashtextextended('tsw.rotation.action.'||$1,0))`, scope)
		}
		if err != nil {
			gate.close()
			return nil, err
		}
		gate.keys = append(gate.keys, key)
	}
	if err = gate.lockWorkspace(ctx); err != nil {
		gate.close()
		return nil, err
	}
	return gate, nil
}
