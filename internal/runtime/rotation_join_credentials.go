package runtime

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/browserenv"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

// saveRotationJoinCredentials consumes only the original intent. Repair verifies
// the original facts and sealed checkpoints; an uncheckpointed marked action is
// review-required, never another login/grant/exchange. No join dispatch, slot,
// usage, delivery, batch authorization or source epoch writes occur here.
func (h *OwnerAuthHandler) saveRotationJoinCredentials(ctx context.Context, owner ownerContext, preview, slot, worker uuid.UUID, duration time.Duration, repair bool) error {
	if worker == uuid.Nil || duration <= 0 || h.rotationJoinEgress == nil || h.rotationJoinAdapters == nil || h.rotationCredentialAdapters == nil {
		return platform.ErrRotationCredentialsUnavailable
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
	// Queue before claiming any bounded credential attempt or database gate.
	// Owner/candidate/workspace authority is rechecked after admission below.
	ctx, releaseTargetRoute, routeBindErr := h.manualTargetRoute(ctx, i.candidateAccountID)
	if routeBindErr != nil {
		return routeBindErr
	}
	defer releaseTargetRoute()
	route, err := h.rotationJoinEgress(ctx)
	if route != nil {
		defer route.Release()
	}
	if err != nil || route == nil || route.Client() == nil || route.Client().Transport == nil || route.Client().Timeout <= 0 {
		return platform.ErrRotationCredentialsUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, min(duration, 45*time.Second))
	defer cancel()
	gate, err := h.lockRemovalGate(bounded, i.workspaceID, keys)
	if err != nil {
		return err
	}
	defer gate.close()
	var pinned joinAdmission
	var attempt joinCredentialAttempt
	// Every local mutation takes a short epoch transaction; none spans I/O.
	local := func(fn func(pgx.Tx, joinAdmission) error) error {
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
		current, err := h.joinAdmissionLocal(bounded, tx, auth, i, owner, versions)
		if err != nil {
			return err
		}
		if pinned.platformID != "" && !sameJoinAdmission(pinned, current) {
			return joinCredentialsStale
		}
		if err = requireJoinPersonalBinding(bounded, tx, i, current, attempt.subject); err != nil {
			return err
		}
		if attempt.binding.attempt != uuid.Nil {
			if err = requireCredentialLease(bounded, tx, attempt); err != nil {
				return err
			}
		}
		if err = fn(tx, current); err != nil {
			return err
		}
		return tx.Commit(bounded)
	}
	err = local(func(tx pgx.Tx, p joinAdmission) error {
		pinned = p
		var claimErr error
		attempt, claimErr = h.claimJoinCredentialAttempt(bounded, tx, i, p, owner, worker, duration, repair)
		return claimErr
	})
	if err != nil {
		return err
	}
	// Release only this exact live lease. Unknown remote effects and the original
	// attempt/checkpoints remain durable, even if cleanup itself cannot write.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = gate.conn.Exec(cleanup, `UPDATE public.tsw_rotation_join_credential_attempts SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,owner_session=NULL WHERE slot_id=$1 AND lease_owner=$2 AND lease_token=$3 AND lease_epoch=$4 AND owner_session=$5 AND lease_expires_at>clock_timestamp()`, credentialLeaseArgs(attempt)...)
	}()
	boundedLease, leaseCancel := context.WithDeadline(bounded, attempt.lease.expires)
	defer leaseCancel()
	bounded = boundedLease
	base := route.Client()
	reads := h.rotationJoinAdapters(func(context.Context) (*http.Client, func(), error) { return base, nil, nil })
	if reads.identity == nil || reads.members == nil || reads.discovery == nil {
		return platform.ErrRotationCredentialsUnavailable
	}
	var proofDeadline time.Time
	remoteProof := func() error {
		if err := gate.unlockWorkspace(bounded); err != nil {
			return err
		}
		if err := checkJoinReadGate(bounded, gate); err != nil {
			return err
		}
		if !platform.ValidateRotationCandidatePersonal(pinned.candidate, attempt.subject, time.Now()) {
			return joinCredentialsReview
		}
		role, err := reads.discovery.Discover(bounded, pinned.mother)
		roleObserved := time.Now().UTC()
		if err != nil || !platform.ValidateDiscovery(role) || role.Status != "discovered" {
			return joinCredentialsReview
		}
		isOwner := false
		for _, w := range role.Workspaces {
			if w.PlatformID == pinned.platformID && w.Access == "readable" && w.Role == "owner" {
				isOwner = true
			}
		}
		if !isOwner {
			return joinCredentialsReview
		}
		if err = checkJoinReadGate(bounded, gate); err != nil {
			return err
		}
		identity, err := reads.identity.ConfirmPersonalIdentity(bounded, pinned.candidate)
		now := time.Now().UTC()
		if err != nil || identity.Identifier != i.candidateIdentifier || identity.SubjectID != attempt.subject || identity.ObservedAt.After(now) || identity.ObservedAt.Before(now.Add(-30*time.Second)) || !identity.ExpiresAt.After(now.Add(time.Minute)) || identity.ExpiresAt.After(pinned.candidate.ExpiresAt) {
			return joinCredentialsReview
		}
		if err = checkJoinReadGate(bounded, gate); err != nil {
			return err
		}
		result, readErr := reads.members.ReadMembers(bounded, pinned.candidate, pinned.platformID)
		observation := classifyRotationMembership(result, readErr, i.candidateIdentifier, i.seatType)
		now = time.Now().UTC()
		if observation.result != "confirmed" || observation.memberID != attempt.member || result.ObservedAt.After(now) || result.ObservedAt.Before(now.Add(-30*time.Second)) {
			return joinCredentialsReview
		}
		for _, m := range result.Members {
			if strings.ToLower(strings.TrimSpace(m.Identifier)) == i.candidateIdentifier && m.PlatformAccountUserID != "" && m.PlatformAccountUserID != attempt.subject {
				return joinCredentialsReview
			}
		}
		proofDeadline = minTime(roleObserved.Add(30*time.Second), minTime(identity.ObservedAt.Add(30*time.Second), result.ObservedAt.Add(30*time.Second)))
		if err = route.Remeasure(bounded); err != nil {
			return platform.ErrRotationCredentialsUnavailable
		}
		return local(func(tx pgx.Tx, _ joinAdmission) error {
			var latestOK bool
			err := tx.QueryRow(bounded, `SELECT result='confirmed' AND platform_member_id=$2 FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1 ORDER BY reconciliation_attempt DESC LIMIT 1`, slot, attempt.member).Scan(&latestOK)
			if err != nil {
				return err
			}
			if !latestOK {
				return joinCredentialsReview
			}
			return nil
		})
	}
	// Before each credential-side effect, the fixed route and local authority are
	// rechecked. Read-only authentication GETs release Workspace for stop/revoke.
	actionAdmission := func() error {
		if err := route.Remeasure(bounded); err != nil {
			return platform.ErrRotationCredentialsUnavailable
		}
		return local(func(tx pgx.Tx, _ joinAdmission) error {
			var fresh bool
			err := tx.QueryRow(bounded, `SELECT $1::timestamptz>clock_timestamp()`, proofDeadline).Scan(&fresh)
			if err != nil {
				return err
			}
			if !fresh {
				return joinCredentialsStale
			}
			return nil
		})
	}
	client := *base
	client.Transport = joinCredentialTransport{next: base.Transport, before: func(r *http.Request) error {
		if credentialReadOnlyRequest(r) {
			if err := gate.unlockWorkspace(bounded); err != nil {
				return err
			}
			if err := checkJoinReadGate(bounded, gate); err != nil {
				return err
			}
			return requireCredentialLease(bounded, gate.conn, attempt)
		}
		return actionAdmission()
	}}
	adapter := h.rotationCredentialAdapters(func(context.Context) (*http.Client, func(), error) { return &client, nil, nil })
	if adapter == nil {
		return platform.ErrRotationCredentialsUnavailable
	}
	if err = remoteProof(); err != nil {
		return err
	}
	// If already published, still verify exactly the same sealed pair; no grants.
	var published bool
	if err = gate.conn.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_generations WHERE attempt_id=$1)`, attempt.binding.attempt).Scan(&published); err != nil {
		return err
	}
	if published {
		_, _, err = h.validateSavedJoinCredentials(bounded, gate.conn, attempt)
		return err
	}
	review := func(stage string) error {
		_ = local(func(tx pgx.Tx, _ joinAdmission) error {
			var exists bool
			err := tx.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_events WHERE attempt_id=$1 AND stage=$2 AND event='review_required')`, attempt.binding.attempt, stage).Scan(&exists)
			if err != nil || exists {
				return err
			}
			return appendCredentialEvent(bounded, tx, attempt, stage, "review_required", time.Now().UTC())
		})
		return joinCredentialsReview
	}
	for _, kind := range []string{"web", "oauth"} {
		var exists, started bool
		if err = gate.conn.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_components WHERE attempt_id=$1 AND kind=$2),EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_events WHERE attempt_id=$1 AND stage=$2 AND event='started')`, attempt.binding.attempt, kind).Scan(&exists, &started); err != nil {
			return err
		}
		if exists {
			if kind == "web" {
				var web platform.WorkspaceAccess
				c, readErr := h.readCredentialComponent(bounded, gate.conn, attempt, kind, &web)
				if readErr != nil || !platform.ValidateRotationCandidateWorkspace(web, pinned.platformID, attempt.subject, time.Now()) || !web.ExpiresAt.Equal(c.expires) {
					return review(kind)
				}
			} else {
				_, _, readErr := h.validateSavedJoinCredentials(bounded, gate.conn, attempt)
				if readErr != nil {
					return review(kind)
				}
			}
			continue
		}
		if started {
			return review(kind)
		}
		if err = remoteProof(); err != nil {
			return err
		}
		if err = actionAdmission(); err != nil {
			return err
		}
		if err = local(func(tx pgx.Tx, _ joinAdmission) error {
			return appendCredentialEvent(bounded, tx, attempt, kind, "started", time.Now().UTC())
		}); err != nil {
			return err
		}
		if err = actionAdmission(); err != nil {
			return err
		}
		var value any
		var expires time.Time
		observed := time.Now().UTC().Truncate(time.Microsecond)
		if kind == "web" {
			web, actionErr := adapter.ExchangeCandidateWorkspace(bounded, pinned.candidate, pinned.platformID, attempt.subject)
			if actionErr != nil || !platform.ValidateRotationCandidateWorkspace(web, pinned.platformID, attempt.subject, time.Now()) {
				return review(kind)
			}
			value = web
			expires = web.ExpiresAt
		} else {
			var request platform.DeliveryCredentialRequest
			if err = local(func(tx pgx.Tx, _ joinAdmission) error {
				var environmentErr error
				request.Environment, environmentErr = browserenv.Ensure(bounded, tx, "target", i.candidateAccountID)
				if environmentErr != nil {
					return environmentErr
				}
				var pw, totp, recovery []byte
				err := tx.QueryRow(bounded, `SELECT password_secret,totp_secret,recovery_secret FROM public.tsw_target_credentials WHERE target_account_id=$1 AND secret_revision=$2 AND materials_sealed AND material_status='complete'`, i.candidateAccountID, attempt.binding.revision).Scan(&pw, &totp, &recovery)
				if err != nil {
					return err
				}
				request.Identifier = i.candidateIdentifier
				request.Workspace = pinned.platformID
				request.Password, err = targetdomain.OpenMaterial(pw, h.keyRing)
				if err != nil {
					return err
				}
				request.TOTPSecret, err = targetdomain.OpenMaterial(totp, h.keyRing)
				if err != nil {
					return err
				}
				request.Recovery, err = targetdomain.OpenMaterial(recovery, h.keyRing)
				return err
			}); err != nil {
				return err
			}
			request.PersonalSession = &pinned.candidate
			oauth, actionErr := adapter.CreateCandidateOAuth(bounded, request, attempt.subject)
			request = platform.DeliveryCredentialRequest{}
			observed = time.Now().UTC().Truncate(time.Microsecond)
			if actionErr != nil {
				return review(kind)
			}
			expires, err = platform.ValidateRotationCandidateOAuth(oauth, pinned.platformID, attempt.subject, observed)
			if err != nil {
				return review(kind)
			}
			value = oauth
		}
		if err = route.Remeasure(bounded); err != nil {
			return platform.ErrRotationCredentialsUnavailable
		}
		if err = local(func(tx pgx.Tx, _ joinAdmission) error {
			return h.appendCredentialComponent(bounded, tx, attempt, kind, value, observed, expires)
		}); err != nil {
			return err
		}
	}
	// Complete durable components alone still do not authorize publication.
	if err = remoteProof(); err != nil {
		return err
	}
	return local(func(tx pgx.Tx, _ joinAdmission) error {
		web, oauth, err := h.validateSavedJoinCredentials(bounded, tx, attempt)
		if err != nil {
			return err
		}
		var fresh bool
		if err = tx.QueryRow(bounded, `SELECT $1::timestamptz>clock_timestamp()`, proofDeadline).Scan(&fresh); err != nil {
			return err
		}
		if !fresh {
			return joinCredentialsStale
		}
		return publishJoinCredentials(bounded, tx, attempt, web, oauth, time.Now().UTC())
	})
}

type joinCredentialTransport struct {
	next   http.RoundTripper
	before func(*http.Request) error
}

func (g joinCredentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := g.before(r); err != nil {
		return nil, err
	}
	return g.next.RoundTrip(r)
}
func credentialReadOnlyRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL == nil {
		return false
	}
	return r.URL.Host == "chatgpt.com" && (r.URL.Path == "/api/auth/providers" || r.URL.Path == "/api/auth/csrf" || r.URL.Path == "/api/auth/session" && r.URL.RawQuery == "")
}
