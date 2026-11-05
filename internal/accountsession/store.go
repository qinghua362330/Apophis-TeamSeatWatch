// Package accountsession owns acquisition of a target's encrypted Personal
// session. Owner actions and delivery workers use the same reservation fences.
package accountsession

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/browserenv"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
)

var ErrDisabled = errors.New("account disabled")
var ErrChanged = errors.New("account session reservation superseded")

// RouteProvider binds all browser and API traffic for a target account to the
// same measured egress lease. It is structural to keep accountsession
// independent from the route implementation.
type RouteProvider interface {
	Prepare(context.Context, uuid.UUID) (context.Context, bool, func(), error)
	Validate(context.Context, uuid.UUID) error
	Published(context.Context, pgx.Tx, uuid.UUID) error
}

// Environment resolves identity for the existing reclaim reservation, whose
// full-login adapter owns authentication. It uses the same active-account lock
// and lazy assignment as Ensure, without changing any encrypted generation.
func (s Store) Environment(ctx context.Context, id uuid.UUID) (browserenv.Environment, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return browserenv.Environment{}, err
	}
	defer tx.Rollback(ctx)
	var active bool
	if err = tx.QueryRow(ctx, `SELECT status='active' FROM tsw_target_accounts WHERE id=$1 FOR UPDATE`, id).Scan(&active); err != nil {
		return browserenv.Environment{}, err
	}
	if !active {
		return browserenv.Environment{}, ErrDisabled
	}
	e, err := browserenv.Ensure(ctx, tx, "target", id)
	if err != nil {
		return browserenv.Environment{}, err
	}
	return e, tx.Commit(ctx)
}

// InvalidATSQL is generation-safe because Personal probe publication holds the
// generation locks and a replacement advances verified_at atomically.
const InvalidATSQL = `EXISTS (SELECT 1 FROM tsw_personal_probe_items item WHERE item.target_account_id=target.id AND item.outcome='credential_invalid' AND item.http_status=401 AND item.finished_at>=session.verified_at)`

type Store struct {
	Pool    *pgxpool.Pool
	KeyRing auth.KeyRing
	Routes  RouteProvider
}
type Result struct {
	Environment browserenv.Environment
	Status      string
	Session     platform.PersonalSession
	Failure     *platform.PersonalRefreshFailure
}
type reservation struct {
	material          platform.MotherMaterial
	revision, attempt int64
	complete          bool
	saved             platform.PersonalSession
	existing          string
}

// Ensure publishes only a successful replacement; failures retain old ciphertext.
// fresh is used only after a browser authorization explicitly rejects its session.
// published runs in the successful publication transaction (e.g. Owner rotation).
func (s Store) Ensure(ctx context.Context, id uuid.UUID, adapter platform.PersonalSessionRefresher, fresh bool, published func(pgx.Tx) error) (Result, error) {
	routeCtx, routeFresh, release, err := s.prepareRoute(ctx, id)
	if err != nil {
		return Result{}, err
	}
	defer release()
	fresh = fresh || routeFresh
	r, err := s.reserve(routeCtx, id, fresh)
	if err != nil {
		return Result{}, err
	}
	if r.existing != "" {
		return Result{Environment: r.material.Environment, Status: r.existing, Session: r.saved}, nil
	}
	stopHeartbeat := KeepVerifying(ctx, s.Pool, "target", id, r.revision, r.attempt)
	defer stopHeartbeat()
	result := platform.PersonalRefreshResult{Status: "missing_credentials"}
	if r.complete {
		if adapter == nil {
			adapter = platform.UnavailablePersonalRefresh{}
		}
		if fresh {
			result, err = adapter.RefreshPersonal(routeCtx, r.material)
		} else {
			result, err = platform.AcquirePersonal(routeCtx, adapter, r.material, r.saved)
		}
		switch {
		case errors.Is(err, platform.ErrPersonalRefreshUnavailable):
			result = platform.PersonalRefreshResult{Status: "unavailable"}
		case err != nil || !platform.ValidatePersonalRefresh(result, time.Now()):
			result = platform.PersonalRefreshResult{Status: "refresh_failed"}
		}
	}
	if result.Status == "ready" && s.Routes != nil {
		if err = s.Routes.Validate(routeCtx, id); err != nil {
			return Result{}, err
		}
	}
	publishCtx, stopPublish := context.WithTimeout(context.WithoutCancel(routeCtx), 5*time.Second)
	defer stopPublish()
	if err = s.publish(publishCtx, id, r, result, func(tx pgx.Tx) error {
		if s.Routes != nil {
			if err := s.Routes.Published(publishCtx, tx, id); err != nil {
				return err
			}
		}
		if published != nil {
			return published(tx)
		}
		return nil
	}); err != nil {
		return Result{}, err
	}
	return Result{Environment: r.material.Environment, Status: result.Status, Session: result.Session, Failure: result.Failure}, nil
}

func (s Store) prepareRoute(ctx context.Context, id uuid.UUID) (context.Context, bool, func(), error) {
	if s.Routes == nil {
		return ctx, false, func() {}, nil
	}
	routeCtx, fresh, release, err := s.Routes.Prepare(ctx, id)
	if release == nil {
		release = func() {}
	}
	return routeCtx, fresh, release, err
}

func lockOwnerAction(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.owner/'||id::text,0)) FROM tsw_owners WHERE singleton`)
	return err
}

func (s Store) reserve(ctx context.Context, id uuid.UUID, fresh bool) (reservation, error) {
	var r reservation
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	var password, totp []byte
	var active bool
	err = tx.QueryRow(ctx, `SELECT target.identifier,credential.password_secret,credential.totp_secret,credential.secret_revision,target.status='active',credential.material_status='complete' AND credential.materials_sealed FROM tsw_target_accounts target JOIN tsw_target_credentials credential ON credential.target_account_id=target.id WHERE target.id=$1 FOR UPDATE OF target,credential`, id).Scan(&r.material.LoginIdentifier, &password, &totp, &r.revision, &active, &r.complete)
	if err != nil {
		return r, err
	}
	if !active {
		return r, ErrDisabled
	}
	r.material.Environment, err = browserenv.Ensure(ctx, tx, "target", id)
	if err != nil {
		return r, err
	}
	var status *string
	var checked *time.Time
	var version *int16
	var nonce, sealed []byte
	var expires *time.Time
	var current, invalid bool
	err = tx.QueryRow(ctx, `SELECT access.status,access.checked_at,session.key_version,session.nonce,session.sealed_session,session.expires_at,COALESCE(session.attempt=access.attempt,false),`+InvalidATSQL+` FROM tsw_target_accounts target LEFT JOIN tsw_target_personal_access access ON access.target_account_id=target.id AND access.secret_revision=$2 LEFT JOIN tsw_target_personal_sessions session ON session.target_account_id=target.id AND session.secret_revision=$2 WHERE target.id=$1`, id, r.revision).Scan(&status, &checked, &version, &nonce, &sealed, &expires, &current, &invalid)
	if err != nil {
		return r, err
	}
	if status != nil && *status == "verifying" && checked != nil && checked.After(time.Now().Add(-time.Minute)) {
		r.existing = "verifying"
		return r, tx.Commit(ctx)
	}
	if version != nil && expires != nil {
		saved, openErr := Open("target", s.KeyRing, id, r.revision, uint16(*version), nonce, sealed)
		if openErr == nil && saved.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(expires.UTC()) {
			r.saved = saved
		}
	}
	if !fresh && !invalid && current && status != nil && *status == "ready" && platform.ValidatePersonalRefresh(platform.PersonalRefreshResult{Status: "ready", Session: r.saved}, time.Now()) {
		r.existing = "ready"
		return r, tx.Commit(ctx)
	}
	if invalid || !current || status == nil || *status != "ready" {
		r.saved.ExpiresAt = time.Time{}
	}
	if r.complete {
		r.material.Password, err = targetdomain.OpenMaterial(password, s.KeyRing)
		if err != nil {
			return r, err
		}
		r.material.TOTPSecret, err = targetdomain.OpenMaterial(totp, s.KeyRing)
		if err != nil {
			return r, err
		}
		r.complete = r.material.Password != "" && targetdomain.CompleteTOTP(r.material.TOTPSecret)
	}
	if err = lockOwnerAction(ctx, tx); err != nil {
		return r, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO tsw_target_personal_access(target_account_id,secret_revision,status) VALUES($1,$2,'verifying') ON CONFLICT(target_account_id) DO UPDATE SET secret_revision=EXCLUDED.secret_revision,attempt=tsw_target_personal_access.attempt+1,status='verifying',checked_at=now() RETURNING attempt`, id, r.revision).Scan(&r.attempt)
	if err != nil {
		return r, err
	}
	return r, tx.Commit(ctx)
}

func (s Store) publish(ctx context.Context, id uuid.UUID, r reservation, result platform.PersonalRefreshResult, published func(pgx.Tx) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var revision, attempt int64
	var active bool
	err = tx.QueryRow(ctx, `SELECT credential.secret_revision,access.attempt,target.status='active' FROM tsw_target_accounts target JOIN tsw_target_credentials credential ON credential.target_account_id=target.id JOIN tsw_target_personal_access access ON access.target_account_id=target.id WHERE target.id=$1 FOR UPDATE OF target,credential,access`, id).Scan(&revision, &attempt, &active)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!active || revision != r.revision || attempt != r.attempt)) {
		return ErrChanged
	}
	if err != nil {
		return err
	}
	if err = lockOwnerAction(ctx, tx); err != nil {
		return err
	}
	if result.Status == "ready" {
		version, nonce, sealed, sealErr := Seal("target", s.KeyRing, id, revision, result.Session)
		if sealErr != nil {
			return sealErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO tsw_target_personal_sessions(target_account_id,secret_revision,attempt,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(target_account_id) DO UPDATE SET secret_revision=EXCLUDED.secret_revision,attempt=EXCLUDED.attempt,generation=EXCLUDED.generation,key_version=EXCLUDED.key_version,nonce=EXCLUDED.nonce,sealed_session=EXCLUDED.sealed_session,expires_at=EXCLUDED.expires_at,verified_at=now()`, id, revision, attempt, uuid.New(), version, nonce, sealed, result.Session.ExpiresAt)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_target_personal_access SET status=$2,checked_at=now() WHERE target_account_id=$1`, id, result.Status)
	if err != nil {
		return err
	}
	if result.Status == "ready" && published != nil {
		if err = published(tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RejectAT retains browser cookies for renewal, but stops a confirmed rejected
// generation being used again, including after probe-history retention cleanup.
// The caller holds target, credential, access and session rows in that order.
func RejectAT(ctx context.Context, tx pgx.Tx, id string, revision int64, generation string) error {
	if err := lockOwnerAction(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE tsw_target_personal_access access SET status='refresh_failed',checked_at=now() FROM tsw_target_personal_sessions session WHERE access.target_account_id=$1 AND access.secret_revision=$2 AND session.target_account_id=access.target_account_id AND session.secret_revision=access.secret_revision AND session.attempt=access.attempt AND session.generation=$3::uuid AND access.status='ready'`, id, revision, generation)
	return err
}
