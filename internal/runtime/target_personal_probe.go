package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/task"
)

// SavedTargetPersonalProbe is used only by the Personal queue. Its input is a
// canonical target UUID, never a caller-provided token, password or endpoint.
type SavedTargetPersonalProbe struct {
	Pool    *pgxpool.Pool
	KeyRing auth.KeyRing
	Routes  accountsession.RouteProvider
	Adapter platform.PersonalUsageProbe
}

func (p SavedTargetPersonalProbe) ProbePersonal(ctx context.Context, targetID string) (platform.PersonalProbeEvidence, error) {
	id, err := uuid.Parse(targetID)
	if err != nil || p.Pool == nil || p.KeyRing == nil {
		return platform.PersonalProbeEvidence{}, task.ErrPersonalCredentialMissing
	}
	if p.Routes != nil {
		routed, fresh, release, routeErr := p.Routes.Prepare(ctx, id)
		if routeErr != nil {
			return platform.PersonalProbeEvidence{}, routeErr
		}
		defer release()
		ctx = routed
		if fresh {
			return platform.PersonalProbeEvidence{}, task.ErrPersonalCredentialMissing
		}
	}
	var revision int64
	var generation uuid.UUID
	var version int16
	var nonce, sealed []byte
	var expires time.Time
	err = p.Pool.QueryRow(ctx, `SELECT credential.secret_revision,session.generation,session.key_version,session.nonce,session.sealed_session,session.expires_at FROM tsw_target_accounts target JOIN tsw_target_credentials credential ON credential.target_account_id=target.id AND credential.material_status='complete' AND credential.materials_sealed JOIN tsw_target_personal_access access ON access.target_account_id=target.id AND access.secret_revision=credential.secret_revision AND access.status='ready' JOIN tsw_target_personal_sessions session ON session.target_account_id=target.id AND session.secret_revision=credential.secret_revision AND session.attempt=access.attempt AND session.expires_at>now()+interval '1 minute' WHERE target.id=$1 AND target.status='active' AND NOT (`+accountsession.InvalidATSQL+`)`, id).Scan(&revision, &generation, &version, &nonce, &sealed, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return platform.PersonalProbeEvidence{}, task.ErrPersonalCredentialMissing
	}
	if err != nil {
		return platform.PersonalProbeEvidence{}, err
	}
	session, err := openSessionFor("target", p.KeyRing, id, revision, uint16(version), nonce, sealed)
	if err != nil || !session.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(expires.UTC()) || !platform.ValidatePersonalRefresh(platform.PersonalRefreshResult{Status: "ready", Session: session}, time.Now()) {
		// Corrupt or expired ciphertext must never be used or silently retried as plaintext.
		return platform.PersonalProbeEvidence{}, task.ErrPersonalCredentialMissing
	}
	evidence, err := p.Adapter.Probe(ctx, session)
	if p.Routes != nil {
		if routeErr := p.Routes.Validate(ctx, id); routeErr != nil {
			return platform.PersonalProbeEvidence{}, routeErr
		}
	}
	evidence.SessionGeneration, evidence.SessionRevision = generation.String(), revision
	return evidence, err
}
