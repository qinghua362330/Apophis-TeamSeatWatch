package runtime

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/accountsession"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

func (h *OwnerAuthHandler) GetTargetPersonalAccess(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	response, err := h.targetPersonalAccess(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "target_not_found", "Not Found", "Target account was not found", 0)
		return
	}
	if err != nil {
		h.targetFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *OwnerAuthHandler) RefreshTargetPersonalAccess(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, _ ownerapi.RefreshTargetPersonalAccessParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	ctx, stopTask := h.personalRefreshContext(r.Context())
	defer stopTask()
	r = r.WithContext(ctx)
	result, err := (accountsession.Store{Pool: h.pool, KeyRing: h.keyRing, Routes: h.accountRoutes()}).Ensure(ctx, id, h.personalRefresh, false, func(tx pgx.Tx) error {
		return h.lockCurrentOwnerSession(ctx, tx, owner)
	})
	switch {
	case errors.Is(err, errPersonalOwnerSession):
		writeProblem(w, r, 401, "session_expired", "Session Expired", "The Owner session changed before account publication", 0)
		return
	case errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, r, 404, "target_not_found", "Not Found", "Target account was not found", 0)
		return
	case errors.Is(err, accountsession.ErrDisabled):
		writeProblem(w, r, 409, "target_disabled", "Account Disabled", "Target account is disabled", 0)
		return
	case errors.Is(err, accountsession.ErrChanged):
		writeProblem(w, r, 409, "target_access_changed", "Conflict", "Target access changed; refresh again", 0)
		return
	case err != nil:
		h.targetFailure(w, r, err)
		return
	}
	response, err := h.targetPersonalAccess(r.Context(), id)
	if err != nil {
		h.targetFailure(w, r, err)
		return
	}
	if result.Failure != nil && (response.Status == ownerapi.TargetPersonalAccessStatusRefreshFailed || response.Status == ownerapi.TargetPersonalAccessStatusSessionExpired) {
		response.Failure = &ownerapi.PersonalLoginFailure{Code: ownerapi.PersonalLoginFailureCode(result.Failure.Code)}
		if result.Failure.HTTPStatus != 0 {
			response.Failure.HttpStatus = &result.Failure.HTTPStatus
		}
	}
	writeJSON(w, http.StatusOK, response)
}

const targetPersonalAccessProjectionSQL = `target.id,CASE WHEN (access.status='refresh_failed' AND session.target_account_id IS NOT NULL) OR access.status='ready' AND (session.target_account_id IS NULL OR session.expires_at<=now()+interval '1 minute' OR ` + accountsession.InvalidATSQL + `) THEN 'session_expired' WHEN access.status='verifying' AND access.checked_at<now()-interval '1 minute' THEN 'refresh_failed' ELSE access.status END,access.checked_at,session.expires_at,credential.secret_revision,session.key_version,session.nonce,session.sealed_session`

const targetPersonalAccessFromSQL = ` FROM tsw_target_accounts target JOIN tsw_target_credentials credential ON credential.target_account_id=target.id LEFT JOIN tsw_target_personal_access access ON access.target_account_id=target.id AND access.secret_revision=credential.secret_revision LEFT JOIN tsw_target_personal_sessions session ON session.target_account_id=target.id AND session.secret_revision=credential.secret_revision AND session.attempt=access.attempt `

func (h *OwnerAuthHandler) scanTargetPersonalAccess(scanner interface{ Scan(...any) error }) (ownerapi.TargetPersonalAccess, error) {
	response := ownerapi.TargetPersonalAccess{Status: ownerapi.TargetPersonalAccessStatusNotVerified}
	var status *string
	var checked, expires *time.Time
	var revision int64
	var version *int16
	var nonce, sealed []byte
	err := scanner.Scan(&response.TargetAccountId, &status, &checked, &expires, &revision, &version, &nonce, &sealed)
	if err != nil {
		return response, err
	}
	if status != nil {
		if *status == "ready" {
			if version == nil || expires == nil {
				*status = "refresh_failed"
			} else {
				session, openErr := openSessionFor("target", h.keyRing, response.TargetAccountId, revision, uint16(*version), nonce, sealed)
				if openErr != nil || !session.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(expires.UTC()) || !platform.ValidatePersonalRefresh(platform.PersonalRefreshResult{Status: "ready", Session: session}, time.Now()) {
					*status = "refresh_failed"
				}
			}
		}
		response.Status = ownerapi.TargetPersonalAccessStatus(*status)
		response.CheckedAt = checked
		if *status == "ready" {
			response.ExpiresAt = expires
		}
	}
	return response, nil
}

func (h *OwnerAuthHandler) targetPersonalAccess(ctx context.Context, id uuid.UUID) (ownerapi.TargetPersonalAccess, error) {
	return h.scanTargetPersonalAccess(h.pool.QueryRow(ctx, `SELECT `+targetPersonalAccessProjectionSQL+targetPersonalAccessFromSQL+` WHERE target.id=$1 AND target.status='active'`, id))
}

func (h *OwnerAuthHandler) loadPagePersonalAccess(ctx context.Context, accounts []ownerapi.TargetAccount) error {
	ids := make([]uuid.UUID, 0, len(accounts))
	indexes := make(map[uuid.UUID]int, len(accounts))
	for i, account := range accounts {
		if account.Status == ownerapi.TargetAccountStatusActive {
			ids = append(ids, account.Id)
			indexes[account.Id] = i
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := h.pool.Query(ctx, `SELECT `+targetPersonalAccessProjectionSQL+targetPersonalAccessFromSQL+` WHERE target.id=ANY($1::uuid[]) AND target.status='active'`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		access, err := h.scanTargetPersonalAccess(rows)
		if err != nil {
			return err
		}
		accounts[indexes[access.TargetAccountId]].PersonalAccess = &access
	}
	return rows.Err()
}
