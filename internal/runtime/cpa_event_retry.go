package runtime

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// retryUnmappedCPAEvent binds a recent authenticated event after refreshed
// workspace evidence becomes available. A receipt is never rewritten or replayed.
func (h *OwnerAuthHandler) retryUnmappedCPAEvent(ctx context.Context) (bool, error) {
	if h.cpaCredentials == nil {
		return false, nil
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	var email string
	err = tx.QueryRow(ctx, `SELECT event_id,normalized_email FROM tsw_cpa_degradation_events
 WHERE mapping_status IN ('received','not_found') AND rotation_case_id IS NULL
 AND observed_at>now()-interval '30 minutes' AND updated_at<now()-interval '15 seconds'
 ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, tx.Commit(ctx)
	}
	if err != nil {
		return false, err
	}
	if err = h.mapCPAEventTx(ctx, tx, id, email); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
