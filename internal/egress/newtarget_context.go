package egress

import "context"

type targetContextKey struct{}
type borrowedLeaseContextKey struct{}

type targetContextValue struct{ id string }
type borrowedLeaseValue struct {
	target string
	lease  *Lease
}

func WithTarget(ctx context.Context, targetID string) context.Context {
	return context.WithValue(ctx, targetContextKey{}, targetContextValue{id: targetID})
}

func Target(ctx context.Context) string {
	value, ok := ctx.Value(targetContextKey{}).(targetContextValue)
	if !ok {
		return ""
	}
	return value.id
}

func WithBorrowedLease(ctx context.Context, targetID string, lease *Lease) context.Context {
	ctx = WithTarget(ctx, targetID)
	return context.WithValue(ctx, borrowedLeaseContextKey{}, borrowedLeaseValue{target: targetID, lease: lease})
}

func BorrowedLease(ctx context.Context, targetID string) (*Lease, bool) {
	value, ok := ctx.Value(borrowedLeaseContextKey{}).(borrowedLeaseValue)
	return value.lease, ok && value.target == targetID && value.lease != nil
}
