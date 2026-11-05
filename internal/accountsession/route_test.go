package accountsession

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"testing"
)

type routeProviderStub struct {
	prepared  bool
	released  bool
	validated bool
	published bool
}

func (r *routeProviderStub) Prepare(ctx context.Context, _ uuid.UUID) (context.Context, bool, func(), error) {
	r.prepared = true
	return context.WithValue(ctx, routeProviderStub{}, "borrowed"), true, func() { r.released = true }, nil
}
func (r *routeProviderStub) Validate(context.Context, uuid.UUID) error {
	r.validated = true
	return nil
}
func (r *routeProviderStub) Published(context.Context, pgx.Tx, uuid.UUID) error {
	r.published = true
	return nil
}

func TestPrepareRouteBindsBeforeReservationAndReleases(t *testing.T) {
	stub := &routeProviderStub{}
	store := Store{Routes: stub}
	ctx := context.Background()
	got, fresh, release, err := store.prepareRoute(ctx, uuid.New())
	if err != nil || !fresh || !stub.prepared {
		t.Fatalf("prepare route: ctx=%v fresh=%v prepared=%v err=%v", got, fresh, stub.prepared, err)
	}
	if got.Value(routeProviderStub{}) != "borrowed" {
		t.Fatal("route provider context was not propagated")
	}
	release()
	if !stub.released {
		t.Fatal("route lease was not released")
	}
}

func TestRouteProviderContractExposesPublicationFenceHooks(t *testing.T) {
	var _ RouteProvider = (*routeProviderStub)(nil)
	stub := &routeProviderStub{}
	if err := stub.Validate(context.Background(), uuid.New()); err != nil || !stub.validated {
		t.Fatal("validate hook was not callable")
	}
}
