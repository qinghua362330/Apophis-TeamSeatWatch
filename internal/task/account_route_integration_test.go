package task

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
)

type targetRouteStub struct {
	enabled bool
	called  bool
}

func (s *targetRouteStub) Enabled(context.Context) (bool, error) { return s.enabled, nil }
func (s *targetRouteStub) Bind(context.Context, uuid.UUID, *egress.Lease) (*egress.Lease, error) {
	s.called = true
	return nil, errors.New("binding rejected")
}

func TestAccountRouteBindingFailureStopsBeforePlatform(t *testing.T) {
	stub := &targetRouteStub{enabled: true}
	w := &Worker{TargetRoutes: stub}
	_, _, err := w.bindAccountRoute(context.Background(), Task{TaskType: "oauth_generate", TargetAccountID: uuid.NewString()}, nil)
	if err == nil || !stub.called {
		t.Fatalf("expected binding failure, called=%v err=%v", stub.called, err)
	}
}

func TestAccountRoutesDoNotTouchRemovalOrWorkspaceTasks(t *testing.T) {
	stub := &targetRouteStub{enabled: true}
	w := &Worker{TargetRoutes: stub}
	for _, taskType := range []string{"remove", "remove_reconcile", "workspace_fact_read"} {
		_, _, err := w.bindAccountRoute(context.Background(), Task{TaskType: taskType, TargetAccountID: uuid.NewString()}, nil)
		if err != nil {
			t.Fatalf("task %s unexpectedly bound: %v", taskType, err)
		}
	}
	if stub.called {
		t.Fatal("non-account task invoked account route binding")
	}
}
