package egress

import (
	"context"
	"testing"
)

func TestTargetAndBorrowedLeaseContextAreScoped(t *testing.T) {
	ctx := context.Background()
	if Target(ctx) != "" {
		t.Fatal("target context leaked")
	}
	lease := &Lease{}
	ctx = WithBorrowedLease(ctx, "node-7", lease)
	if Target(ctx) != "node-7" {
		t.Fatal("borrowed lease did not annotate target")
	}
	if got, ok := BorrowedLease(ctx, "node-7"); !ok || got != lease {
		t.Fatal("borrowed lease was not returned for matching target")
	}
	if _, ok := BorrowedLease(ctx, "node-8"); ok {
		t.Fatal("borrowed lease crossed target scope")
	}
}
