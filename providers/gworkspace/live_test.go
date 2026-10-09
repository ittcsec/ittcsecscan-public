//go:build live

package gworkspace

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveGoogleWorkspace runs the real read-only Directory path against the customer whose
// token is in GOOGLE_WORKSPACE_TOKEN. It is maintainer-run (the live build tag) and skips when
// the env is absent.
func TestLiveGoogleWorkspace(t *testing.T) {
	if os.Getenv("GOOGLE_WORKSPACE_TOKEN") == "" {
		t.Skip("set GOOGLE_WORKSPACE_TOKEN to run the live Google Workspace test")
	}
	ctx := context.Background()
	src := NewSource(os.LookupEnv)
	if _, err := src.adapter.Resolve(ctx, model.GoogleWorkspace, auth.Discovery); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	account, collectors, err := src.Collectors(ctx, collect.NewBudget(200))
	if err != nil {
		t.Fatalf("collectors: %v", err)
	}
	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, c := range scan.Completeness {
		if c.Status == collect.Errored {
			t.Errorf("collector errored: %+v", c)
		}
	}
	users, groups, memberships := 0, 0, 0
	for _, n := range scan.Nodes {
		switch n.Type {
		case model.NodeIdentity:
			users++
		case model.NodeGroup:
			groups++
		}
	}
	for _, l := range scan.Links {
		if l.Kind == model.EdgeMemberOf {
			memberships++
		}
	}
	t.Logf("customer=%s users=%d groups=%d memberships=%d", account, users, groups, memberships)
}
