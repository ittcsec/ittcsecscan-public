//go:build live

package okta

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveOkta runs the real read-only Okta path against the org named by OKTA_ORG_URL /
// OKTA_API_TOKEN. It is maintainer-run (the live build tag) and skips when the env is absent.
func TestLiveOkta(t *testing.T) {
	if os.Getenv("OKTA_ORG_URL") == "" || os.Getenv("OKTA_API_TOKEN") == "" {
		t.Skip("set OKTA_ORG_URL and OKTA_API_TOKEN to run the live Okta test")
	}
	ctx := context.Background()
	src := NewSource(os.LookupEnv)
	id, err := src.adapter.Resolve(ctx, model.Okta, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	t.Logf("resolved org=%s", id.Account)

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
	t.Logf("org=%s users=%d groups=%d memberships=%d", account, users, groups, memberships)
}
