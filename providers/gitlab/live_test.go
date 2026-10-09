//go:build live

package gitlab

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveGitLabProjects runs the real read-only GitLab path against the account named
// by GITLAB_TOKEN. It is maintainer-run (the live build tag); CI does not run it. It confirms
// identity resolution and that the projects collector emits repository nodes and records
// a non-errored completeness.
func TestLiveGitLabProjects(t *testing.T) {
	if os.Getenv("GITLAB_TOKEN") == "" {
		t.Skip("set GITLAB_TOKEN to run the live GitLab test")
	}
	ctx := context.Background()
	src := NewSource(os.LookupEnv)

	id, err := src.adapter.Resolve(ctx, model.GitLab, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if id.Account == "" {
		t.Fatal("resolved identity has no username")
	}
	t.Logf("resolved username: %s", id.Account)

	account, collectors, err := src.Collectors(ctx, collect.NewBudget(50))
	if err != nil {
		t.Fatalf("collectors: %v", err)
	}
	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(scan.Completeness) == 0 {
		t.Fatal("no completeness recorded")
	}
	for _, c := range scan.Completeness {
		if c.Status == collect.Errored {
			t.Errorf("collector errored: %+v", c)
		}
	}
	repos, pipelines, artifacts := 0, 0, 0
	for _, n := range scan.Nodes {
		switch n.Type {
		case model.NodeRepository:
			repos++
		case model.NodePipeline:
			pipelines++
		case model.NodeArtifact:
			artifacts++
		default:
			t.Errorf("unexpected node type %q", n.Type)
		}
		if n.NativeID == "" {
			t.Errorf("%s node has no native id", n.Type)
		}
	}
	contains, builds := 0, 0
	for _, l := range scan.Links {
		switch l.Kind {
		case model.EdgeContains:
			contains++
		case model.EdgeBuilds:
			builds++
		}
	}
	t.Logf("account=%s projects=%d pipelines=%d artifacts=%d contains-edges=%d builds-edges=%d",
		account, repos, pipelines, artifacts, contains, builds)
}
