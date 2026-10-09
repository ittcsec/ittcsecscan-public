package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func findLink(links []collect.Link, source, target string) (collect.Link, bool) {
	for _, l := range links {
		if l.SourceNativeID == source && l.TargetNativeID == target {
			return l, true
		}
	}
	return collect.Link{}, false
}

// The workflows collector lists repos, reads each repo's workflows, and emits a
// pipeline node plus a repository->pipeline contains edge per workflow.
func TestWorkflowsCollectEmitsPipelinesAndContainsEdges(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"full_name":"acme/web","name":"web","owner":{"login":"acme","type":"Organization"}}]`, next: ""},
		{body: `{"workflows":[{"id":42,"name":"CI","path":".github/workflows/ci.yml","state":"active"}]}`, next: ""},
	}}
	c := newWorkflowsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	const pipeline = "acme/web/.github/workflows/ci.yml"
	n, ok := findNode(sink.Nodes, pipeline)
	if !ok || n.Type != model.NodePipeline || n.Name != "CI" {
		t.Fatalf("pipeline node wrong: %+v", n)
	}
	if n.Attributes["state"] != "active" || n.Attributes["path"] != ".github/workflows/ci.yml" || n.Attributes["workflow_id"] != "42" || n.Attributes["repository"] != "acme/web" {
		t.Errorf("pipeline attributes wrong: %+v", n.Attributes)
	}
	l, ok := findLink(sink.Links, "acme/web", pipeline)
	if !ok || l.Kind != model.EdgeContains {
		t.Fatalf("expected a contains edge acme/web -> pipeline, got %+v", sink.Links)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Complete || sink.Completeness[0].Collected != 1 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

// A denied repository listing is a represented Denied gap.
func TestWorkflowsDeniedRepoListingIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &githubError{status: 403, body: "forbidden"}}}}
	c := newWorkflowsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("denied listing must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected Denied completeness, got %+v", sink.Completeness)
	}
	if len(sink.Nodes) != 0 || len(sink.Links) != 0 {
		t.Error("denied listing must emit nothing")
	}
}

// A denied per-repo workflow read degrades the overall status to Partial, not Complete.
func TestWorkflowsPerRepoDenialIsPartial(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"full_name":"acme/web","owner":{"login":"acme"}}]`, next: ""},
		{err: &githubError{status: 403, body: "forbidden"}},
	}}
	c := newWorkflowsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("per-repo denial must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected Partial completeness, got %+v", sink.Completeness)
	}
}
