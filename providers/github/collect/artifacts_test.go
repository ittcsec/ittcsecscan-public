package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// The artifacts collector maps runs to workflow paths and emits an artifact node with
// a builds edge from the producing pipeline.
func TestArtifactsCollectBuildsEdgeFromPipeline(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"full_name":"acme/web","owner":{"login":"acme"}}]`, next: ""},
		{body: `{"workflow_runs":[{"id":100,"path":".github/workflows/ci.yml"}]}`, next: ""},
		{body: `{"artifacts":[{"id":5,"name":"build","size_in_bytes":123,"expired":false,"workflow_run":{"id":100}}]}`, next: ""},
	}}
	c := newArtifactsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	const art = "acme/web/artifacts/5"
	n, ok := findNode(sink.Nodes, art)
	if !ok || n.Type != model.NodeArtifact || n.Name != "build" {
		t.Fatalf("artifact node wrong: %+v", n)
	}
	if n.Attributes["size_bytes"] != "123" || n.Attributes["expired"] != "false" {
		t.Errorf("artifact attributes wrong: %+v", n.Attributes)
	}
	l, ok := findLink(sink.Links, "acme/web/.github/workflows/ci.yml", art)
	if !ok || l.Kind != model.EdgeBuilds {
		t.Fatalf("expected a builds edge pipeline -> artifact, got %+v", sink.Links)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Complete || sink.Completeness[0].Collected != 1 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

// An artifact whose run cannot be mapped to a workflow is attached to its repository
// with a contains edge, never guessed onto a pipeline.
func TestArtifactsUnmappedRunFallsBackToRepo(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"full_name":"acme/web","owner":{"login":"acme"}}]`, next: ""},
		{body: `{"workflow_runs":[]}`, next: ""},
		{body: `{"artifacts":[{"id":9,"name":"orphan","workflow_run":{"id":999}}]}`, next: ""},
	}}
	c := newArtifactsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if _, ok := findLink(sink.Links, "acme/web", "acme/web/artifacts/9"); !ok {
		t.Fatalf("expected a contains fallback edge repo -> artifact, got %+v", sink.Links)
	}
	for _, l := range sink.Links {
		if l.Kind == model.EdgeBuilds {
			t.Error("must not emit a builds edge for an unmapped artifact")
		}
	}
}
