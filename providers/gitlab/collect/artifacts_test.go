package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// The collector lists projects then jobs, and emits an artifact node with a builds edge
// from the project's pipeline for each job that produced a build archive. A job with no
// archive (only a report, or none) yields no node.
func TestArtifactsEmitsArtifactAndBuildsEdge(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":1,"path_with_namespace":"acme/web","ci_config_path":""}]`, next: ""},
		{body: `[
			{"id":50,"name":"build","stage":"build","status":"success","ref":"main","artifacts_expire_at":"2026-10-01T00:00:00Z","artifacts_file":{"filename":"artifacts.zip","size":2048}},
			{"id":51,"name":"test","stage":"test","status":"success","ref":"main","artifacts":[{"file_type":"junit","size":10,"filename":"junit.xml"}]}
		]`, next: ""},
	}}
	c := newArtifactsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	const art = "acme/web/artifacts/50"
	n, ok := findNode(sink.Nodes, art)
	if !ok || n.Type != model.NodeArtifact || n.Name != "artifacts.zip" {
		t.Fatalf("artifact node wrong: %+v", n)
	}
	if n.Attributes["size_bytes"] != "2048" || n.Attributes["job"] != "build" || n.Attributes["repository"] != "acme/web" {
		t.Errorf("artifact attributes wrong: %+v", n.Attributes)
	}
	l, ok := findLink(sink.Links, "acme/web/.gitlab-ci.yml", art)
	if !ok || l.Kind != model.EdgeBuilds {
		t.Fatalf("expected a builds edge pipeline -> artifact, got %+v", sink.Links)
	}
	// The test job's junit report is not a build archive, so it yields no artifact node.
	if _, ok := findNode(sink.Nodes, "acme/web/artifacts/51"); ok {
		t.Error("a job with only a report artifact must not emit an artifact node")
	}
	if len(sink.Nodes) != 1 {
		t.Errorf("emitted %d nodes, want 1", len(sink.Nodes))
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Complete || sink.Completeness[0].Collected != 1 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

// An "archive" entry in the artifacts array is recognized as the build archive when
// there is no legacy artifacts_file, and the custom ci_config_path keys the builds edge.
func TestArtifactsRecognizesArchiveArrayEntry(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":2,"path_with_namespace":"acme/api","ci_config_path":".ci/pipeline.yml"}]`, next: ""},
		{body: `[{"id":90,"name":"package","stage":"build","ref":"trunk","artifacts":[{"file_type":"archive","size":4096,"filename":"pkg.tar.gz"}]}]`, next: ""},
	}}
	c := newArtifactsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	const art = "acme/api/artifacts/90"
	n, ok := findNode(sink.Nodes, art)
	if !ok || n.Name != "pkg.tar.gz" || n.Attributes["size_bytes"] != "4096" {
		t.Fatalf("archive-array artifact wrong: %+v", n)
	}
	if _, ok := findLink(sink.Links, "acme/api/.ci/pipeline.yml", art); !ok {
		t.Fatalf("expected builds edge from custom ci_config_path pipeline, got %+v", sink.Links)
	}
}

// A per-project denied jobs read is a represented Partial gap, not a hard error and not
// a silent stop.
func TestArtifactsPerProjectDenialIsPartial(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":1,"path_with_namespace":"acme/web"}]`, next: ""},
		{err: &gitlabError{status: 403, body: "forbidden"}},
	}}
	c := newArtifactsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a per-project denial must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected a Partial completeness, got %+v", sink.Completeness)
	}
	if len(sink.Nodes) != 0 {
		t.Error("a denied jobs read must emit no artifact node")
	}
}

// A denied project listing is a represented Denied gap.
func TestArtifactsProjectListDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &gitlabError{status: 401, body: "unauthorized"}}}}
	c := newArtifactsCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a denied listing must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected a Denied completeness, got %+v", sink.Completeness)
	}
}
