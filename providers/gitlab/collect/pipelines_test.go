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

// The collector lists projects, then for each project that has a pipeline emits one
// pipeline node keyed by its CI config path and a contains edge from the project. A
// project with no pipeline emits nothing (CI is not asserted without evidence).
func TestPipelinesEmitsPipelineAndContains(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":1,"path_with_namespace":"acme/web","ci_config_path":""},{"id":2,"path_with_namespace":"acme/api","ci_config_path":".ci/pipeline.yml"}]`, next: ""},
		{body: `[{"id":100,"ref":"main","sha":"abc","status":"success","source":"push","web_url":"https://gitlab.com/acme/web/-/pipelines/100"}]`, next: ""},
		{body: `[]`, next: ""},
	}}
	c := newPipelinesCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	const pid = "acme/web/.gitlab-ci.yml"
	n, ok := findNode(sink.Nodes, pid)
	if !ok || n.Type != model.NodePipeline || n.Name != ".gitlab-ci.yml" {
		t.Fatalf("pipeline node wrong: %+v", n)
	}
	if n.Attributes["latest_status"] != "success" || n.Attributes["ci_config_path"] != ".gitlab-ci.yml" || n.Attributes["repository"] != "acme/web" {
		t.Errorf("pipeline attributes wrong: %+v", n.Attributes)
	}
	if _, ok := findLink(sink.Links, "acme/web", pid); !ok {
		t.Fatalf("expected a contains edge project -> pipeline, got %+v", sink.Links)
	}
	// The project with an empty pipeline list yields no pipeline node.
	if _, ok := findNode(sink.Nodes, "acme/api/.ci/pipeline.yml"); ok {
		t.Error("a project with no pipeline must not emit a pipeline node")
	}
	if len(sink.Nodes) != 1 {
		t.Errorf("emitted %d nodes, want 1", len(sink.Nodes))
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Complete || sink.Completeness[0].Collected != 1 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

// The custom ci_config_path is used to key the pipeline node when the project sets one.
func TestPipelinesUsesCustomConfigPath(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":2,"path_with_namespace":"acme/api","ci_config_path":".ci/pipeline.yml"}]`, next: ""},
		{body: `[{"id":200,"ref":"trunk","status":"failed","source":"schedule"}]`, next: ""},
	}}
	c := newPipelinesCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if _, ok := findNode(sink.Nodes, "acme/api/.ci/pipeline.yml"); !ok {
		t.Fatalf("expected pipeline keyed by custom ci_config_path, got %+v", sink.Nodes)
	}
}

// A per-project denied read is a represented Partial gap, not a hard error and not a
// silent stop; other projects are still processed.
func TestPipelinesPerProjectDenialIsPartial(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":1,"path_with_namespace":"acme/web"}]`, next: ""},
		{err: &gitlabError{status: 403, body: "forbidden"}},
	}}
	c := newPipelinesCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a per-project denial must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected a Partial completeness, got %+v", sink.Completeness)
	}
	if len(sink.Nodes) != 0 {
		t.Error("a denied pipeline read must emit no pipeline node")
	}
}

// A denied project listing is a represented Denied gap.
func TestPipelinesProjectListDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &gitlabError{status: 403, body: "forbidden"}}}}
	c := newPipelinesCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a denied listing must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected a Denied completeness, got %+v", sink.Completeness)
	}
}
