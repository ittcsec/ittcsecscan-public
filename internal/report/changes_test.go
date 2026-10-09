package report

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/schema"
)

// The diff (Changes) section carries the recorded appeared/changed/disappeared deltas,
// renders them in the shared text lines, and keeps the report schema-valid.
func TestChangeSectionBuildsAndRenders(t *testing.T) {
	r := Build(Input{
		Tenant: "t", ToolVersion: "v", ChangeScanID: 7,
		EntityChanges: []EntityChange{
			{Change: "appeared", Type: "workload", Entity: "w1", Name: "runner"},
			{Change: "disappeared", Type: "identity", Entity: "u1"},
		},
		EdgeChanges: []EdgeChange{{Change: "appeared", Kind: "member_of", Source: "w1", Target: "a1"}},
	})
	if r.Changes.ScanID != 7 {
		t.Errorf("scan id = %d, want 7", r.Changes.ScanID)
	}
	if len(r.Changes.Entities) != 2 || len(r.Changes.Edges) != 1 {
		t.Fatalf("counts: %d entities, %d edges", len(r.Changes.Entities), len(r.Changes.Edges))
	}
	var sb strings.Builder
	for _, ln := range reportLines(r) {
		sb.WriteString(ln.Text)
		sb.WriteString("\n")
	}
	out := sb.String()
	for _, want := range []string{"Changes since the previous scan", "appeared: workload w1", "disappeared: identity u1", "edge w1 -member_of-> a1"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q", want)
		}
	}
	b, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateJSON(schema.ModelReport, b); err != nil {
		t.Fatalf("report with changes section violates the schema: %v\n%s", err, b)
	}
}

// A baseline scan (no recorded changes) renders the honest "no changes" line, not a
// synthesized set of appeared entities.
func TestChangeSectionBaselineEmpty(t *testing.T) {
	r := Build(Input{Tenant: "t", ToolVersion: "v", ChangeScanID: 1})
	if len(r.Changes.Entities) != 0 || len(r.Changes.Edges) != 0 {
		t.Error("baseline changes should be empty")
	}
	var sb strings.Builder
	for _, ln := range reportLines(r) {
		sb.WriteString(ln.Text)
		sb.WriteString("\n")
	}
	if !strings.Contains(sb.String(), "no changes recorded") {
		t.Error("baseline 'no changes recorded' message missing")
	}
}
