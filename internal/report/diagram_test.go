package report

import (
	"strings"
	"testing"
)

func pathReport() Report {
	return Report{
		SchemaVersion: 1, Tenant: "t", ToolVersion: "v",
		Paths: []Path{{
			Entry: "exposed-vm", Target: "secret-bucket", Risk: 80, Confidence: 70,
			Steps: []Step{
				{Node: "exposed-vm"},
				{Node: "arn:aws:iam::1:role/app", Via: "assumes", Technique: "sts:AssumeRole"},
				{Node: "secret-bucket", Via: "can_read"},
			},
		}},
	}
}

// TestAttackPathDiagramRendersSVG proves the HTML report renders each attack path as an
// inline SVG with the node labels, the edge-kind arrow labels, and accessibility markup.
func TestAttackPathDiagramRendersSVG(t *testing.T) {
	b, err := HTML(pathReport())
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{
		"Attack path diagrams",
		"<svg", `role="img"`, "<title>",
		"exposed-vm", "secret-bucket", "assumes",
		"sts:AssumeRole",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML diagram missing %q", want)
		}
	}
	// No script and no external asset: the report stays self-contained and offline.
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Error("diagram must not introduce a script")
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		// The only URL allowed is the SVG namespace, which is an xmlns identifier, not a fetch.
		if !strings.Contains(out, `xmlns="http://www.w3.org/2000/svg"`) || strings.Count(out, "http") != strings.Count(out, "www.w3.org") {
			t.Error("diagram must not reference an external asset")
		}
	}
}

// TestAttackPathDiagramDeterministic proves the SVG is a pure function of the model: the
// same report renders byte-identical HTML.
func TestAttackPathDiagramDeterministic(t *testing.T) {
	r := pathReport()
	a, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("HTML with diagrams is not deterministic")
	}
}

// TestAttackPathDiagramEscapes proves a hostile node id cannot break out of the SVG markup:
// it is XML-escaped, so no raw tag reaches the document.
func TestAttackPathDiagramEscapes(t *testing.T) {
	r := Report{
		SchemaVersion: 1, Tenant: "t", ToolVersion: "v",
		Paths: []Path{{
			Entry: "e", Target: "x", Risk: 1, Confidence: 1,
			Steps: []Step{
				{Node: `<script>alert(1)</script>`},
				{Node: `x"/><rect onload="evil"`, Via: `a"b`},
			},
		}},
	}
	out, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Error("raw script tag leaked into the SVG")
	}
	if strings.Contains(s, `onload="evil"`) {
		t.Error("raw attribute injection leaked into the SVG")
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Error("expected the script tag to appear XML-escaped")
	}
}

// TestNoPathsNoDiagramSection proves the diagram section is absent when there are no attack
// paths, so a clean report does not show an empty diagrams heading.
func TestNoPathsNoDiagramSection(t *testing.T) {
	out, err := HTML(Report{SchemaVersion: 1, Tenant: "t", ToolVersion: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "Attack path diagrams") {
		t.Error("diagram section should be absent when there are no paths")
	}
}
