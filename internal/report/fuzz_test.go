package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
)

// FuzzReportRendersSafely drives arbitrary attacker-influenced strings (a resource native
// id, a detail, and a completeness reason) through the whole report pipeline: Build, then
// every renderer. It asserts no renderer panics, JSON and SARIF stay valid JSON, and no raw
// control byte or bidi override reaches any format's content (T-02, T-03, T-16).
func FuzzReportRendersSafely(f *testing.F) {
	// The bidi override (U+202E) is built at runtime so no dangerous bidi character is
	// committed to this source file (bidichk / gosec G116).
	bidi := string(rune(0x202e))
	f.Add("arn:aws:s3:::pub", "a normal detail", "not subscribed")
	f.Add("\x1b[31m\x00</w:t>", "</script><script>x</script>", bidi+"evil\xff")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, native, detail, reason string) {
		in := Input{
			Tenant: "aaaaaaaaaaaaaaaaaaaaaaaaaa", ToolVersion: "v1",
			Providers: []ProviderCoverage{{
				Provider: "aws", Authenticated: true,
				Records: []collect.Completeness{{Service: "s3", Status: collect.Denied, Reason: reason}},
			}},
			Findings: []pipeline.RankedFinding{{
				Finding: model.Finding{Rule: model.RuleRef{RuleID: "R"}, Entity: "sid1", State: model.Fail, Detail: detail},
				Native:  native,
			}},
		}
		r := Build(in)

		j, err := JSON(r)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		if !json.Valid(j) {
			t.Fatalf("JSON invalid for native=%q detail=%q reason=%q", native, detail, reason)
		}
		s, err := SARIF(r)
		if err != nil {
			t.Fatalf("SARIF: %v", err)
		}
		if !json.Valid(s) {
			t.Fatalf("SARIF invalid for native=%q", native)
		}
		h, err := HTML(r)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		d, err := DOCX(r)
		if err != nil {
			t.Fatalf("DOCX: %v", err)
		}
		p, err := PDF(r)
		if err != nil {
			t.Fatalf("PDF: %v", err)
		}

		// Content must carry no raw control bytes or bidi override. DOCX is a zip, so check
		// its uncompressed document part.
		content := map[string][]byte{"json": j, "sarif": s, "html": h, "pdf": p, "docx": []byte(docxText(t, d))}
		for name, out := range content {
			for _, seq := range [][]byte{{0x1b}, {0x00}, {0x07}, {0xe2, 0x80, 0xae}} {
				if bytes.Contains(out, seq) {
					t.Fatalf("%s content carries a raw control/bidi sequence for native=%q detail=%q reason=%q", name, native, detail, reason)
				}
			}
		}
	})
}
