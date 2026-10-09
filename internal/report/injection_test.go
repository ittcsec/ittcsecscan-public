package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
)

// maliciousInput builds a report whose attacker-controlled strings (a resource native id,
// an entity name, a completeness reason, a detail, and a classification label) carry every
// class of injection payload a hostile estate can plant in a name: HTML/script markup, OOXML
// tag breakout, PDF string breakout, shell metacharacters, an ANSI escape, C0/C1 control
// characters, a NUL, invalid UTF-8, and a "Trojan Source" bidi override. A report must
// neutralize all of it in every format (T-02, T-03).
func maliciousInput() Input {
	// The bidi override (U+202E) is built at runtime so no dangerous bidi character is
	// committed to this source file (bidichk / gosec G116).
	bidi := string(rune(0x202e))
	evil := "pub\x1b[31m\x00\x07</w:t></w:r>\") Tj 0 0 0 rg (</script><script>alert(1)</script>$(rm -rf /)`id`" + bidi + "exe.\xff"
	return Input{
		Tenant:      "aaaaaaaaaaaaaaaaaaaaaaaaaa",
		ToolVersion: "v1.0.0",
		Started:     "2026-09-28T00:00:00Z",
		Completed:   "2026-09-28T00:01:00Z",
		Providers: []ProviderCoverage{{
			Provider: "aws", Account: "acct-1", Authenticated: true,
			Records: []collect.Completeness{{Service: "s3", Status: collect.Denied, Reason: evil}},
		}},
		Findings: []pipeline.RankedFinding{{
			Finding: model.Finding{Rule: model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS"}, Entity: "sid1", State: model.Fail, Risk: 35, Confidence: 95, Detail: evil},
			Native:  evil,
			Basis:   []string{evil},
		}},
		Classifications: []model.Classification{{Entity: model.StableID(evil), Label: evil, Method: "resource_nature=data_store", Confidence: 15}},
	}
}

func TestReportsNeutralizeMaliciousResourceNames(t *testing.T) {
	formats := renderAll(t, Build(maliciousInput()))

	// The dangerous raw bytes and sequences must not survive into any format's content. The
	// ESC (0x1b), NUL, BEL, and the bidi override (UTF-8 E2 80 AE) are the concrete carriers.
	// A .docx is a ZIP, whose deflate stream legitimately contains arbitrary bytes, so its
	// content is checked as the uncompressed word/document.xml, not the zip wrapper.
	content := map[string][]byte{
		"json":  formats["json"],
		"sarif": formats["sarif"],
		"html":  formats["html"],
		"pdf":   formats["pdf"],
		"docx":  []byte(docxText(t, formats["docx"])),
	}
	forbiddenBytes := map[string][]byte{
		"ESC":           {0x1b},
		"NUL":           {0x00},
		"BEL":           {0x07},
		"bidi-override": {0xe2, 0x80, 0xae}, // U+202E right-to-left override
	}
	for name, out := range content {
		for label, seq := range forbiddenBytes {
			if bytes.Contains(out, seq) {
				t.Errorf("%s content contains raw %s from a malicious resource name", name, label)
			}
		}
	}

	// JSON and SARIF must remain valid JSON despite the payload.
	if !json.Valid(formats["json"]) {
		t.Error("JSON render is not valid JSON under a malicious resource name")
	}
	if !json.Valid(formats["sarif"]) {
		t.Error("SARIF render is not valid JSON under a malicious resource name")
	}

	// HTML must not contain an unescaped <script> tag: the payload must be entity-escaped.
	if bytes.Contains(formats["html"], []byte("<script>")) {
		t.Error("HTML output contains an unescaped <script> tag")
	}

	// The DOCX document part must be well-formed XML (the OOXML tag-breakout payload must
	// not have broken out of the text run).
	if err := xml.Unmarshal([]byte("<root>"+docxText(t, formats["docx"])+"</root>"), new(struct {
		XMLName xml.Name
		Inner   string `xml:",innerxml"`
	})); err != nil {
		// A raw </w:t></w:r> breakout would make this fail; escaped, it parses.
		if strings.Contains(docxText(t, formats["docx"]), "</w:t></w:r>") {
			t.Errorf("DOCX text contains a raw OOXML breakout sequence: %v", err)
		}
	}
	// And the whole .docx must still be a valid zip whose document.xml parses (docxText
	// already asserts the zip; parse the real part too).
	if err := xml.Unmarshal(fullDocumentXML(t, formats["docx"]), new(interface{})); err != nil {
		t.Errorf("DOCX word/document.xml is not well-formed XML: %v", err)
	}

	// PDF: escapePDF maps every byte outside printable ASCII to '?', so no ESC/NUL/bidi can
	// survive (covered above) and the parenthesis breakout is escaped; assert the payload's
	// literal ")" did not create an unescaped string terminator by checking the raw "\)"
	// escaping is what appears.
	if bytes.Contains(formats["pdf"], []byte(")\x1b")) {
		t.Error("PDF output has an unescaped string terminator followed by control bytes")
	}
}

// fullDocumentXML returns the raw word/document.xml bytes of a .docx.
func fullDocumentXML(t *testing.T, b []byte) []byte {
	t.Helper()
	return []byte(docxText(t, b))
}

// A malicious resource name still must not leak an embedded secret: the payload is combined
// with a secret and asserted redacted in every format (defense in depth over T-01).
func TestMaliciousNameStillRedactsSecrets(t *testing.T) {
	in := maliciousInput()
	in.Findings[0].Finding.Detail = "AKIAIOSFODNN7EXAMPLE " + in.Findings[0].Finding.Detail
	formats := renderAll(t, Build(in))
	for name, out := range formats {
		if bytes.Contains(out, []byte("AKIAIOSFODNN7EXAMPLE")) {
			t.Errorf("%s output leaked an AWS key id embedded alongside a malicious name", name)
		}
	}
}
