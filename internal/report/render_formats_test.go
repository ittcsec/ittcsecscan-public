package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

func renderAll(t *testing.T, r Report) map[string][]byte {
	t.Helper()
	j, err := JSON(r)
	must(t, err)
	s, err := SARIF(r)
	must(t, err)
	h, err := HTML(r)
	must(t, err)
	d, err := DOCX(r)
	must(t, err)
	p, err := PDF(r)
	must(t, err)
	return map[string][]byte{"json": j, "sarif": s, "html": h, "docx": d, "pdf": p}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// docxText returns the concatenated word/document.xml of a .docx byte stream.
func docxText(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			must(t, err)
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			must(t, err)
			return string(data)
		}
	}
	t.Fatal("docx has no word/document.xml")
	return ""
}

// searchable returns each format's searchable text (docx is unzipped to its document.xml).
func searchable(t *testing.T, formats map[string][]byte) map[string]string {
	out := map[string]string{}
	for name, b := range formats {
		if name == "docx" {
			out[name] = docxText(t, b)
		} else {
			out[name] = string(b)
		}
	}
	return out
}

func TestAllFormatsDeterministic(t *testing.T) {
	a := renderAll(t, Build(fixtureInput()))
	b := renderAll(t, Build(fixtureInput()))
	for name := range a {
		if !bytes.Equal(a[name], b[name]) {
			t.Errorf("%s render is not deterministic", name)
		}
	}
}

// TestAllFormatsHonesty is the honesty gate over every rendered format: none leaks the
// secret or emits a forbidden dash, and the secret is redacted.
func TestAllFormatsHonesty(t *testing.T) {
	txt := searchable(t, renderAll(t, Build(fixtureInput())))
	for name, s := range txt {
		if strings.Contains(s, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%s leaked the secret", name)
		}
		if !strings.Contains(s, "[REDACTED]") {
			t.Errorf("%s did not carry the redaction placeholder", name)
		}
		if containsForbiddenDash(s) {
			t.Errorf("%s emitted a forbidden em/en dash", name)
		}
	}
}

// TestFindingsIdenticalAcrossAllFormats proves every finding (rule and entity) appears
// in all five formats, the design's identical-findings requirement.
func TestFindingsIdenticalAcrossAllFormats(t *testing.T) {
	r := Build(fixtureInput())
	txt := searchable(t, renderAll(t, r))
	if len(r.Findings) == 0 {
		t.Fatal("fixture has no findings")
	}
	for _, f := range r.Findings {
		for name, s := range txt {
			if !strings.Contains(s, f.Rule) {
				t.Errorf("%s is missing finding rule %q", name, f.Rule)
			}
			if !strings.Contains(s, f.Entity) {
				t.Errorf("%s is missing finding entity %q", name, f.Entity)
			}
		}
	}
}

func TestFormatStructure(t *testing.T) {
	f := renderAll(t, Build(fixtureInput()))
	if !bytes.HasPrefix(f["pdf"], []byte("%PDF-1.")) || !bytes.Contains(f["pdf"], []byte("%%EOF")) {
		t.Error("pdf is not a well-formed PDF")
	}
	if !bytes.Contains(f["html"], []byte("<!DOCTYPE html>")) {
		t.Error("html is not a well-formed HTML document")
	}
	// docx opened as a zip in docxText already asserts validity; confirm coverage heading present.
	if !strings.Contains(docxText(t, f["docx"]), "Coverage and blind spots") {
		t.Error("docx missing the coverage section")
	}
}
