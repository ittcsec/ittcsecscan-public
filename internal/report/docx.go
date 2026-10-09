package report

import (
	"archive/zip"
	"bytes"
	"strings"
)

// DOCX renders the frozen report model to a minimal, valid Office Open XML (.docx)
// document using only the standard library (archive/zip plus hand-written XML). It is a
// pure view of the ordered report lines, so it carries the same content as the other
// formats; XML text is escaped on top of the model's sanitization. It is deterministic:
// the zip entries are written in a fixed order with zero (pinned) modification times and
// no host metadata.
func DOCX(r Report) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", relsXML},
		{"word/document.xml", documentXML(r)},
	}
	for _, f := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate}) // Modified left zero: deterministic
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`</Relationships>`

func documentXML(r Report) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, ln := range reportLines(r) {
		b.WriteString(`<w:p>`)
		if ln.Heading {
			b.WriteString(`<w:pPr><w:rPr><w:b/></w:rPr></w:pPr><w:r><w:rPr><w:b/></w:rPr>`)
		} else {
			b.WriteString(`<w:r>`)
		}
		b.WriteString(`<w:t xml:space="preserve">`)
		b.WriteString(xmlEscape(ln.Text))
		b.WriteString(`</w:t></w:r></w:p>`)
	}
	b.WriteString(`<w:sectPr/></w:body></w:document>`)
	return b.String()
}

// xmlEscape escapes the five XML predefined entities. Control characters that are
// invalid in XML 1.0 are dropped, keeping the document well-formed regardless of input.
func xmlEscape(s string) string {
	var b strings.Builder
	for _, rr := range s {
		switch rr {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if rr == '\t' || rr == '\n' || rr == '\r' || rr >= 0x20 {
				b.WriteRune(rr)
			}
		}
	}
	return b.String()
}
