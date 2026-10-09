package report

import (
	"bytes"
	"strconv"
	"strings"
)

// PDF renders the frozen report model to a minimal, deterministic PDF using only the
// standard library and the built-in Helvetica fonts (no font embedding, no third-party
// code, no timestamps, no randomness). It is a pure view of the ordered report lines,
// paginated; identical input yields byte-identical output. This is the stdlib-only
// choice (ADR-0028): no dependency, no reproducible-build-timeout impact.
func PDF(r Report) ([]byte, error) {
	lines := reportLines(r)
	const (
		linesPerPage = 48
		startY       = 742
		lineH        = 14
		leftX        = 50
	)
	var pages [][]reportLine
	for i := 0; i < len(lines); i += linesPerPage {
		end := i + linesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[i:end])
	}
	if len(pages) == 0 {
		pages = [][]reportLine{{}}
	}

	// Object numbering: 1 catalog, 2 pages, 3 Helvetica (F1), 4 Helvetica-Bold (F2),
	// then per page i: content stream = 5+2i, page = 6+2i.
	nPages := len(pages)
	var kids []string
	for i := 0; i < nPages; i++ {
		kids = append(kids, strconv.Itoa(6+2*i)+" 0 R")
	}

	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [" + strings.Join(kids, " ") + "] /Count " + strconv.Itoa(nPages) + " >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
	}
	for i := 0; i < nPages; i++ {
		content := pageContent(pages[i], startY, lineH, leftX)
		objs = append(objs, "<< /Length "+strconv.Itoa(len(content))+" >>\nstream\n"+content+"\nendstream")
		objs = append(objs, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents "+strconv.Itoa(5+2*i)+" 0 R >>")
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs)+1)
	for i, o := range objs {
		offsets[i+1] = b.Len()
		b.WriteString(strconv.Itoa(i+1) + " 0 obj\n" + o + "\nendobj\n")
	}
	xrefStart := b.Len()
	n := len(objs) + 1
	b.WriteString("xref\n0 " + strconv.Itoa(n) + "\n0000000000 65535 f \n")
	for i := 1; i < n; i++ {
		b.WriteString(pad10(offsets[i]) + " 00000 n \n")
	}
	b.WriteString("trailer\n<< /Size " + strconv.Itoa(n) + " /Root 1 0 R >>\nstartxref\n" + strconv.Itoa(xrefStart) + "\n%%EOF\n")
	return b.Bytes(), nil
}

func pageContent(lines []reportLine, startY, lineH, leftX int) string {
	var b strings.Builder
	y := startY
	for _, ln := range lines {
		font, size := "F1", 10
		if ln.Heading {
			font, size = "F2", 12
		}
		b.WriteString("BT /" + font + " " + strconv.Itoa(size) + " Tf " + strconv.Itoa(leftX) + " " + strconv.Itoa(y) + " Td (" + escapePDF(ln.Text) + ") Tj ET\n")
		y -= lineH
	}
	return b.String()
}

// escapePDF escapes a PDF literal string and maps bytes outside printable ASCII to '?'.
// The built-in fonts use WinAnsi and the report text is sanitized ASCII, so this keeps
// any stray byte deterministic and safe.
func escapePDF(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		default:
			if c < 0x20 || c > 0x7e {
				b.WriteByte('?')
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func pad10(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}
