package report

import (
	"html/template"
	"strconv"
	"strings"
)

// Attack-path diagram (item 8): a deterministic, self-contained inline SVG for each
// attack path in the HTML report, rendering the chain exposed resource to assumed role to
// effective permission to sensitive data as node boxes joined by labeled arrows, rather
// than only a table row. It uses no JavaScript and no external asset, so the report stays
// a self-contained offline artifact, and its geometry is a pure function of the step
// list, so the same model renders identical bytes. Every inserted value is XML-escaped on
// top of the model's honesty-gate sanitization.

const (
	dgBoxW   = 190
	dgBoxH   = 48
	dgGapX   = 56
	dgMargX  = 12
	dgTopY   = 40 // room above the boxes for the arrow labels
	dgHeight = dgTopY + dgBoxH + 16
	dgMaxLbl = 26 // characters shown in a box before truncation (full text is in the title)
)

// diagram is one attack path's rendered SVG and its caption.
type diagram struct {
	Title   string
	Caption string
	SVG     template.HTML
}

// attackPathDiagrams builds one diagram per attack path, in the model's (risk) order.
func attackPathDiagrams(r Report) []diagram {
	out := make([]diagram, 0, len(r.Paths))
	for _, p := range r.Paths {
		if len(p.Steps) == 0 {
			continue
		}
		out = append(out, diagram{
			Title:   "Attack path: " + p.Entry + " to " + p.Target,
			Caption: "risk " + strconv.Itoa(p.Risk) + ", confidence " + strconv.Itoa(p.Confidence) + ", " + strconv.Itoa(len(p.Steps)-1) + " hops",
			SVG:     template.HTML(pathSVG(p)), //nolint:gosec // G203: every dynamic value is XML-escaped by xmlEscape below; static geometry otherwise
		})
	}
	return out
}

// pathSVG renders one path as an SVG string. The nodes lay out left to right; each arrow
// into a node is labeled with the edge kind (Via) and the technique that reached it. The
// first node (entry) and the last (target) are colored distinctly from the hops between.
func pathSVG(p Path) string {
	n := len(p.Steps)
	width := dgMargX*2 + n*dgBoxW + (n-1)*dgGapX
	var b strings.Builder
	title := "Attack path from " + p.Entry + " to " + p.Target
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" role="img" width="`)
	b.WriteString(strconv.Itoa(width))
	b.WriteString(`" height="`)
	b.WriteString(strconv.Itoa(dgHeight))
	b.WriteString(`" viewBox="0 0 `)
	b.WriteString(strconv.Itoa(width) + " " + strconv.Itoa(dgHeight))
	b.WriteString(`"><title>`)
	b.WriteString(xmlEscape(title))
	b.WriteString(`</title>`)

	for i, s := range p.Steps {
		x := dgMargX + i*(dgBoxW+dgGapX)
		// Arrow into this node from the previous one, with its edge kind and technique.
		if i > 0 {
			prevRight := x - dgGapX
			midY := dgTopY + dgBoxH/2
			b.WriteString(line(prevRight, midY, x, midY))
			b.WriteString(arrowHead(x, midY))
			lbl := strings.TrimSpace(s.Via)
			if s.Technique != "" {
				if lbl != "" {
					lbl += " / "
				}
				lbl += s.Technique
			}
			if lbl != "" {
				b.WriteString(labelText(prevRight+dgGapX/2, dgTopY-6, lbl))
			}
		}
		b.WriteString(nodeBox(x, dgTopY, i, n, s.Node))
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func nodeBox(x, y, i, n int, label string) string {
	fill := "#e5e7eb" // a hop
	switch i {
	case 0:
		fill = "#fde68a" // entry (exposed)
	case n - 1:
		fill = "#fecaca" // target (sensitive)
	}
	var b strings.Builder
	// The full node id is a title nested inside the rect, so hovering the box shows it even
	// when the visible label is truncated (a sibling title would attach to nothing).
	b.WriteString(`<rect x="` + strconv.Itoa(x) + `" y="` + strconv.Itoa(y) + `" width="` + strconv.Itoa(dgBoxW) + `" height="` + strconv.Itoa(dgBoxH) + `" rx="6" fill="` + fill + `" stroke="#9ca3af">`)
	b.WriteString(`<title>` + xmlEscape(label) + `</title></rect>`)
	b.WriteString(text(x+dgBoxW/2, y+dgBoxH/2+4, "middle", 11, "#111", truncate(label, dgMaxLbl)))
	return b.String()
}

func line(x1, y1, x2, y2 int) string {
	return `<line x1="` + strconv.Itoa(x1) + `" y1="` + strconv.Itoa(y1) + `" x2="` + strconv.Itoa(x2) + `" y2="` + strconv.Itoa(y2) + `" stroke="#6b7280" stroke-width="1.5"/>`
}

// arrowHead draws a small triangle pointing right at (x,y), the end of an arrow.
func arrowHead(x, y int) string {
	return `<polygon points="` +
		strconv.Itoa(x-6) + "," + strconv.Itoa(y-4) + " " +
		strconv.Itoa(x) + "," + strconv.Itoa(y) + " " +
		strconv.Itoa(x-6) + "," + strconv.Itoa(y+4) +
		`" fill="#6b7280"/>`
}

func text(x, y int, anchor string, size int, fill, s string) string {
	return `<text x="` + strconv.Itoa(x) + `" y="` + strconv.Itoa(y) +
		`" text-anchor="` + anchor + `" font-family="system-ui,sans-serif" font-size="` + strconv.Itoa(size) +
		`" fill="` + fill + `">` + xmlEscape(s) + `</text>`
}

// labelText renders an arrow label (edge kind and technique), visually truncated to fit
// the gap, with the full text in a title so no detail is lost.
func labelText(x, y int, full string) string {
	shown := truncate(full, 28)
	return `<text x="` + strconv.Itoa(x) + `" y="` + strconv.Itoa(y) +
		`" text-anchor="middle" font-family="system-ui,sans-serif" font-size="10" fill="#555">` +
		`<title>` + xmlEscape(full) + `</title>` + xmlEscape(shown) + `</text>`
}

// truncate shortens s to max runes, adding an ellipsis marker, so a long id fits a box
// (the full value is in the node's title). xmlEscape (docx.go) escapes every value before
// it enters the SVG, as a second net over the model's honesty-gate sanitization.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
