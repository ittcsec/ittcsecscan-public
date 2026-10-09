package report

import (
	"bytes"
	"html/template"
)

// htmlTemplate renders the ordered report lines, then the attack-path diagrams.
// html/template applies contextual auto-escaping to every {{.Text}}, so an untrusted
// resource name or tag cannot inject markup, on top of the redaction and dash-stripping
// already applied to the model. The diagram SVGs are template.HTML built by diagram.go,
// where every dynamic value is XML-escaped; they carry no script and no external asset, so
// the document stays self-contained and offline. lang="en" marks the current language;
// localization is a named follow-up (RP-2).
var htmlTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ittcsecscan report</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4;color:#111}
h2{margin-top:1.6rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}
.line{white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,monospace;font-size:.9rem}
.diagram{margin:1rem 0;overflow-x:auto}
.diagram figcaption{font-size:.85rem;color:#555;margin-bottom:.2rem}</style>
</head><body>
{{range .Lines}}{{if .Heading}}<h2>{{.Text}}</h2>
{{else}}<div class="line">{{.Text}}</div>
{{end}}{{end}}{{if .Diagrams}}<h2>Attack path diagrams</h2>
{{range .Diagrams}}<figure class="diagram"><figcaption>{{.Title}} ({{.Caption}})</figcaption>
{{.SVG}}</figure>
{{end}}{{end}}</body></html>
`))

// htmlModel is what the HTML template renders: the shared ordered lines plus the SVG
// attack-path diagrams the HTML format adds on top of them.
type htmlModel struct {
	Lines    []reportLine
	Diagrams []diagram
}

// HTML renders the frozen report model to a self-contained HTML document. It carries the
// same textual content as the other formats (the shared ordered lines) and adds a visual
// attack-path diagram per path; html/template escaping is applied on top of the model's
// sanitization, and the diagrams are XML-escaped, script-free inline SVG. Deterministic.
func HTML(r Report) ([]byte, error) {
	var b bytes.Buffer
	m := htmlModel{Lines: reportLines(r), Diagrams: attackPathDiagrams(r)}
	if err := htmlTemplate.Execute(&b, m); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
