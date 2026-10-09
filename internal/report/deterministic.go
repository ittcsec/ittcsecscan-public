package report

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ForbiddenImports is the deny-list of packages the report engine must never import,
// because each would make a report depend on something other than the frozen model it
// is given: the network or an AI service, the host, process execution, run-time code
// loading, randomness, or the wall clock. The same scan must always produce a
// byte-identical report (ADR-0028 section 6), so time-based values arrive as data
// (pre-formatted strings from the scan manifest), never a clock read, and archive
// timestamps are pinned. It is the structural sibling of the graph, rules, and risk
// gates.
//
// One synthetic entry is kept permanently so the gate is proven to bite now.
var ForbiddenImports = map[string]string{
	"example.com/forbidden-synthetic-import": "synthetic forbidden import, kept to prove the gate bites",

	"net":          "no network access in the report engine; a report depends only on the frozen model",
	"net/http":     "no HTTP or AI-service client in the report engine; a report is rendered, not fetched",
	"os":           "no host access in the report engine; renderers write to buffers, the CLI writes files",
	"os/exec":      "no process execution in the report engine",
	"plugin":       "never load code at run time",
	"math/rand":    "no randomness in the report engine; a report must be reproducible",
	"math/rand/v2": "no randomness in the report engine; a report must be reproducible",
	"crypto/rand":  "no randomness in the report engine; a report must be reproducible",
	"time":         "the wall clock must not enter a report; timestamps arrive as data from the scan manifest",
}

// Violation is one forbidden import found in the report source.
type Violation struct {
	File   string
	Line   int
	Import string
	Reason string
}

func checkImports(fset *token.FileSet, filename, src string) []Violation {
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	var out []Violation
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if reason, forbidden := ForbiddenImports[path]; forbidden {
			pos := fset.Position(imp.Pos())
			out = append(out, Violation{File: filename, Line: pos.Line, Import: path, Reason: reason})
		}
	}
	return out
}

// CheckDir walks root's non-test Go source and returns every forbidden import.
func CheckDir(root string) ([]Violation, error) {
	fset := token.NewFileSet()
	var out []Violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if d.Name() == "deterministic.go" {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from walking a source tree given by the caller, not untrusted input
		if err != nil {
			return err
		}
		out = append(out, checkImports(fset, path, string(data))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}
