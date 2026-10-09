package risk

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ForbiddenImports is the deny-list of packages the risk model must never import,
// because each would let a risk score depend on something other than the analysis
// outputs it is given: the network or an AI service, process execution, run-time code
// loading, randomness, or the wall clock. It is the structural sibling of
// internal/graph/deterministic.go and internal/rules/deterministic.go: the risk model
// is a transparent, versioned, reproducible calculation, so identical input yields an
// identical score (ADR-0027). Any time-based input arrives as data, never a clock read.
//
// One synthetic entry is kept permanently so the gate is proven to bite now rather
// than being first exercised by a real violation.
var ForbiddenImports = map[string]string{
	"example.com/forbidden-synthetic-import": "synthetic forbidden import, kept to prove the gate bites",

	"net":          "no network access in the risk model; a score depends only on the analysis outputs",
	"net/http":     "no HTTP or AI-service client in the risk model; a score is a documented calculation, not a model call",
	"os":           "no host or environment access in the risk model",
	"os/exec":      "no process execution in the risk model",
	"plugin":       "never load code at run time",
	"math/rand":    "no randomness in the risk model; scores must be reproducible",
	"math/rand/v2": "no randomness in the risk model; scores must be reproducible",
	"crypto/rand":  "no randomness in the risk model; scores must be reproducible",
	"time":         "the wall clock must not enter a score; a finding's first-seen comes from the scan",
}

// Violation is one forbidden import found in the risk-model source.
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

// CheckDir walks root's non-test Go source and returns every forbidden import. vendor
// and testdata are skipped, and this gate's own definition is skipped (it names the
// forbidden paths as string-literal map keys, not imports).
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
