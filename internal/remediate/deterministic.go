package remediate

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ForbiddenImports is the deny-list of packages the remediation PLAN generator
// must never import. Plan generation is read-only and deterministic: the same
// finding and entity must always produce a byte-identical plan (so its PlanHash
// is stable and an approval can bind to it), and content comes only from the
// in-code, doc-verified template catalog, never the network, an AI service, the
// host, process execution, run-time code, randomness, or the wall clock. It is
// the structural sibling of the graph, rules, risk, and report gates.
//
// The executor (the one component allowed to call provider writes) lives in the
// execute subpackage behind an experimental build tag and is intentionally NOT
// covered by this gate; the CheckDir walk skips it, exactly as the rules gate
// skips its pack subpackage.
//
// One synthetic entry is kept permanently so the gate is proven to bite now.
var ForbiddenImports = map[string]string{
	"example.com/forbidden-synthetic-import": "synthetic forbidden import, kept to prove the gate bites",

	"net":          "no network access in plan generation; a plan depends only on the finding and the entity's collected facts",
	"net/http":     "no HTTP or AI-service client in plan generation; guidance comes from the in-code doc-verified catalog",
	"os":           "no host access in plan generation; the CLI reads and writes files, the generator does not",
	"os/exec":      "no process execution in plan generation",
	"plugin":       "never load code at run time",
	"math/rand":    "no randomness in plan generation; a plan must be reproducible so its hash is stable",
	"math/rand/v2": "no randomness in plan generation; a plan must be reproducible so its hash is stable",
	"crypto/rand":  "no randomness in plan generation; a plan must be reproducible so its hash is stable",
	"time":         "the wall clock must not enter a plan; time-dependent values (for example a next-rotation time) are left as explicit placeholders",
}

// Violation is one forbidden import found in the remediation source.
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

// CheckDir walks root's non-test Go source and returns every forbidden import,
// skipping the execute subpackage (the tagged executor) as noted above.
func CheckDir(root string) ([]Violation, error) {
	fset := token.NewFileSet()
	var out []Violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" || d.Name() == "execute" {
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
