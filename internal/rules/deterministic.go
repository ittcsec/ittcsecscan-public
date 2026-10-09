package rules

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ForbiddenImports is the deny-list of packages the rule-evaluation code must never
// import, because each would let a finding decision depend on something other than the
// collected evidence: the network or an AI service, process execution, run-time code
// loading, randomness, or the wall clock (ADR-0021 §4). It is the structural sibling of
// internal/collect/readonly.go: the determinism and no-AI guarantees are enforced by a
// standing, testable gate, not by a written policy a reviewer might miss.
//
// A rule itself is closed predicate data with no call site (rule.go), so it cannot call
// out regardless; this gate additionally keeps the *interpreter* incapable of reaching
// any of these. Signature verification and pack loading, which legitimately touch
// crypto and embedded bytes, live in a separate package (internal/rules/pack) that
// never performs a finding decision and is gated for its own concern (no network, no
// shell); the evaluation package here imports only the loaded rule data.
//
// One synthetic entry is kept permanently so the gate is proven to bite now rather than
// being first exercised by a real violation (see TestDeterministicGateBites).
var ForbiddenImports = map[string]string{
	"example.com/forbidden-synthetic-import": "synthetic forbidden import, kept to prove the gate bites",

	"net":          "no network access in evaluation; a finding depends only on collected evidence",
	"net/http":     "no HTTP or AI-service client in evaluation; findings are never outsourced to a model",
	"os":           "no host or environment access in evaluation",
	"os/exec":      "no process execution in evaluation (ADR-0005)",
	"plugin":       "never load code at run time; packs are declarative (ADR-0004)",
	"math/rand":    "no randomness in evaluation; results must be reproducible",
	"math/rand/v2": "no randomness in evaluation; results must be reproducible",
	"crypto/rand":  "no randomness in evaluation; results must be reproducible",
	"time":         "the wall clock must not enter a finding decision; timestamps come from the scan manifest",
}

// Violation is one forbidden import found in the evaluation source.
type Violation struct {
	File   string
	Line   int
	Import string
	Reason string
}

// checkImports parses one Go source and returns the forbidden imports in it. An
// unparseable source yields no violations; the compiler catches that separately.
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
// forbidden paths as string-literal map keys, not imports, but it is excluded for the
// same clarity as the read-only gate excludes readonly.go). It is the gate: an
// evaluation file that imports a forbidden package is a failing test, not a review
// catch.
func CheckDir(root string) ([]Violation, error) {
	fset := token.NewFileSet()
	var out []Violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// pack is the signature-verification and loading subpackage; it legitimately
			// uses crypto and file reads and performs no finding decision, so it is
			// outside the evaluation gate (mirrored by the depguard scope).
			if d.Name() == "vendor" || d.Name() == "testdata" || d.Name() == "pack" {
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
