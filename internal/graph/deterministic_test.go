package graph

import (
	"go/token"
	"strings"
	"testing"
)

// TestGraphAnalysisIsDeterministic is the standing gate: the graph-analysis package
// imports nothing that could make a derived edge depend on the network, an AI service,
// the host, randomness, or the clock. It runs over the real source, so a later analysis
// file that imports a forbidden package fails CI (ADR-0022 §3).
func TestGraphAnalysisIsDeterministic(t *testing.T) {
	v, err := CheckDir(".")
	if err != nil {
		t.Fatalf("checking analysis source: %v", err)
	}
	if len(v) != 0 {
		var lines []string
		for _, x := range v {
			lines = append(lines, x.File+": imports "+x.Import+" ("+x.Reason+")")
		}
		t.Errorf("forbidden imports in the graph package:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestGraphDeterministicGateBites proves the gate fires now: a synthetic source importing
// a forbidden package (and the synthetic marker) is flagged, so the gate is known to work
// before a real violation ever exists.
func TestGraphDeterministicGateBites(t *testing.T) {
	src := `package p
import (
	_ "net/http"
	_ "time"
	_ "example.com/forbidden-synthetic-import"
)
`
	got := checkImports(token.NewFileSet(), "synthetic.go", src)
	if len(got) != 3 {
		t.Fatalf("gate found %d forbidden imports, want 3: %+v", len(got), got)
	}
}

// TestGraphGatePassesCleanImports proves the gate is signal, not noise.
func TestGraphGatePassesCleanImports(t *testing.T) {
	src := `package p
import (
	"fmt"
	"sort"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)
var _ = fmt.Sprint
`
	if got := checkImports(token.NewFileSet(), "clean.go", src); len(got) != 0 {
		t.Errorf("gate wrongly flagged clean imports: %+v", got)
	}
}

// TestGraphForbiddenSetCovers locks the categories the gate must forbid.
func TestGraphForbiddenSetCovers(t *testing.T) {
	for _, p := range []string{"net", "net/http", "os", "os/exec", "plugin", "math/rand", "math/rand/v2", "crypto/rand", "time"} {
		if _, ok := ForbiddenImports[p]; !ok {
			t.Errorf("graph gate does not forbid %q", p)
		}
	}
}
