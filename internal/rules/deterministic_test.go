package rules

import (
	"go/token"
	"strings"
	"testing"
)

// TestEvaluationIsDeterministic is the standing gate: the rule-evaluation package
// imports nothing that could make a finding depend on the network, an AI service, the
// host, randomness, or the clock. It runs over the real source, not a demonstration, so
// a later evaluation file that imports a forbidden package fails CI (ADR-0021 §4).
func TestEvaluationIsDeterministic(t *testing.T) {
	v, err := CheckDir(".")
	if err != nil {
		t.Fatalf("checking evaluation source: %v", err)
	}
	if len(v) != 0 {
		var lines []string
		for _, x := range v {
			lines = append(lines, x.File+": imports "+x.Import+" ("+x.Reason+")")
		}
		t.Errorf("forbidden imports in the evaluation package:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestDeterministicGateBites proves the gate fires now: a synthetic source importing a
// forbidden package (and the synthetic marker) is flagged, so the gate is known to work
// before a real violation ever exists.
func TestDeterministicGateBites(t *testing.T) {
	src := `package p
import (
	_ "net/http"
	_ "example.com/forbidden-synthetic-import"
)
`
	got := checkImports(token.NewFileSet(), "synthetic.go", src)
	if len(got) != 2 {
		t.Fatalf("gate found %d forbidden imports, want 2: %+v", len(got), got)
	}
}

// TestGatePassesCleanImports proves the gate is signal, not noise: a source importing
// only allowed packages is not flagged.
func TestGatePassesCleanImports(t *testing.T) {
	src := `package p
import (
	"fmt"
	"sort"
	"strings"
	"github.com/ittcsec/ittcsecscan/internal/collect"
)
var _ = fmt.Sprint
`
	if got := checkImports(token.NewFileSet(), "clean.go", src); len(got) != 0 {
		t.Errorf("gate wrongly flagged clean imports: %+v", got)
	}
}

// TestForbiddenSetCoversNondeterminismAndIO documents and locks the categories the gate
// must forbid: network/AI (net, net/http), host/process (os, os/exec), run-time code
// (plugin), randomness (math/rand, math/rand/v2, crypto/rand), and the clock (time).
func TestForbiddenSetCoversNondeterminismAndIO(t *testing.T) {
	for _, p := range []string{"net", "net/http", "os", "os/exec", "plugin", "math/rand", "math/rand/v2", "crypto/rand", "time"} {
		if _, ok := ForbiddenImports[p]; !ok {
			t.Errorf("evaluation gate does not forbid %q", p)
		}
	}
}
