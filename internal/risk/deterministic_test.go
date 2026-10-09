package risk

import (
	"go/token"
	"strings"
	"testing"
)

// TestRiskModelIsDeterministic is the standing gate: the risk model imports nothing
// that could make a score depend on the network, an AI service, the host, randomness,
// or the clock. It runs over the real source (ADR-0027).
func TestRiskModelIsDeterministic(t *testing.T) {
	v, err := CheckDir(".")
	if err != nil {
		t.Fatalf("checking risk source: %v", err)
	}
	if len(v) != 0 {
		var lines []string
		for _, x := range v {
			lines = append(lines, x.File+": imports "+x.Import+" ("+x.Reason+")")
		}
		t.Errorf("forbidden imports in the risk package:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestRiskDeterministicGateBites proves the gate fires now.
func TestRiskDeterministicGateBites(t *testing.T) {
	src := `package p
import (
	_ "net/http"
	_ "time"
	_ "example.com/forbidden-synthetic-import"
)
`
	if got := checkImports(token.NewFileSet(), "synthetic.go", src); len(got) != 3 {
		t.Fatalf("gate found %d forbidden imports, want 3: %+v", len(got), got)
	}
}

// TestRiskForbiddenSetCovers locks the categories the gate must forbid.
func TestRiskForbiddenSetCovers(t *testing.T) {
	for _, p := range []string{"net", "net/http", "os", "os/exec", "plugin", "math/rand", "math/rand/v2", "crypto/rand", "time"} {
		if _, ok := ForbiddenImports[p]; !ok {
			t.Errorf("risk gate does not forbid %q", p)
		}
	}
}
