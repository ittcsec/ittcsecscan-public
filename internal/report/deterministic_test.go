package report

import (
	"go/token"
	"strings"
	"testing"
)

func TestReportEngineIsDeterministic(t *testing.T) {
	v, err := CheckDir(".")
	if err != nil {
		t.Fatalf("checking report source: %v", err)
	}
	if len(v) != 0 {
		var lines []string
		for _, x := range v {
			lines = append(lines, x.File+": imports "+x.Import+" ("+x.Reason+")")
		}
		t.Errorf("forbidden imports in the report package:\n  %s", strings.Join(lines, "\n  "))
	}
}

func TestReportDeterministicGateBites(t *testing.T) {
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

func TestReportForbiddenSetCovers(t *testing.T) {
	for _, p := range []string{"net", "net/http", "os", "os/exec", "plugin", "math/rand", "math/rand/v2", "crypto/rand", "time"} {
		if _, ok := ForbiddenImports[p]; !ok {
			t.Errorf("report gate does not forbid %q", p)
		}
	}
}
