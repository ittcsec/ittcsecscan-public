package pack

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/rules"
	"github.com/ittcsec/ittcsecscan/packs"
)

// productionSource concatenates every non-test Go source under the collector providers and
// the analysis engines, where completeness services are recorded and node facts are written.
// A fact key or completeness service a rule requires must appear here as a string literal, or
// nothing produces it.
func productionSource(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, root := range []string{"../../../providers", "../../../internal/graph"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path) //nolint:gosec // G304: walking a fixed in-repo source tree in a test
			if rerr != nil {
				return rerr
			}
			b.Write(data)
			b.WriteByte('\n')
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return b.String()
}

// collectFacts gathers every fact key a predicate references, recursing through children and
// the far node of a has_edge.
func collectFacts(p rules.Predicate, out map[string]bool) {
	if p.Fact != "" {
		out[p.Fact] = true
	}
	for _, c := range p.Children {
		collectFacts(c, out)
	}
	if p.Target != nil && p.Target.Predicate != nil {
		collectFacts(*p.Target.Predicate, out)
	}
}

func ruleFacts(r rules.Rule) map[string]bool {
	out := map[string]bool{}
	if r.Selector.Predicate != nil {
		collectFacts(*r.Selector.Predicate, out)
	}
	collectFacts(r.Predicate, out)
	for _, f := range r.Confidence.Factors {
		collectFacts(f.When, out)
	}
	return out
}

func allShippedRules(t *testing.T) []rules.Rule {
	t.Helper()
	core, err := LoadBuiltinAll(packs.FS, nil)
	if err != nil {
		t.Fatalf("load builtin packs: %v", err)
	}
	all := append(core, loadAIGuard(t)...)
	return append(all, loadIdentityHygiene(t)...)
}

// TestEveryRuleFactAndServiceIsProduced is the groundedness guard: every fact key a shipped
// rule reads, and every completeness service it requires, must be produced by some production
// collector or engine (appear as a string literal in the provider or graph source). It fails
// closed on a rule that depends on a fact or service nothing emits, which is exactly the bug
// where the excessive-agency rule required the nonexistent "iam.effectivePrivilege" service
// and read privilege_level on a node that never carries it.
func TestEveryRuleFactAndServiceIsProduced(t *testing.T) {
	src := productionSource(t)
	has := func(s string) bool { return strings.Contains(src, `"`+s+`"`) }

	for _, r := range allShippedRules(t) {
		for _, svc := range r.Requires.Completeness {
			if !has(svc) {
				t.Errorf("rule %s requires completeness service %q, which no production collector emits", r.ID, svc)
			}
		}
		for fact := range ruleFacts(r) {
			if !has(fact) {
				t.Errorf("rule %s reads fact %q, which no production collector or engine writes", r.ID, fact)
			}
		}
	}
}
