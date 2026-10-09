package remediate

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/packs"
)

// shippedRuleIDs returns the ids of every rule in every embedded (shipped) detection
// pack, the set of finding types a real scan can produce.
func shippedRuleIDs(t *testing.T) []string {
	t.Helper()
	ruleset, err := pack.LoadBuiltinAll(packs.FS, nil)
	if err != nil {
		t.Fatalf("load builtin packs: %v", err)
	}
	ids := make([]string, 0, len(ruleset))
	for _, r := range ruleset {
		ids = append(ids, r.ID)
	}
	return ids
}

// TestEveryShippedRuleHasRemediationOrNamedGap is the remediation-completeness audit
// (item 7): every finding type a scan can produce must ship either a real remediation
// template or a specific, tracked named gap. A rule in neither silently falls back to the
// generic gap, which this test forbids, so a newly shipped detection cannot land without a
// deliberate remediation decision. A rule must not be in both.
func TestEveryShippedRuleHasRemediationOrNamedGap(t *testing.T) {
	for _, id := range shippedRuleIDs(t) {
		_, hasTemplate := templates[id]
		_, hasGap := namedGaps[id]
		switch {
		case hasTemplate && hasGap:
			t.Errorf("%s is both a remediation template and a named gap; it must be exactly one", id)
		case !hasTemplate && !hasGap:
			t.Errorf("%s has neither a remediation template nor a named gap: it would silently fall back to the generic gap. Add a real template or a tracked named gap.", id)
		}
	}
}

// auditEntity carries a superset of the trigger facts the templates read, so every
// template produces its real apply-ready action(s) for the audit.
func auditEntity() model.Entity {
	return model.Entity{
		Name:     "audit-resource",
		NativeID: "/subscriptions/s/resourceGroups/rg/providers/p/locations/eu/keyRings/kr/cryptoKeys/audit-resource",
		Type:     model.NodeDataStore,
		Attributes: map[string]string{
			"policy_is_public":    "true",
			"acl_all_users":       "READ",
			"publicly_accessible": "true",
			"engine":              "postgresql",
			"rotation_enabled":    "false",
		},
	}
}

// TestTemplatesShipRealCLIAndIaC proves every remediation template emits real, concrete
// content (a CLI command and an IaC snippet), not prose hints. This is the "not prose"
// half of the item 7 audit.
func TestTemplatesShipRealCLIAndIaC(t *testing.T) {
	e := auditEntity()
	var anyResourceBlock bool
	for id, build := range templates {
		c := build(e)
		if len(c.Actions) == 0 {
			t.Errorf("%s: template produced no actions", id)
			continue
		}
		var anyCLI, anyIaC bool
		for _, a := range c.Actions {
			if len(a.CLI) > 0 {
				anyCLI = true
				for _, cmd := range a.CLI {
					if strings.TrimSpace(cmd) == "" {
						t.Errorf("%s: an action has an empty CLI command", id)
					}
				}
			}
			if strings.TrimSpace(a.IaC) != "" {
				anyIaC = true
			}
			if strings.Contains(a.IaC, "resource \"") {
				anyResourceBlock = true
			}
		}
		if !anyCLI {
			t.Errorf("%s: ships no CLI command (prose only)", id)
		}
		if !anyIaC {
			t.Errorf("%s: ships no IaC snippet", id)
		}
		if len(c.Verification) == 0 {
			t.Errorf("%s: ships no verification step", id)
		}
	}
	if !anyResourceBlock {
		t.Error("no template ships a real Terraform resource block; expected at least one concrete resource snippet")
	}
}

// TestNamedGapsAreSpecific proves every named gap carries a specific, tracked reason, not
// an empty or placeholder string.
func TestNamedGapsAreSpecific(t *testing.T) {
	for id, reason := range namedGaps {
		if len(strings.TrimSpace(reason)) < 40 {
			t.Errorf("%s: named-gap reason is too short to be specific: %q", id, reason)
		}
	}
}
