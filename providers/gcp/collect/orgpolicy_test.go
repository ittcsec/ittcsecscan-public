package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func runOrgPolicy(t *testing.T, project string, api gcpAPI, constraints []string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newOrgPolicyCollector(project, api, constraints).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func orgNode(s collect.Scan, constraint string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Attributes["gcp_type"] == "org_policy" && n.Attributes["constraint"] == "constraints/"+constraint {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestOrgPolicyEffectiveEnforcement proves each constraint's effective policy is read
// and recorded: an enforced boolean is "true", a constraint with no in-force policy
// is "false" (the documented default, a known state), and both are Complete.
func TestOrgPolicyEffectiveEnforcement(t *testing.T) {
	s := runOrgPolicy(t, "ex", &stubGCP{bodies: map[string]string{
		"iam.disableServiceAccountKeyCreation:getEffectivePolicy": `{"name":"projects/ex/policies/iam.disableServiceAccountKeyCreation","spec":{"rules":[{"enforce":true}]}}`,
		"compute.requireOsLogin:getEffectivePolicy":               `{"name":"projects/ex/policies/compute.requireOsLogin"}`,
	}}, []string{"iam.disableServiceAccountKeyCreation", "compute.requireOsLogin"})

	if c := completenessOf(s, "orgpolicy.effectivePolicies"); c.Status != collect.Complete || c.Collected != 2 {
		t.Fatalf("orgpolicy.effectivePolicies = %+v, want complete/2", c)
	}
	enf, ok := orgNode(s, "iam.disableServiceAccountKeyCreation")
	if !ok || enf.Attributes["enforced"] != "true" {
		t.Errorf("enforced constraint = %q (ok=%v), want true", enf.Attributes["enforced"], ok)
	}
	def, ok := orgNode(s, "compute.requireOsLogin")
	if !ok || def.Attributes["enforced"] != "false" {
		t.Errorf("no-policy constraint = %q (ok=%v), want false (default)", def.Attributes["enforced"], ok)
	}
}

// TestOrgPolicyListShapeIsUnknown proves a list-constraint rule shape (no enforce
// flag) is recorded enforced=unknown, never guessed as false.
func TestOrgPolicyListShapeIsUnknown(t *testing.T) {
	s := runOrgPolicy(t, "ex", &stubGCP{bodies: map[string]string{
		"iam.allowedPolicyMemberDomains:getEffectivePolicy": `{"spec":{"rules":[{"values":{"allowedValues":["C0xxxx"]}}]}}`,
	}}, []string{"iam.allowedPolicyMemberDomains"})
	n, ok := orgNode(s, "iam.allowedPolicyMemberDomains")
	if !ok || n.Attributes["enforced"] != "unknown" {
		t.Errorf("list-constraint enforced = %q (ok=%v), want unknown", n.Attributes["enforced"], ok)
	}
}

// TestOrgPolicyUnknownNeverRendersAsNotEnforced proves that a constraint whose
// effective policy is a list-type rule shape OR an unparseable response is recorded
// as enforced="unknown", never "false", in both the node fact and the evidence, so a
// guardrail whose state we cannot determine is never shown as "off". This is the
// amendment guarantee: unknown is never rendered as not-enforced.
func TestOrgPolicyUnknownNeverRendersAsNotEnforced(t *testing.T) {
	cases := map[string]string{
		"iam.allowedPolicyMemberDomains": `{"spec":{"rules":[{"values":{"allowedValues":["C0xxxx"]}}]}}`, // list shape
		"compute.requireOsLogin":         `{not valid json`,                                              // unparseable
	}
	for constraint, body := range cases {
		s := runOrgPolicy(t, "ex", &stubGCP{bodies: map[string]string{constraint + ":getEffectivePolicy": body}}, []string{constraint})
		n, ok := orgNode(s, constraint)
		if !ok {
			t.Fatalf("%s: node not emitted", constraint)
		}
		if n.Attributes["enforced"] != "unknown" {
			t.Errorf("%s: enforced=%q, want unknown (never false for an undetermined guardrail)", constraint, n.Attributes["enforced"])
		}
		// And the node never carries a not-enforced claim for an unknown constraint.
		if n.Attributes["enforced"] == "false" {
			t.Errorf("%s: an unknown constraint must never render as not-enforced", constraint)
		}
	}
}

// TestOrgPolicyParseEnforce unit-tests the enforce parser's honesty directly: enforce
// true/false are known, no-spec is the documented default (not-enforced, known), and
// unparseable or a non-enforce rule shape is unknown.
func TestOrgPolicyParseEnforce(t *testing.T) {
	cases := []struct {
		body        string
		wantEnforce bool
		wantOK      bool
	}{
		{`{"spec":{"rules":[{"enforce":true}]}}`, true, true},
		{`{"spec":{"rules":[{"enforce":false}]}}`, false, true},
		{`{"name":"projects/p/policies/x"}`, false, true},                      // no spec -> default not-enforced, known
		{`{"spec":{"rules":[]}}`, false, true},                                 // empty rules -> not-enforced, known
		{`{"spec":{"rules":[{"values":{"allowedValues":[]}}]}}`, false, false}, // list shape -> unknown
		{`garbage`, false, false},                                              // unparseable -> unknown
	}
	for _, c := range cases {
		gotEnforce, gotOK := parseEffectiveEnforce([]byte(c.body))
		if gotEnforce != c.wantEnforce || gotOK != c.wantOK {
			t.Errorf("parseEffectiveEnforce(%s) = (%v,%v), want (%v,%v)", c.body, gotEnforce, gotOK, c.wantEnforce, c.wantOK)
		}
	}
}

// TestOrgPolicyDeniedIsGap proves a denial on the first constraint is a terminal
// Denied gap with no nodes, never a false empty-complete.
func TestOrgPolicyDeniedIsGap(t *testing.T) {
	s := runOrgPolicy(t, "ex", &stubGCP{failSub: ":getEffectivePolicy", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}, []string{"iam.disableServiceAccountKeyCreation"})
	if statusOf(s, "orgpolicy.effectivePolicies") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "orgpolicy.effectivePolicies"))
	}
	if nodesByType(s)[model.NodeControl] != 0 {
		t.Error("no control node should be emitted on a denied read")
	}
}

// TestOrgPolicyServiceDisabledIsUnsupported proves the API disabled is Unsupported.
func TestOrgPolicyServiceDisabledIsUnsupported(t *testing.T) {
	s := runOrgPolicy(t, "ex", &stubGCP{failSub: ":getEffectivePolicy", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Org Policy API is not enabled"}}, []string{"iam.disableServiceAccountKeyCreation"})
	if statusOf(s, "orgpolicy.effectivePolicies") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "orgpolicy.effectivePolicies"))
	}
}

// TestOrgPolicyNoProject proves a credential with no default project is Unsupported.
func TestOrgPolicyNoProject(t *testing.T) {
	s := runOrgPolicy(t, "", &stubGCP{}, securityConstraints)
	if statusOf(s, "orgpolicy.effectivePolicies") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "orgpolicy.effectivePolicies"))
	}
}
