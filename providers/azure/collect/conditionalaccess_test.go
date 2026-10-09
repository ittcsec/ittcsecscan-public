package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func runCA(t *testing.T, api graphAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newConditionalAccessCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestConditionalAccessPoliciesMapped proves real CA policies become control nodes
// with their state and condition/grant-control facts, and the read is Complete.
func TestConditionalAccessPoliciesMapped(t *testing.T) {
	s := runCA(t, &stubGraph{bodies: map[string]string{
		"conditionalAccess/policies": `{"value":[{"id":"p1","displayName":"Require MFA","state":"enabled","conditions":{"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]}`,
	}})
	if c := completenessOf(s, "entra.conditionalAccess"); c.Status != collect.Complete || c.Collected != 1 {
		t.Fatalf("entra.conditionalAccess = %+v, want complete/1", c)
	}
	var n collect.Node
	for _, x := range s.Nodes {
		if x.Attributes["azure_type"] == "conditional_access_policy" {
			n = x
		}
	}
	if n.Attributes["state"] != "enabled" || n.Attributes["grant_controls"] == "" {
		t.Errorf("CA policy facts = %+v", n.Attributes)
	}
}

// TestConditionalAccessEmptyIsUnsupported proves an empty list (the unlicensed-tenant
// case) is Unsupported, never Complete and never a pass, with no node. This is the
// ADR-0036 amendment guarantee.
func TestConditionalAccessEmptyIsUnsupported(t *testing.T) {
	s := runCA(t, &stubGraph{bodies: map[string]string{"conditionalAccess/policies": `{"value":[]}`}})
	c := completenessOf(s, "entra.conditionalAccess")
	if c.Status != collect.Unsupported {
		t.Errorf("empty CA list = %s, want unsupported (never complete/pass)", c.Status)
	}
	if nodesByType(s)[model.NodeControl] != 0 {
		t.Error("no control node should be emitted for an empty CA list")
	}
}

// TestConditionalAccessLicensingErrorIsUnsupported proves a licensing error is
// Unsupported, not Denied and not Errored.
func TestConditionalAccessLicensingErrorIsUnsupported(t *testing.T) {
	s := runCA(t, &stubGraph{failSub: "conditionalAccess/policies", failWith: &azureError{status: 403, body: "Conditional Access requires an Azure AD Premium license"}})
	if statusOf(s, "entra.conditionalAccess") != collect.Unsupported {
		t.Errorf("licensing error = %s, want unsupported", statusOf(s, "entra.conditionalAccess"))
	}
}

// TestConditionalAccessDeniedIsGap proves a plain permission denial (no licensing
// signal) is Denied, so a real missing-permission is never hidden as Unsupported.
func TestConditionalAccessDeniedIsGap(t *testing.T) {
	s := runCA(t, &stubGraph{failSub: "conditionalAccess/policies", failWith: &azureError{status: 403, body: "Authorization_RequestDenied: Insufficient privileges"}})
	if statusOf(s, "entra.conditionalAccess") != collect.Denied {
		t.Errorf("plain denial = %s, want denied", statusOf(s, "entra.conditionalAccess"))
	}
}
