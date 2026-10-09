package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func runSecDefaults(t *testing.T, api graphAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newSecurityDefaultsCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestSecurityDefaultsEnabled proves the enforcement policy becomes a control node
// carrying security_defaults_enabled, and the read is Complete.
func TestSecurityDefaultsEnabled(t *testing.T) {
	s := runSecDefaults(t, &stubGraph{bodies: map[string]string{
		"identitySecurityDefaultsEnforcementPolicy": `{"id":"default","displayName":"Security Defaults","isEnabled":true}`,
	}})
	if c := completenessOf(s, "entra.securityDefaults"); c.Status != collect.Complete || c.Collected != 1 {
		t.Fatalf("entra.securityDefaults = %+v, want complete/1", c)
	}
	var n collect.Node
	for _, x := range s.Nodes {
		if x.Type == model.NodeControl && x.Attributes["azure_type"] == "security_defaults" {
			n = x
		}
	}
	if n.Attributes["security_defaults_enabled"] != "true" {
		t.Errorf("security_defaults_enabled = %q, want true", n.Attributes["security_defaults_enabled"])
	}
}

// TestSecurityDefaultsDisabledIsRecorded proves a disabled policy is recorded as the
// fact "false", not dropped (a disabled baseline is the security-relevant state).
func TestSecurityDefaultsDisabledIsRecorded(t *testing.T) {
	s := runSecDefaults(t, &stubGraph{bodies: map[string]string{
		"identitySecurityDefaultsEnforcementPolicy": `{"id":"default","isEnabled":false}`,
	}})
	var n collect.Node
	for _, x := range s.Nodes {
		if x.Attributes["azure_type"] == "security_defaults" {
			n = x
		}
	}
	if n.Attributes["security_defaults_enabled"] != "false" {
		t.Errorf("security_defaults_enabled = %q, want false", n.Attributes["security_defaults_enabled"])
	}
}

// TestSecurityDefaultsDeniedIsGap proves a denied read is Denied with no node.
func TestSecurityDefaultsDeniedIsGap(t *testing.T) {
	s := runSecDefaults(t, &stubGraph{failSub: "identitySecurityDefaults", failWith: &azureError{status: 403, body: "denied"}})
	if statusOf(s, "entra.securityDefaults") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "entra.securityDefaults"))
	}
	if nodesByType(s)[model.NodeControl] != 0 {
		t.Error("no control node should be emitted on a denied read")
	}
}
