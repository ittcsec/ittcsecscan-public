package store

import (
	"slices"
	"testing"
)

// Stored codes are part of the file format: a code's number never changes,
// and the lists only ever grow at the end. Changing an entry here needs a
// contract migration, which ADR-0012 gates.
func TestStoredCodesArePinned(t *testing.T) {
	for name, c := range map[string]struct {
		list codeList
		want []string
	}{
		"providers": {providerCodes, []string{"aws", "azure", "gcp", "github", "gitlab", "kubernetes", "okta", "google_workspace", "mcp"}},
		"node types": {nodeTypeCodes, []string{
			"account", "subscription", "project", "organization", "tenant",
			"identity", "group", "role", "policy", "credential", "token",
			"workload", "compute", "network", "endpoint", "gateway", "api",
			"data_store", "secret_store", "repository", "pipeline", "artifact",
			"cluster", "namespace", "service", "ai_model", "ai_agent",
			"mcp_server", "tool", "endpoint_device", "vulnerability", "control",
			"business_asset",
		}},
		"edge kinds": {edgeKindCodes, []string{
			"member_of", "assumes", "can_impersonate", "can_create_credential",
			"can_modify_policy", "can_execute_on", "can_read", "can_write",
			"can_delete", "can_exfiltrate", "exposed_to", "routes_to",
			"resolves_to", "trusts", "federates_with", "deploys", "builds",
			"contains_secret", "accesses_data", "invokes_tool", "controls_agent",
			"bypasses_control", "monitored_by", "protected_by", "contains",
		}},
		"scan statuses": {scanStatusCodes, []string{"running", "completed", "failed", "incomplete"}},
		"changes":       {changeCodes, []string{"appeared", "changed", "disappeared"}},
		"freshness":     {freshnessCodes, []string{"fresh", "stale", "unknown"}},
		"completeness":  {completenessCodes, []string{"complete", "partial", "unknown"}},
		"rule outcomes": {outcomeCodes, []string{"pass", "fail", "unknown", "error", "not_applicable"}},
		"scope reasons": {scopeReasonCodes, []string{"denied", "unsupported", "error"}},
	} {
		if !slices.Equal(c.list, c.want) {
			t.Errorf("%s: %q, want %q", name, c.list, c.want)
		}
		for i, n := range c.list {
			if code, ok := c.list.code(n); !ok || code != int64(i)+1 || slices.Index(c.list, n) != i {
				t.Errorf("%s: %q has code %d, want %d, and must be unique", name, n, code, i+1)
			}
		}
		if c.list.valid(0) || !c.list.valid(1) || c.list.valid(int64(len(c.list))+1) {
			t.Errorf("%s: valid codes must be exactly 1 to %d", name, len(c.list))
		}
	}
	if len(nodeTypeCodes) != 33 || len(edgeKindCodes) != 25 {
		t.Errorf("the canonical model lists 33 node types and 24 edge types plus expansion edges; the codes have %d and %d", len(nodeTypeCodes), len(edgeKindCodes))
	}
}
