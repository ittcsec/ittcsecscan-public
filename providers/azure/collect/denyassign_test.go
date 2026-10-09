package collect

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// TestDenyAssignmentStampsPrincipal proves a deny-assignment denying full actions to
// a principal stamps deny_privilege_level=admin on that principal's node (keyed by
// object id, so it merges with the RBAC assignment's principal), with the deny read
// reported Complete.
func TestDenyAssignmentStampsPrincipal(t *testing.T) {
	deny := `{"value":[{"properties":{
		"principals":[{"id":"u-guid","type":"User"}],
		"permissions":[{"actions":["*"]}]}}]}`
	s := runRBAC(t, &stubARM{bodies: map[string]string{
		"/subscriptions?":   subsOne,
		"/roleDefinitions?": roleDefsTwo,
		"/roleAssignments?": assignmentsTwo,
		"/denyAssignments?": deny,
	}})

	// The deny collector emits its own node for the principal (the graph attribute
	// merge combines it with the RBAC assignment's node), so scan all nodes.
	var stamped bool
	for _, n := range s.Nodes {
		if n.NativeID == "u-guid" && n.Attributes["deny_privilege_level"] == "admin" {
			stamped = true
		}
	}
	if !stamped {
		t.Error("deny-assignment did not stamp deny_privilege_level=admin on u-guid")
	}
	if statusOf(s, "rbac.denyAssignments") != collect.Complete {
		t.Errorf("rbac.denyAssignments status = %s, want complete", statusOf(s, "rbac.denyAssignments"))
	}
}

// TestDenyAssignmentReadOnlyActionsNoStamp proves a deny of only read actions
// removes no privilege, so no deny fact is stamped.
func TestDenyAssignmentReadOnlyActionsNoStamp(t *testing.T) {
	deny := `{"value":[{"properties":{
		"principals":[{"id":"u-guid","type":"User"}],
		"permissions":[{"actions":["*/read"]}]}}]}`
	s := runRBAC(t, &stubARM{bodies: map[string]string{
		"/subscriptions?":   subsOne,
		"/roleDefinitions?": roleDefsTwo,
		"/roleAssignments?": assignmentsTwo,
		"/denyAssignments?": deny,
	}})
	for _, n := range s.Nodes {
		if _, has := n.Attributes["deny_privilege_level"]; has {
			t.Errorf("a read-only deny wrongly stamped a deny level on %s", n.NativeID)
		}
	}
}
