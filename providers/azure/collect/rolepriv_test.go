package collect

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func TestClassifyAzureRoleOwner(t *testing.T) {
	// Owner: full "*" and no access-management exclusion => admin.
	lvl, _ := classifyAzureRole([]azurePermission{{Actions: []string{"*"}}})
	if lvl != "admin" {
		t.Errorf("Owner ([*]) => %q, want admin", lvl)
	}
}

func TestClassifyAzureRoleContributor(t *testing.T) {
	// Contributor: full "*" but access management excluded => privileged, not admin.
	lvl, _ := classifyAzureRole([]azurePermission{{
		Actions:    []string{"*"},
		NotActions: []string{"Microsoft.Authorization/*/Write", "Microsoft.Authorization/*/Delete", "Microsoft.Authorization/elevateAccess/Action"},
	}})
	if lvl != "privileged" {
		t.Errorf("Contributor => %q, want privileged (full but cannot manage access)", lvl)
	}
}

func TestClassifyAzureRoleUserAccessAdmin(t *testing.T) {
	// Can grant role assignments => privilege escalation.
	lvl, esc := classifyAzureRole([]azurePermission{{Actions: []string{"*/read", "Microsoft.Authorization/*"}}})
	if lvl != "privileged" {
		t.Errorf("User Access Administrator => %q, want privileged", lvl)
	}
	if len(esc) == 0 {
		t.Error("access-management role recorded no escalation basis")
	}
}

func TestClassifyAzureRoleReader(t *testing.T) {
	lvl, esc := classifyAzureRole([]azurePermission{{Actions: []string{"*/read"}}})
	if lvl != "" || len(esc) != 0 {
		t.Errorf("Reader classified privileged: lvl=%q esc=%v", lvl, esc)
	}
}

func TestClassifyAzureRoleExplicitAssignmentWrite(t *testing.T) {
	lvl, esc := classifyAzureRole([]azurePermission{{Actions: []string{"Microsoft.Authorization/roleAssignments/write"}}})
	if lvl != "privileged" || len(esc) == 0 {
		t.Errorf("explicit roleAssignments/write => lvl=%q esc=%v, want privileged with escalation", lvl, esc)
	}
}

// TestRBACStampsPrivilegeLevel proves the collector stamps a grounded
// privilege_level on the role node from the definition's actions.
func TestRBACStampsPrivilegeLevel(t *testing.T) {
	roleDefs := `{"value":[
		{"name":"` + ownerGUID + `","properties":{"roleName":"Owner","type":"BuiltInRole","permissions":[{"actions":["*"]}]}},
		{"name":"` + contributorGUID + `","properties":{"roleName":"Contributor","type":"BuiltInRole","permissions":[{"actions":["*"],"notActions":["Microsoft.Authorization/*/Write","Microsoft.Authorization/elevateAccess/Action"]}]}}]}`
	s := runRBAC(t, &stubARM{bodies: map[string]string{
		"/subscriptions?":   subsOne,
		"/roleDefinitions?": roleDefs,
		"/roleAssignments?": assignmentsTwo,
	}})
	if n, _ := nodeNamed(s, model.NodeRole, ownerGUID); n.Attributes["privilege_level"] != "admin" {
		t.Errorf("Owner privilege_level = %q, want admin", n.Attributes["privilege_level"])
	}
	if n, _ := nodeNamed(s, model.NodeRole, contributorGUID); n.Attributes["privilege_level"] != "privileged" {
		t.Errorf("Contributor privilege_level = %q, want privileged", n.Attributes["privilege_level"])
	}
}
