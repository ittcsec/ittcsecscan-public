package collect

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

func TestClassifyRoleAdmin(t *testing.T) {
	lvl, _ := classifyRole([]string{"resourcemanager.projects.get", "resourcemanager.projects.setIamPolicy"})
	if lvl != "admin" {
		t.Errorf("project setIamPolicy => %q, want admin", lvl)
	}
}

func TestClassifyRolePrivilegedEscalation(t *testing.T) {
	lvl, esc := classifyRole([]string{"iam.serviceAccounts.actAs", "storage.objects.get"})
	if lvl != "privileged" {
		t.Errorf("actAs => %q, want privileged", lvl)
	}
	if len(esc) != 1 || esc[0] != "iam.serviceaccounts.actas" {
		t.Errorf("escalation = %v, want [iam.serviceaccounts.actas]", esc)
	}
}

func TestClassifyRoleAnySetIamPolicyIsEscalation(t *testing.T) {
	lvl, esc := classifyRole([]string{"storage.buckets.setIamPolicy"})
	if lvl != "privileged" || len(esc) != 1 {
		t.Errorf("a resource setIamPolicy should be privileged escalation: lvl=%q esc=%v", lvl, esc)
	}
}

func TestClassifyRoleNonPrivileged(t *testing.T) {
	lvl, esc := classifyRole([]string{"storage.objects.get", "storage.objects.list", "compute.instances.get"})
	if lvl != "" || len(esc) != 0 {
		t.Errorf("read-only role classified privileged: lvl=%q esc=%v", lvl, esc)
	}
}

func TestParseRoleDefinitionMalformed(t *testing.T) {
	if _, ok := parseRoleDefinition([]byte("not json")); ok {
		t.Error("malformed role must return ok=false, not a silent empty definition")
	}
}

// TestRolePrivilegeEndToEnd proves a role bound in the policy is fetched, its
// permissions classified, and privilege_level stamped on the role node, with the
// role-definition read reported Complete.
func TestRolePrivilegeEndToEnd(t *testing.T) {
	binding := `{"bindings":[{"role":"roles/owner","members":["user:alice@example.com"]}]}`
	api := &stubPolicy{
		body:  binding,
		roles: map[string]string{"roles/owner": `{"name":"roles/owner","includedPermissions":["resourcemanager.projects.setIamPolicy","iam.serviceAccounts.actAs"]}`},
	}
	s := runPolicy(t, "proj", api)
	for _, n := range s.Nodes {
		if n.NativeID == "roles/owner" {
			if n.Attributes["privilege_level"] != "admin" {
				t.Errorf("roles/owner privilege_level = %q, want admin", n.Attributes["privilege_level"])
			}
			if n.Attributes["permissions_read"] != "true" {
				t.Error("roles/owner missing permissions_read fact")
			}
		}
	}
	if statusOf(s, "iam.roleDefinitions") != collect.Complete {
		t.Errorf("iam.roleDefinitions status = %s, want complete", statusOf(s, "iam.roleDefinitions"))
	}
}

// TestRolePrivilegeDeniedIsHonest proves a denied roles.get is an honest gap: the
// role node carries no privilege_level (never a silent "not privileged"), and the
// role-definition completeness is Denied.
func TestRolePrivilegeDeniedIsHonest(t *testing.T) {
	binding := `{"bindings":[{"role":"roles/owner","members":["user:alice@example.com"]}]}`
	api := &stubPolicy{body: binding, roleErr: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	s := runPolicy(t, "proj", api)
	for _, n := range s.Nodes {
		if n.NativeID == "roles/owner" {
			if _, ok := n.Attributes["privilege_level"]; ok {
				t.Error("a role whose definition read was denied must not carry a privilege_level")
			}
		}
	}
	if statusOf(s, "iam.roleDefinitions") != collect.Denied {
		t.Errorf("iam.roleDefinitions status = %s, want denied", statusOf(s, "iam.roleDefinitions"))
	}
}
