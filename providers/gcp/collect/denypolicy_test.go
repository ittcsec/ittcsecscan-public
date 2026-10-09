package collect

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

func TestBareDenyPermission(t *testing.T) {
	if got := bareDenyPermission("iam.googleapis.com/roles.create"); got != "iam.roles.create" {
		t.Errorf("bareDenyPermission = %q, want iam.roles.create", got)
	}
	if got := bareDenyPermission("*"); got != "*" {
		t.Errorf("bareDenyPermission(*) = %q, want *", got)
	}
}

func TestDenyLevel(t *testing.T) {
	if lvl := denyLevel([]string{"iam.googleapis.com/roles.list"}); lvl != "" {
		t.Errorf("denying a read permission = %q, want none", lvl)
	}
	if lvl := denyLevel([]string{"resourcemanager.googleapis.com/projects.setIamPolicy"}); lvl != "admin" {
		t.Errorf("denying project setIamPolicy = %q, want admin", lvl)
	}
	if lvl := denyLevel([]string{"iam.googleapis.com/serviceAccounts.actAs"}); lvl != "privileged" {
		t.Errorf("denying actAs = %q, want privileged", lvl)
	}
	if lvl := denyLevel([]string{"*"}); lvl != "admin" {
		t.Errorf("denying * = %q, want admin", lvl)
	}
}

func TestDenyPrincipalKey(t *testing.T) {
	cases := map[string]string{
		"principalSet://goog/public:all": "allUsers",
		"principal://iam.googleapis.com/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com": "sa@p.iam.gserviceaccount.com",
		"principal://goog/subject/alice@example.com":                                             "alice@example.com",
		"principalSet://cloudresourcemanager.googleapis.com/projects/p":                          "principalSet://cloudresourcemanager.googleapis.com/projects/p",
	}
	for in, want := range cases {
		if got := denyPrincipalKey(in); got != want {
			t.Errorf("denyPrincipalKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDenyPolicyStampsPrincipal proves a deny policy denying an admin permission to
// a principal stamps deny_privilege_level=admin on that principal's node, keyed to
// match the allow-policy member node, with the deny read reported Complete.
func TestDenyPolicyStampsPrincipal(t *testing.T) {
	binding := `{"bindings":[{"role":"roles/owner","members":["user:alice@example.com"]}]}`
	deny := `{"policies":[{"name":"p","rules":[{"denyRule":{
		"deniedPrincipals":["principal://goog/subject/alice@example.com"],
		"deniedPermissions":["resourcemanager.googleapis.com/projects.setIamPolicy"]}}]}]}`
	s := runPolicy(t, "proj", &stubPolicy{body: binding, deny: deny})

	var stamped bool
	for _, n := range s.Nodes {
		if n.NativeID == "alice@example.com" && n.Attributes["deny_privilege_level"] == "admin" {
			stamped = true
		}
	}
	if !stamped {
		t.Error("deny policy did not stamp deny_privilege_level=admin on the denied principal")
	}
	if statusOf(s, "iam.denyPolicies") != collect.Complete {
		t.Errorf("iam.denyPolicies status = %s, want complete", statusOf(s, "iam.denyPolicies"))
	}
}

// TestDenyPolicyDeniedIsHonest proves a denied deny-policy read is an honest gap.
func TestDenyPolicyDeniedIsHonest(t *testing.T) {
	s := runPolicy(t, "proj", &stubPolicy{
		body:    `{"bindings":[]}`,
		denyErr: &gcpError{status: 403, body: "PERMISSION_DENIED"},
	})
	if statusOf(s, "iam.denyPolicies") != collect.Denied {
		t.Errorf("iam.denyPolicies status = %s, want denied", statusOf(s, "iam.denyPolicies"))
	}
}
