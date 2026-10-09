package collect

import (
	"encoding/json"
	"sort"
	"strings"
)

// gcpAdminPerms are permissions that grant project-, folder-, or organization-wide
// IAM control: whoever holds one can grant themselves or anyone else any role, so a
// role that includes one is administrator-equivalent. Derived from the IAM
// permission reference, matched literally against a role's includedPermissions.
var gcpAdminPerms = map[string]bool{
	"resourcemanager.projects.setiampolicy":      true,
	"resourcemanager.folders.setiampolicy":       true,
	"resourcemanager.organizations.setiampolicy": true,
}

// gcpEscalationPerms are permissions that let a principal raise privilege short of
// full IAM control: impersonate a service account, mint its credentials, or modify
// role definitions. A role that includes any is flagged privileged. Any other
// "*.setIamPolicy" permission (on a specific resource) is also treated as
// escalation, computed in classifyRole.
var gcpEscalationPerms = map[string]bool{
	"iam.serviceaccounts.actas":              true,
	"iam.serviceaccounts.getaccesstoken":     true,
	"iam.serviceaccounts.getopenidtoken":     true,
	"iam.serviceaccounts.implicitdelegation": true,
	"iam.serviceaccounts.signblob":           true,
	"iam.serviceaccounts.signjwt":            true,
	"iam.serviceaccountkeys.create":          true,
	"iam.roles.create":                       true,
	"iam.roles.update":                       true,
}

// roleDefinition is the subset of the roles.get response we read.
type roleDefinition struct {
	Name                string   `json:"name"`
	IncludedPermissions []string `json:"includedPermissions"`
	Stage               string   `json:"stage"`
}

// classifyRole derives a role's privilege from its actual included permissions
// (not its name): admin when it grants project/folder/org-wide IAM control,
// privileged when it grants an escalation or any resource's setIamPolicy. It
// returns the level ("admin"/"privileged"/"") and the sorted escalation
// permissions found, so the basis is auditable.
func classifyRole(perms []string) (level string, escalation []string) {
	admin := false
	esc := map[string]bool{}
	for _, p := range perms {
		lp := strings.ToLower(p)
		if gcpAdminPerms[lp] {
			admin = true
		}
		if gcpEscalationPerms[lp] || strings.HasSuffix(lp, ".setiampolicy") {
			esc[lp] = true
		}
	}
	for k := range esc {
		escalation = append(escalation, k)
	}
	sort.Strings(escalation)
	switch {
	case admin:
		return "admin", escalation
	case len(escalation) > 0:
		return "privileged", escalation
	default:
		return "", escalation
	}
}

// parseRoleDefinition decodes a roles.get body, returning ok=false on a malformed
// body so an unreadable role is an honest non-classification, never a silent
// "not privileged".
func parseRoleDefinition(body []byte) (roleDefinition, bool) {
	var r roleDefinition
	if json.Unmarshal(body, &r) != nil {
		return roleDefinition{}, false
	}
	return r, true
}
