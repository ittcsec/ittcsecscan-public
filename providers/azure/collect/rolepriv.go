package collect

import (
	"sort"
	"strings"
)

// azurePermission is one permission block of an ARM role definition: the control-
// plane actions it allows and excludes. Data-plane actions are read too but do not
// change the privilege classification, which is about control over the resource
// and its access.
type azurePermission struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

// classifyAzureRole derives a role's privilege from its actual permission blocks
// (not its name): admin when it can do everything including manage access (an
// Owner-like "*" without the access-management exclusion), privileged when it can
// grant role assignments (privilege escalation) or holds a full "*" wildcard whose
// access management is excluded (a Contributor-like broad grant). It returns the
// level and the sorted escalation reasons, so the basis is auditable.
func classifyAzureRole(perms []azurePermission) (level string, escalation []string) {
	var actions, notActions []string
	for _, p := range perms {
		actions = append(actions, p.Actions...)
		notActions = append(notActions, p.NotActions...)
	}
	la := lowerAll(actions)
	ln := lowerAll(notActions)

	full := hasExact(la, "*")
	managesAccess := actionMatches(la, "microsoft.authorization/roleassignments/write") && !actionMatches(ln, "microsoft.authorization/roleassignments/write")

	esc := map[string]bool{}
	if managesAccess {
		esc["microsoft.authorization/roleassignments/write"] = true
	}
	if actionMatches(la, "microsoft.authorization/elevateaccess/action") && !actionMatches(ln, "microsoft.authorization/elevateaccess/action") {
		esc["microsoft.authorization/elevateaccess/action"] = true
	}
	for k := range esc {
		escalation = append(escalation, k)
	}
	sort.Strings(escalation)

	switch {
	case full && managesAccess:
		return "admin", escalation
	case full || managesAccess || len(escalation) > 0:
		return "privileged", escalation
	default:
		return "", escalation
	}
}

func lowerAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

func hasExact(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// actionMatches reports whether any pattern (with Azure "*" wildcards) covers the
// target action. Azure actions use "*" as a wildcard segment, so "*",
// "microsoft.authorization/*", and "microsoft.authorization/*/write" all cover
// "microsoft.authorization/roleassignments/write".
func actionMatches(patterns []string, target string) bool {
	for _, p := range patterns {
		if p == "*" || p == target {
			return true
		}
		if strings.Contains(p, "*") && globMatch(p, target) {
			return true
		}
	}
	return false
}

// globMatch reports whether pattern (with "*" wildcards) matches s, deterministically.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
