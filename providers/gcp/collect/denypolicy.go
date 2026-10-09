package collect

import (
	"encoding/json"
	"sort"
	"strings"
)

// denyPolicyList is the subset of the IAM v2 listPolicies (deny policies) response
// we read. A deny policy denies a set of permissions to a set of principals.
type denyPolicyList struct {
	Policies []struct {
		Name  string `json:"name"`
		Rules []struct {
			DenyRule struct {
				DeniedPrincipals    []string `json:"deniedPrincipals"`
				DeniedPermissions   []string `json:"deniedPermissions"`
				ExceptionPrincipals []string `json:"exceptionPrincipals"`
			} `json:"denyRule"`
		} `json:"rules"`
	} `json:"policies"`
}

// denyLevel classifies what privilege a set of denied permissions removes, from the
// actual permissions (not names): admin when it denies all ("*") or project/folder/
// org-wide IAM control, privileged when it denies an escalation permission or any
// resource's setIamPolicy. A deny at this level removes an effective grant at or
// below it (consumed by the Step 4 engine as deny_privilege_level). Denied
// permissions carry a "service.googleapis.com/" prefix, stripped before matching.
func denyLevel(deniedPermissions []string) string {
	admin := false
	esc := false
	for _, p := range deniedPermissions {
		lp := strings.ToLower(bareDenyPermission(p))
		if lp == "*" || gcpAdminPerms[lp] {
			admin = true
		}
		if gcpEscalationPerms[lp] || strings.HasSuffix(lp, ".setiampolicy") {
			esc = true
		}
	}
	switch {
	case admin:
		return "admin"
	case esc:
		return "privileged"
	default:
		return ""
	}
}

// bareDenyPermission strips the "service.googleapis.com/" prefix a deny policy uses
// (e.g. "iam.googleapis.com/roles.create" to "iam.roles.create"), so it matches the
// permission form roles.get returns. A "*" is left as is.
func bareDenyPermission(p string) string {
	i := strings.Index(p, ".googleapis.com/")
	if i < 0 {
		return p
	}
	service := p[:i]
	rest := p[i+len(".googleapis.com/"):]
	return service + "." + rest
}

// denyPrincipalKey maps a deny-policy principal identifier to the native id the
// allow-policy member nodes use, so a deny lands on the same principal node the
// grant did. Deny policies identify principals as "principal://.../{email}" or
// "principalSet://goog/public:all" (all users); the email tail is extracted to
// match the bare-email keying, and an unrecognized identifier is kept verbatim so a
// deny is never dropped, only unjoined.
func denyPrincipalKey(identifier string) string {
	switch identifier {
	case "principalSet://goog/public:all":
		return "allUsers"
	case "principalSet://goog/public:all_authenticated":
		return "allAuthenticatedUsers"
	}
	if i := strings.LastIndex(identifier, "/"); i >= 0 && i+1 < len(identifier) {
		tail := identifier[i+1:]
		if strings.Contains(tail, "@") { // an email (user or service account)
			return tail
		}
	}
	return identifier
}

// denyLevels folds a deny-policy list into the highest deny level per affected
// principal native id, deterministically. It is a pure function of the response, so
// it is unit-tested without the network.
func denyLevels(list denyPolicyList) map[string]string {
	out := map[string]string{}
	for _, pol := range list.Policies {
		for _, r := range pol.Rules {
			level := denyLevel(r.DenyRule.DeniedPermissions)
			if level == "" {
				continue
			}
			for _, principal := range r.DenyRule.DeniedPrincipals {
				key := denyPrincipalKey(principal)
				if higherDeny(out[key], level) == level {
					out[key] = level
				}
			}
		}
	}
	return out
}

// higherDeny returns the more privileged of two deny levels (admin > privileged > "").
func higherDeny(a, b string) string {
	rank := map[string]int{"": 0, "privileged": 1, "admin": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// parseDenyPolicies decodes a deny-policy list body, returning ok=false on a
// malformed body so an unreadable response is an honest non-result.
func parseDenyPolicies(body []byte) (denyPolicyList, bool) {
	var l denyPolicyList
	if json.Unmarshal(body, &l) != nil {
		return denyPolicyList{}, false
	}
	return l, true
}

// sortedKeys returns a map's keys in sorted order, for deterministic emission.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
