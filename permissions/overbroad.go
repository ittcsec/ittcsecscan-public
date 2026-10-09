package permissions

import "sort"

// Excess returns the permissions that are granted to the scanner but that the
// template does not require: the overbroad permissions to warn about (master
// plan a later milestone). It is a pure set difference, sorted and de-duplicated.
//
// Obtaining the actually-granted permissions needs a provider IAM query, which
// is itself a permissioned call and arrives with the collectors; until then this
// function has no caller in production. It is report-only: an overbroad
// permission is a warning, never a refusal, and against an empty template every
// grant would be "excess", so no warning is emitted until a template is
// populated.
func Excess(granted []string, t Template) []string {
	need := make(map[string]bool, len(t.Permissions))
	for _, e := range t.Permissions {
		need[e.Permission] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range granted {
		if !need[g] && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}
