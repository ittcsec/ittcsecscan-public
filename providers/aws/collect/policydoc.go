package collect

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// escalationActions is the fixed, documented set of IAM actions that let a
// principal raise its own or another principal's privilege (attach or embed a
// policy, create credentials, pass a role, assume a role, change a policy
// version). A policy that Allows any of these is flagged as privileged; the set
// is derived from AWS's own privilege-escalation guidance, not guessed, and is
// matched literally or through a policy action wildcard.
var escalationActions = []string{
	"iam:addusertogroup",
	"iam:attachgrouppolicy",
	"iam:attachrolepolicy",
	"iam:attachuserpolicy",
	"iam:createaccesskey",
	"iam:createloginprofile",
	"iam:createpolicyversion",
	"iam:passrole",
	"iam:putgrouppolicy",
	"iam:putrolepolicy",
	"iam:putuserpolicy",
	"iam:setdefaultpolicyversion",
	"iam:updateassumerolepolicy",
	"iam:updateloginprofile",
	"sts:assumerole",
}

// policyClass is the privilege classification of one policy document: whether it
// is administrator-equivalent (Allow "*" on "*") and which escalation actions it
// grants. Both are derived deterministically from the document's Allow statements.
type policyClass struct {
	adminEquivalent bool
	escalation      []string // sorted, deduplicated members of escalationActions the policy allows
}

// level maps a classification to the privilege_level fact: admin (full wildcard),
// privileged (grants an escalation action), or empty (neither).
func (c policyClass) level() string {
	switch {
	case c.adminEquivalent:
		return "admin"
	case len(c.escalation) > 0:
		return "privileged"
	default:
		return ""
	}
}

type policyStatement struct {
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition"`
}

// classifyPolicy parses an IAM policy document (URL-encoded JSON, as the IAM API
// returns it) and classifies its Allow statements. It returns ok=false when the
// document cannot be parsed, so a malformed document is an honest non-result, never
// a silent "not privileged".
func classifyPolicy(doc string) (cls policyClass, ok bool) {
	stmts, ok := parseStatements(doc)
	if !ok {
		return policyClass{}, false
	}
	esc := map[string]bool{}
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		actions := lowerAll(stringOrSlice(s.Action))
		resources := stringOrSlice(s.Resource)
		if hasExact(actions, "*") && hasExact(resources, "*") {
			cls.adminEquivalent = true
		}
		for _, ea := range escalationActions {
			if actionAllowed(actions, ea) {
				esc[ea] = true
			}
		}
	}
	for k := range esc {
		cls.escalation = append(cls.escalation, k)
	}
	sort.Strings(cls.escalation)
	return cls, true
}

// parseStatements decodes a policy document's Statement list, handling both a
// single object and an array.
func parseStatements(doc string) ([]policyStatement, bool) {
	decoded := doc
	if d, err := url.PathUnescape(doc); err == nil {
		decoded = d
	}
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(decoded), &parsed) != nil || len(parsed.Statement) == 0 {
		return nil, false
	}
	var arr []policyStatement
	if json.Unmarshal(parsed.Statement, &arr) == nil {
		return arr, true
	}
	var one policyStatement
	if json.Unmarshal(parsed.Statement, &one) == nil {
		return []policyStatement{one}, true
	}
	return nil, false
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

// actionAllowed reports whether a set of policy action patterns allows target (a
// lowercase "service:action"). A pattern matches if it equals target, is the full
// "*", or globs onto it with "*" wildcards (for example "iam:*" or "iam:put*").
func actionAllowed(patterns []string, target string) bool {
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

// globMatch reports whether pattern (with "*" wildcards) matches s. It is a small,
// deterministic matcher: no regex, no backtracking beyond the segment walk.
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

// inlinePrivilege classifies the union of a principal's inline policies: the
// highest privilege any inline policy grants. Inline policies are embedded in the
// principal's authorization detail, so this needs no extra API call.
func inlinePrivilege(inline []iamtypes.PolicyDetail) string {
	best := ""
	for _, p := range inline {
		cls, ok := classifyPolicy(deref(p.PolicyDocument))
		if !ok {
			continue
		}
		best = higher(best, cls.level())
	}
	return best
}

// higher returns the more privileged of two levels (admin > privileged > "").
func higher(a, b string) string {
	rank := map[string]int{"": 0, "privileged": 1, "admin": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// principalAuthzAttrs returns the authorization facts a principal carries from its
// own detail: the privilege its inline policies grant, and the ARN of its
// permission boundary (which caps its effective permissions). Both come from the
// principal's authorization detail, so this needs no extra API call.
func principalAuthzAttrs(inlineLevel string, boundary *iamtypes.AttachedPermissionsBoundary) []string {
	var out []string
	if inlineLevel != "" {
		out = append(out, "inline_privilege", inlineLevel)
	}
	if boundary != nil {
		if arn := deref(boundary.PermissionsBoundaryArn); arn != "" {
			out = append(out, "permission_boundary", arn)
		}
	}
	return out
}

// defaultPolicyDocument returns a managed policy's default version document, which
// GetAccountAuthorizationDetails already returns inline (no GetPolicyVersion call).
func defaultPolicyDocument(p iamtypes.ManagedPolicyDetail) string {
	def := deref(p.DefaultVersionId)
	for _, v := range p.PolicyVersionList {
		if v.IsDefaultVersion || deref(v.VersionId) == def {
			return deref(v.Document)
		}
	}
	return ""
}
