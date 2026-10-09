package collect

import (
	"encoding/json"
	"net/url"
	"strings"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// attachmentEdges emits, for a principal (user, group, or role), a grant edge to
// each managed policy attached to it: the principal assumes (wields) the policy's
// permissions. The policy is also emitted as a node so the edge resolves even
// when it is an AWS-managed policy not present in the Policies list; the store
// dedups it with the full policy node when one exists.
func (c *IdentityCollector) attachmentEdges(sink collect.Sink, principalArn string, attached []iamtypes.AttachedPolicy) {
	if principalArn == "" {
		return
	}
	for _, ap := range attached {
		arn := deref(ap.PolicyArn)
		if arn == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodePolicy, NativeID: arn, Name: deref(ap.PolicyName)})
		_ = sink.Link(collect.Link{SourceNativeID: principalArn, TargetNativeID: arn, Kind: model.EdgeAssumes})
	}
}

// trustEdges parses a role's trust policy and emits, for each principal it allows,
// a grant edge: the principal can assume the role. Each trusted principal is also
// emitted as a node so the edge resolves (external principals are new nodes;
// internal ones dedup with the identity pass).
func (c *IdentityCollector) trustEdges(sink collect.Sink, roleArn, doc string) {
	if roleArn == "" || doc == "" {
		return
	}
	decoded := doc
	if d, err := url.PathUnescape(doc); err == nil {
		decoded = d
	}
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(decoded), &d) != nil {
		return
	}
	for _, s := range trustStatements(d.Statement) {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		cond := conditionString(s.Condition)
		for _, p := range principalsOf(s.Principal) {
			node, ok := principalNode(p)
			if !ok {
				continue
			}
			_ = sink.Node(node)
			link := collect.Link{SourceNativeID: node.NativeID, TargetNativeID: roleArn, Kind: model.EdgeAssumes}
			if cond != "" {
				// The trust may apply only under a condition (an external-id or
				// source-account gate); record it so the edge is not read as
				// unconditional. The condition is carried opaquely, not evaluated.
				link.Conditions = map[string]string{"trust_condition": cond}
			}
			_ = sink.Link(link)

			// Cross-domain join (ADR-0031, EX-2b): when the federated principal is the
			// GitHub Actions OIDC provider and the trust condition names a repository in
			// its sub claim, emit a federates_with edge from that GitHub repository
			// (keyed by owner/repo, the same native id the GitHub repositories collector
			// emits) to the role. In a scan that also collects GitHub, this links the
			// repository-to-pipeline-to-artifact graph into the cloud role and its
			// workload; in an AWS-only scan the edge has no GitHub endpoint and is
			// dropped by normalize. The repo comes only from the signed trust policy,
			// never guessed.
			if p.typ == "federated" && strings.Contains(p.value, githubActionsOIDCHost) {
				for _, repo := range githubReposFromCondition(s.Condition) {
					_ = sink.Link(collect.Link{SourceNativeID: repo, TargetNativeID: roleArn, Kind: model.EdgeFederatesWith,
						Conditions: map[string]string{"via": "github-actions-oidc"}})
				}
			}

			// The same cross-domain join for GitLab CI/CD (ADR-0031, GL-4): when the
			// federated principal is the GitLab OIDC provider and the trust condition
			// names a project in its sub claim, emit a federates_with edge from that
			// GitLab project (keyed by group/project, the same path_with_namespace the
			// GitLab projects collector emits) to the role. Same discipline: the project
			// comes only from the signed trust policy, never guessed. This recognizes the
			// gitlab.com issuer; a self-managed GitLab OIDC host is folded into the
			// self-managed follow-up (GL-1).
			if p.typ == "federated" && strings.Contains(p.value, gitlabOIDCHost) {
				for _, proj := range gitlabProjectsFromCondition(s.Condition) {
					_ = sink.Link(collect.Link{SourceNativeID: proj, TargetNativeID: roleArn, Kind: model.EdgeFederatesWith,
						Conditions: map[string]string{"via": "gitlab-oidc"}})
				}
			}
		}
	}
}

// githubActionsOIDCHost is the issuer host of the GitHub Actions OIDC provider, used to
// recognize a role that federates trust to GitHub Actions.
const githubActionsOIDCHost = "token.actions.githubusercontent.com"

// githubReposFromCondition extracts the "owner/repo" repositories named in the sub
// claim(s) of a GitHub Actions OIDC trust condition. It reads only the structured
// condition of the signed trust policy; a condition that names no repo yields nothing.
func githubReposFromCondition(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var ops map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &ops) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, kv := range ops {
		for key, v := range kv {
			if !strings.HasSuffix(key, ":sub") || !strings.Contains(key, githubActionsOIDCHost) {
				continue
			}
			for _, val := range stringOrSlice(v) {
				if repo, ok := repoFromSub(val); ok && !seen[repo] {
					seen[repo] = true
					out = append(out, repo)
				}
			}
		}
	}
	return out
}

// repoFromSub extracts "owner/repo" from a GitHub OIDC sub claim value such as
// "repo:owner/repo:ref:refs/heads/main" or "repo:owner/repo:*".
func repoFromSub(sub string) (string, bool) {
	const prefix = "repo:"
	if !strings.HasPrefix(sub, prefix) {
		return "", false
	}
	rest := sub[len(prefix):]
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || !strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

// gitlabOIDCHost is the issuer host of the GitLab.com OIDC provider, used to recognize a
// role that federates trust to GitLab CI/CD.
const gitlabOIDCHost = "gitlab.com"

// gitlabProjectsFromCondition extracts the "group/project" paths named in the sub
// claim(s) of a GitLab OIDC trust condition. It reads only the structured condition of
// the signed trust policy; a condition that names no project yields nothing.
func gitlabProjectsFromCondition(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var ops map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &ops) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, kv := range ops {
		for key, v := range kv {
			if !strings.HasSuffix(key, ":sub") || !strings.Contains(key, gitlabOIDCHost) {
				continue
			}
			for _, val := range stringOrSlice(v) {
				if proj, ok := projectFromSub(val); ok && !seen[proj] {
					seen[proj] = true
					out = append(out, proj)
				}
			}
		}
	}
	return out
}

// projectFromSub extracts "group/project" (which may be a nested group path) from a
// GitLab OIDC sub claim value such as
// "project_path:group/project:ref_type:branch:ref:main" or "project_path:group/project:*".
// A sub keyed on project_id instead of project_path names no path and yields nothing:
// the path is the only form that joins to the GitLab projects collector's native id.
func projectFromSub(sub string) (string, bool) {
	const prefix = "project_path:"
	if !strings.HasPrefix(sub, prefix) {
		return "", false
	}
	rest := sub[len(prefix):]
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || !strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

// conditionString returns a trust statement's Condition block as a compact JSON
// string, or empty when there is none. It is carried verbatim, not decomposed.
func conditionString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	return string(raw)
}

// trustPrincipal is one principal a role's trust policy allows to assume it.
type trustPrincipal struct {
	typ   string // aws | service | federated | canonical
	value string
}

// trustedPrincipals extracts the principals a role trust policy allows to assume
// the role, from its Allow statements. The document is URL-encoded JSON (the IAM
// API returns policies RFC 3986 encoded); it is decoded before parsing.
func trustedPrincipals(doc string) []trustPrincipal {
	decoded := doc
	if d, err := url.PathUnescape(doc); err == nil {
		decoded = d
	}
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(decoded), &d) != nil {
		return nil
	}
	var out []trustPrincipal
	for _, s := range trustStatements(d.Statement) {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		out = append(out, principalsOf(s.Principal)...)
	}
	return out
}

type trustStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

// trustStatements returns the Statement list, handling both a single object and
// an array (a policy document allows either form).
func trustStatements(raw json.RawMessage) []trustStatement {
	if len(raw) == 0 {
		return nil
	}
	var arr []trustStatement
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var one trustStatement
	if json.Unmarshal(raw, &one) == nil {
		return []trustStatement{one}
	}
	return nil
}

// principalsOf parses a statement's Principal, which is either "*" or an object
// mapping a principal type (AWS, Service, Federated, CanonicalUser) to a string
// or a list of strings.
func principalsOf(raw json.RawMessage) []trustPrincipal {
	if len(raw) == 0 {
		return nil
	}
	var star string
	if json.Unmarshal(raw, &star) == nil {
		if star == "*" {
			return []trustPrincipal{{typ: "aws", value: "*"}}
		}
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	var out []trustPrincipal
	for key, v := range obj {
		typ := principalType(key)
		for _, val := range stringOrSlice(v) {
			if val != "" {
				out = append(out, trustPrincipal{typ: typ, value: val})
			}
		}
	}
	return out
}

func principalType(key string) string {
	switch key {
	case "AWS":
		return "aws"
	case "Service":
		return "service"
	case "Federated":
		return "federated"
	case "CanonicalUser":
		return "canonical"
	default:
		return strings.ToLower(key)
	}
}

func stringOrSlice(raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	return nil
}

// principalNode maps a trusted principal to a provider-neutral node, keyed so
// that internal principals dedup with the nodes the identity pass emitted: an
// account root keys to the account id, a user or role ARN keys by ARN.
func principalNode(p trustPrincipal) (collect.Node, bool) {
	switch p.typ {
	case "aws":
		if p.value == "*" {
			return collect.Node{Type: model.NodeIdentity, NativeID: "*", Name: "any AWS principal", Attributes: attrs("public", "true")}, true
		}
		if acct, ok := rootAccount(p.value); ok {
			return collect.Node{Type: model.NodeAccount, NativeID: acct}, true
		}
		switch {
		case strings.Contains(p.value, ":role/"):
			return collect.Node{Type: model.NodeRole, NativeID: p.value}, true
		case strings.Contains(p.value, ":user/"):
			return collect.Node{Type: model.NodeIdentity, NativeID: p.value}, true
		case isAccountID(p.value):
			// A bare account id is the account root.
			return collect.Node{Type: model.NodeAccount, NativeID: p.value}, true
		default:
			return collect.Node{Type: model.NodeIdentity, NativeID: p.value}, true
		}
	case "service":
		// An AI-runtime service principal (Bedrock, SageMaker) that a role trusts is a
		// real, structurally-verifiable AI agent bound to that role: the runtime can
		// assume the role and act with its permissions. Type it as an ai_agent so the
		// resulting assumes edge (ai_agent to role) joins the AI domain into the identity
		// graph. This is grounded only in the signed trust policy already collected, never
		// in a name or tag heuristic; a role that no AI runtime trusts yields no ai_agent
		// node (ADR-0031, AI domain).
		if runtime, ok := aiRuntimeName(p.value); ok {
			return collect.Node{Type: model.NodeAIAgent, NativeID: p.value, Name: p.value, Attributes: attrs("service_principal", "true", "ai_runtime", runtime)}, true
		}
		return collect.Node{Type: model.NodeService, NativeID: p.value, Name: p.value, Attributes: attrs("service_principal", "true")}, true
	case "federated":
		return collect.Node{Type: model.NodeIdentity, NativeID: p.value, Attributes: attrs("federated", "true")}, true
	case "canonical":
		return collect.Node{Type: model.NodeIdentity, NativeID: p.value, Attributes: attrs("canonical_user", "true")}, true
	default:
		return collect.Node{Type: model.NodeIdentity, NativeID: p.value, Attributes: attrs("principal_type", p.typ)}, true
	}
}

// aiRuntimeServices maps the AWS AI-runtime service principals (those that run customer
// AI workloads and assume a role to do so) to a short runtime name. A role trusted by one
// of these is an AI execution role; the trusting principal is modeled as an ai_agent.
var aiRuntimeServices = map[string]string{
	"bedrock.amazonaws.com":   "bedrock",
	"sagemaker.amazonaws.com": "sagemaker",
}

// aiRuntimeName returns the AI-runtime name for a service principal, and whether it is a
// recognized AI runtime.
func aiRuntimeName(servicePrincipal string) (string, bool) {
	name, ok := aiRuntimeServices[servicePrincipal]
	return name, ok
}

// rootAccount returns the account id of an account-root principal ARN
// (arn:aws:iam::<account>:root), so it keys to the same node as the account.
func rootAccount(arn string) (string, bool) {
	if !strings.HasSuffix(arn, ":root") {
		return "", false
	}
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 && isAccountID(parts[4]) {
		return parts[4], true
	}
	return "", false
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
