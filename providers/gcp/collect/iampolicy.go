package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// policyCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const policyCollectorID = "collector:gcp.iam.policy"

const (
	// crmBaseURL is the Cloud Resource Manager v1 REST endpoint.
	crmBaseURL = "https://cloudresourcemanager.googleapis.com/v1"
	// crmAPIVersion is recorded as evidence provenance.
	crmAPIVersion = "v1"
	// policyRequestBody asks for policy version 3 so that conditional role
	// bindings are returned rather than dropped or erroring (Cloud Resource
	// Manager / IAM reference, verified 2026-09-18).
	policyRequestBody = `{"options":{"requestedPolicyVersion":3}}`
)

// policyAPI is the read-only surface this collector uses: read a project's IAM
// policy, and read a role definition (its included permissions). Both return the
// raw JSON body. It is an interface so tests inject a stub and never touch the
// network, a real token, or the client libraries.
type policyAPI interface {
	getIamPolicy(ctx context.Context, project string) ([]byte, error)
	getRole(ctx context.Context, roleName string) ([]byte, error)
	getDenyPolicies(ctx context.Context, project string) ([]byte, error)
}

const (
	// denyBaseURL is the IAM v2 endpoint for deny policies. Verified live against the
	// real endpoint (2026-09-23): GET .../v2/policies/<attachmentPoint>/denypolicies,
	// a read-only list that mutates nothing and returns {} when none are set.
	denyBaseURL    = "https://iam.googleapis.com/v2"
	denyAPIVersion = "v2"
)

// PolicyCollector reads a project's IAM allow policy: the role bindings that
// grant principals (members) roles on the project. It is the authorization graph
// for GCP: who has which role. projects.getIamPolicy was verified against the
// Cloud Resource Manager API reference (v1, 2026-09-18): a read-only POST (it
// mutates nothing), requiring resourcemanager.projects.getIamPolicy, returning
// the policy's bindings; it is a single call, not paginated.
type PolicyCollector struct {
	projectID string
	api       policyAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewPolicyCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3). budget is
// the scan's shared call cap (nil is unlimited).
func NewPolicyCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *PolicyCollector {
	return &PolicyCollector{projectID: projectID, api: &gcpPolicyClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newPolicyCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newPolicyCollector(projectID string, api policyAPI) *PolicyCollector {
	return &PolicyCollector{projectID: projectID, api: api}
}

func (c *PolicyCollector) ID() string               { return policyCollectorID }
func (c *PolicyCollector) Provider() model.Provider { return model.GCP }

// policyRequirements are the read-only permissions this collector needs.
func policyRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "resourcemanager.projects.getIamPolicy", By: policyCollectorID},
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "iam.roles.get", By: policyCollectorID},
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "iam.denypolicies.list", By: policyCollectorID},
	}
}

func init() {
	for _, r := range policyRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *PolicyCollector) Requirements() []permissions.Requirement { return policyRequirements() }

// Collect reads the project's IAM policy and emits the role nodes, member nodes,
// and the member-to-role grant edges. The project IAM policy is a single global
// read, so there is one region: "global". Role-to-resource scoping and group
// membership expansion are noted follow-ups; this collector records the direct
// grants a binding states.
func (c *PolicyCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "iam.projectPolicy"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{
			Service: service, Region: collect.Global, Scope: c.scope(),
			Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to",
		})
	}
	if !c.budget.Spend() {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
	}
	body, err := c.api.getIamPolicy(ctx, c.projectID)
	if err != nil {
		_ = sink.Complete(c.completeness(service, err))
		if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
			return nil
		}
		return err
	}
	_ = sink.Evidence(c.evidence("getIamPolicy", body))

	var policy iamPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Reason: redact.String(err.Error())})
		return fmt.Errorf("%s: decoding policy: %w", service, err)
	}

	// The project is the scope of these bindings; emit it so the graph has the
	// resource the roles are granted on. It dedups with the service-account
	// collector's project node at ingest.
	if err := sink.Node(collect.Node{Type: model.NodeProject, NativeID: c.projectID}); err != nil {
		return err
	}
	// Classify each distinct role's included permissions (roles.get) so a role
	// node carries a grounded privilege_level (ADR-0022 Layer A). A role whose
	// definition could not be read is emitted without the fact, and the gap is
	// recorded as its own completeness, never a silent "not privileged".
	roleAttrs, roleStatus, roleCount := c.classifyRoles(ctx, sink, policy)
	bindings := c.mapBindings(sink, policy, roleAttrs)
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: bindings})
	if roleStatus != "" {
		_ = sink.Complete(collect.Completeness{Service: "iam.roleDefinitions", Region: collect.Global, Scope: c.scope(), Status: roleStatus, Collected: roleCount, Reason: roleStatusReason(roleStatus)})
	}
	c.denyPolicies(ctx, sink)
	return nil
}

// denyPolicies reads the project's IAM v2 deny policies and stamps a
// deny_privilege_level fact on each denied principal (the highest privilege the
// deny removes), which the Step 4 effective-privilege engine consumes as an
// explicit deny that overrides an allow (ADR-0022 EP-6). A denied or absent read is
// an honest gap; an empty result (no deny policies) is Complete with zero.
func (c *PolicyCollector) denyPolicies(ctx context.Context, sink collect.Sink) {
	const service = "iam.denyPolicies"
	if !c.budget.Spend() {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
		return
	}
	body, err := c.api.getDenyPolicies(ctx, c.projectID)
	if err != nil {
		_ = sink.Complete(c.completeness(service, err))
		return
	}
	_ = sink.Evidence(collect.Envelope{
		Provider: model.GCP, Service: "iam", Operation: "denypolicies.list", Region: collect.Global, Scope: c.scope(),
		Response: json.RawMessage(redact.String(string(body))), Provenance: collect.Provenance{APIVersion: denyAPIVersion, Collector: policyCollectorID},
	})
	list, ok := parseDenyPolicies(body)
	if !ok {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Reason: "malformed deny policy response"})
		return
	}
	levels := denyLevels(list)
	for _, key := range sortedKeys(levels) {
		_ = sink.Node(collect.Node{Type: denyPrincipalType(key), NativeID: key, Attributes: attrs("deny_privilege_level", levels[key])})
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: len(levels)})
}

// denyPrincipalType infers the node type of a denied principal from its key, so the
// deny node merges cleanly with the allow-policy member node of the same id.
func denyPrincipalType(key string) model.NodeType {
	if strings.Contains(key, ".iam.gserviceaccount.com") || strings.Contains(key, "serviceAccount") {
		return model.NodeWorkload
	}
	return model.NodeIdentity
}

// classifyRoles reads each distinct role's definition (roles.get) and returns the
// privilege facts to stamp on each role node, the worst completeness status seen,
// and how many roles were classified. Roles are read in sorted order and each
// read spends from the shared budget; a failed read downgrades the status but
// never fails the whole collection, so one unreadable role does not lose the rest.
func (c *PolicyCollector) classifyRoles(ctx context.Context, sink collect.Sink, policy iamPolicy) (map[string][]string, collect.Status, int) {
	seen := map[string]bool{}
	var roles []string
	for _, b := range policy.Bindings {
		if b.Role != "" && !seen[b.Role] {
			seen[b.Role] = true
			roles = append(roles, b.Role)
		}
	}
	if len(roles) == 0 {
		return nil, "", 0
	}
	sort.Strings(roles)
	out := map[string][]string{}
	status := collect.Complete
	n := 0
	for _, role := range roles {
		if !c.budget.Spend() {
			status = worseStatus(status, collect.Partial)
			continue
		}
		body, err := c.api.getRole(ctx, role)
		if err != nil {
			status = worseStatus(status, roleErrStatus(err))
			continue
		}
		_ = sink.Evidence(c.roleEvidence(role, body))
		def, ok := parseRoleDefinition(body)
		if !ok {
			status = worseStatus(status, collect.Errored)
			continue
		}
		level, esc := classifyRole(def.IncludedPermissions)
		var a []string
		if level != "" {
			a = append(a, "privilege_level", level)
		}
		if len(esc) > 0 {
			a = append(a, "escalation_permissions", strings.Join(esc, ","))
		}
		a = append(a, "permissions_read", "true")
		out[role] = a
		n++
	}
	return out, status, n
}

// mapBindings emits a role node and, for each member, a member node and a
// member-to-role grant edge, returning the number of bindings mapped. A binding's
// condition is carried on its edges. Nodes may repeat (the same member across
// roles, the same service account the identity collector also lists); the store
// dedups by native id, so the collector emits freely.
func (c *PolicyCollector) mapBindings(sink collect.Sink, policy iamPolicy, roleAttrs map[string][]string) int {
	for _, b := range policy.Bindings {
		if b.Role == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeRole, NativeID: b.Role, Name: b.Role, Attributes: attrs(roleAttrs[b.Role]...)})
		conditions := bindingConditions(b.Condition)
		for _, m := range b.Members {
			node := memberNode(m)
			if node.NativeID == "" {
				continue
			}
			_ = sink.Node(node)
			_ = sink.Link(collect.Link{SourceNativeID: node.NativeID, TargetNativeID: b.Role, Kind: model.EdgeAssumes, Conditions: conditions})
		}
	}
	return len(policy.Bindings)
}

// iamPolicy is the subset of the getIamPolicy response the collector reads.
type iamPolicy struct {
	Bindings []struct {
		Role      string   `json:"role"`
		Members   []string `json:"members"`
		Condition *struct {
			Title      string `json:"title"`
			Expression string `json:"expression"`
		} `json:"condition"`
	} `json:"bindings"`
}

// memberNode classifies an IAM policy member string into a provider-neutral
// node, keyed so that a service-account member reuses the service-account
// collector's node (bare email). Members verified against the IAM principal
// identifier reference (2026-09-18). An unknown member type is never dropped: it
// becomes an identity keyed by the whole string, with its raw form recorded.
func memberNode(member string) collect.Node {
	switch member {
	case "allUsers":
		return collect.Node{Type: model.NodeIdentity, NativeID: "allUsers", Name: "all users", Attributes: attrs("public", "true")}
	case "allAuthenticatedUsers":
		return collect.Node{Type: model.NodeIdentity, NativeID: "allAuthenticatedUsers", Name: "all authenticated users", Attributes: attrs("public", "true")}
	}
	prefix, rest, ok := strings.Cut(member, ":")
	if !ok {
		return collect.Node{Type: model.NodeIdentity, NativeID: member, Attributes: attrs("member_type", "unknown")}
	}
	switch prefix {
	case "user":
		return collect.Node{Type: model.NodeIdentity, NativeID: rest}
	case "serviceAccount":
		// Bare email, matching the service-account collector's node native id, so
		// the two collectors' views of one service account merge at ingest.
		return collect.Node{Type: model.NodeWorkload, NativeID: rest}
	case "group":
		return collect.Node{Type: model.NodeGroup, NativeID: rest}
	case "domain":
		// A domain is not an email; keep the full member string as the id so it
		// cannot collide with a user or group.
		return collect.Node{Type: model.NodeGroup, NativeID: member, Name: rest, Attributes: attrs("member_type", "domain")}
	case "principal":
		// A single federated (workforce, workload, or agent) identity.
		return collect.Node{Type: model.NodeIdentity, NativeID: member, Attributes: attrs("member_type", "principal")}
	case "principalSet":
		// A set of federated identities (a group).
		return collect.Node{Type: model.NodeGroup, NativeID: member, Attributes: attrs("member_type", "principal_set")}
	case "deleted":
		// A principal that was deleted but still named in the policy: a real stale
		// grant. Keyed by the full string so it stays distinct from a live
		// principal of the same email.
		return collect.Node{Type: deletedMemberType(rest), NativeID: member, Attributes: attrs("member_type", "deleted")}
	default:
		return collect.Node{Type: model.NodeIdentity, NativeID: member, Attributes: attrs("member_type", "unknown")}
	}
}

// deletedMemberType returns the node type for a "deleted:<inner>:..." member
// from its inner principal type.
func deletedMemberType(rest string) model.NodeType {
	inner, _, _ := strings.Cut(rest, ":")
	switch inner {
	case "serviceAccount":
		return model.NodeWorkload
	case "group":
		return model.NodeGroup
	default:
		return model.NodeIdentity
	}
}

// bindingConditions turns a binding's optional condition into edge conditions.
func bindingConditions(cond *struct {
	Title      string `json:"title"`
	Expression string `json:"expression"`
}) map[string]string {
	if cond == nil {
		return nil
	}
	return attrs("condition_title", cond.Title, "condition_expression", cond.Expression)
}

// worseStatus returns the more concerning of two completeness statuses, so one
// denied or errored role read is not masked by other complete ones.
func worseStatus(a, b collect.Status) collect.Status {
	rank := func(s collect.Status) int {
		switch s {
		case collect.Complete:
			return 0
		case collect.Unsupported:
			return 1
		case collect.Partial:
			return 2
		case collect.Denied:
			return 3
		default:
			return 4
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// roleErrStatus maps a roles.get error to a completeness status, the same honest
// classification the policy read uses.
func roleErrStatus(err error) collect.Status {
	switch {
	case isServiceDisabled(err):
		return collect.Unsupported
	case isDenied(err):
		return collect.Denied
	case isThrottle(err):
		return collect.Partial
	default:
		return collect.Errored
	}
}

// roleStatusReason pins a reason for a non-complete role-definition read so a gap
// is always explained.
func roleStatusReason(s collect.Status) string {
	switch s {
	case collect.Complete:
		return ""
	case collect.Denied:
		return "a role definition read was denied (iam.roles.get)"
	case collect.Partial:
		return "budget exhausted or throttled before every role was read"
	case collect.Unsupported:
		return "the IAM API is not enabled"
	default:
		return "a role definition read failed"
	}
}

func (c *PolicyCollector) roleEvidence(role string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "iam", Operation: "roles.get", Region: collect.Global,
		Scope:      collect.Scope{Account: c.projectID, Resource: role},
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: policyCollectorID},
	}
}

func (c *PolicyCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *PolicyCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "resourcemanager", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: crmAPIVersion, Collector: policyCollectorID},
	}
}

func (c *PolicyCollector) completeness(service string, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{
		Service: service, Region: collect.Global, Scope: c.scope(),
		Status: status, Reason: redact.String(err.Error()),
	}
}

// gcpPolicyClient is the production policyAPI: it POSTs getIamPolicy (a read)
// with a request for policy version 3.
type gcpPolicyClient struct {
	tokens oauth2.TokenSource
	http   *http.Client
}

func (g *gcpPolicyClient) getIamPolicy(ctx context.Context, project string) ([]byte, error) {
	u := fmt.Sprintf("%s/projects/%s:getIamPolicy", crmBaseURL, url.PathEscape(project))
	return gcpDo(ctx, g.http, g.tokens, http.MethodPost, u, []byte(policyRequestBody))
}

// getRole reads a role definition (predefined "roles/..." or custom
// "projects/.../roles/..."). It is a plain GET on the role's resource name and
// mutates nothing (IAM API reference: roles.get).
func (g *gcpPolicyClient) getRole(ctx context.Context, roleName string) ([]byte, error) {
	u := iamBaseURL + "/" + roleName
	return gcpDo(ctx, g.http, g.tokens, http.MethodGet, u, nil)
}

// getDenyPolicies lists the deny policies attached to the project (IAM v2). The
// attachment point is the project's Cloud Resource Manager resource, with its slash
// URL-encoded. It is a read-only GET.
func (g *gcpPolicyClient) getDenyPolicies(ctx context.Context, project string) ([]byte, error) {
	ap := url.PathEscape("cloudresourcemanager.googleapis.com/projects/" + project)
	u := fmt.Sprintf("%s/policies/%s/denypolicies", denyBaseURL, ap)
	return gcpDo(ctx, g.http, g.tokens, http.MethodGet, u, nil)
}
