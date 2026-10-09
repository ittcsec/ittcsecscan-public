// Package collect holds the Azure read-only collectors. They read Microsoft
// Entra (and later Azure RBAC) through the credential the identity adapter
// already resolved, and emit the provider-neutral nodes, evidence, and
// completeness the collection framework defines.
//
// Entra is read over the Microsoft Graph REST API with plain HTTP and JSON, not
// the generated Graph SDK: the SDK is very large (hundreds of packages) for what
// here is three list calls, and a bearer token from the shared azcore credential
// plus net/http is lighter and fully sufficient (ADR-0017, and the same choice
// made for GCP). The Azure SDK stays confined to providers/azure (ADR-0016 §1).
package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// identityCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const identityCollectorID = "collector:azure.entra.identities"

const (
	// graphBaseURL is the Microsoft Graph v1.0 endpoint. The collector only ever
	// issues GETs against the read-only list resources below.
	graphBaseURL = "https://graph.microsoft.com/v1.0"
	// graphScope is the token scope for Microsoft Graph. The credential resolved
	// for identity mints a Graph-scoped token for these reads; it is one
	// credential, a different scope (see the adapter's resolveCredential).
	graphScope = "https://graph.microsoft.com/.default"
	// graphAPIVersion is recorded as evidence provenance.
	graphAPIVersion = "v1.0"
	// maxResponseBytes caps a single Graph page the collector will read, so a
	// hostile or malfunctioning endpoint cannot exhaust memory.
	maxResponseBytes = 16 << 20
	// maxPages bounds how many pages the collector will follow, so an endpoint
	// that returns an @odata.nextLink forever cannot hang the scan. Hitting it is a
	// represented Partial gap, never a silent stop. Graph's default page size is
	// 100, so this is 100k objects per resource, far above any real tenant.
	maxPages = 1000
)

// graphAPI is the read-only Microsoft Graph surface the collector uses: fetch a
// list URL (the base resource, then each @odata.nextLink) and return the raw
// JSON body. It is an interface so tests inject a stub and never touch the
// network, a real token, or the SDK.
type graphAPI interface {
	get(ctx context.Context, url string) ([]byte, error)
}

// IdentityCollector reads the Microsoft Entra identity graph for a tenant: the
// users (human identity), groups, and service principals (machine identity), and
// each group's direct members (as member-of edges). The reads were verified
// against the Microsoft Graph API reference (graph-rest-1.0, users/groups/service
// principals 2026-09-18, group members 2026-09-19): each is a read-only GET,
// paginated by @odata.nextLink, and returns no secret value (a service
// principal's keyCredentials.key is omitted unless explicitly $select-ed, which
// this collector never does).
type IdentityCollector struct {
	tenantID string
	api      graphAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
	groupIDs []string        // group ids gathered during the groups pass, expanded for membership
}

// NewIdentityCollector builds the collector with a Graph client that mints a
// Graph-scoped token from the adapter's resolved credential (ADR-0018 §3). The
// credential is the same one the identity adapter used, so identity and
// collection cannot come from two different resolutions. budget is the scan's
// shared call cap (nil is unlimited).
func NewIdentityCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *IdentityCollector {
	return &IdentityCollector{tenantID: tenantID, api: &graphClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newIdentityCollector is the injectable constructor tests use with a stub API.
// It has no budget (unlimited); a test that needs one sets the field.
func newIdentityCollector(tenantID string, api graphAPI) *IdentityCollector {
	return &IdentityCollector{tenantID: tenantID, api: api}
}

func (c *IdentityCollector) ID() string               { return identityCollectorID }
func (c *IdentityCollector) Provider() model.Provider { return model.Azure }

// identityRequirements are the read-only Microsoft Graph application permissions
// this collector needs, credited to it. They are the least-privileged permission
// for each list operation per the Graph reference (verified 2026-09-18), and are
// registered at init so the templates reconcile against real code (ADR-0016).
func identityRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Azure, Profile: permissions.Discovery, Permission: p, By: identityCollectorID}
	}
	return []permissions.Requirement{
		req("User.Read.All"),
		req("Group.Read.All"),
		req("Application.Read.All"),
		// GroupMember.ReadBasic.All is deliberately NOT declared: the group-member read
		// (GET /groups/{id}/members) accepts Group.Read.All as an application permission
		// (Microsoft Graph "List group members", graph-rest-1.0, verified 2026-10-05:
		// Application permissions include Group.Read.All), which this collector already
		// requires for listing groups. Declaring GroupMember.ReadBasic.All as well would
		// over-state the least-privilege set (GM-PERM-1 in known-limitations).
	}
}

func init() {
	for _, r := range identityRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *IdentityCollector) Requirements() []permissions.Requirement { return identityRequirements() }

// Collect reads the tenant and its Entra identity graph, emitting nodes,
// evidence, and completeness. Entra is a global (tenant-wide) directory, so there
// is one region: "global". After the users, groups, and service principals are
// listed, each group's direct members are expanded into member-of edges, so a
// user's roles through group membership are visible.
func (c *IdentityCollector) Collect(ctx context.Context, sink collect.Sink) error {
	c.groupIDs = nil
	if err := sink.Node(collect.Node{Type: model.NodeTenant, NativeID: c.tenantID}); err != nil {
		return err
	}
	// Each list is its own enumeration with its own completeness; one denied or
	// throttled read is a recorded gap for that resource, not a silent empty and
	// not an end to the others.
	for _, page := range []struct {
		service string
		path    string
		emit    func(collect.Sink, json.RawMessage) (int, error)
	}{
		{"entra.users", "/users?$select=id,displayName,userPrincipalName,accountEnabled", c.emitUsers},
		{"entra.groups", "/groups?$select=id,displayName,securityEnabled", c.emitGroups},
		{"entra.servicePrincipals", "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType", c.emitServicePrincipals},
	} {
		if err := c.paginate(ctx, sink, page.service, page.path, page.emit); err != nil {
			return err
		}
	}
	return c.expandGroupMembers(ctx, sink)
}

// expandGroupMembers reads each group's direct members and emits a member-of edge
// per member, reusing the group ids gathered by the groups pass so no second
// group list is fetched. This is the scan's most call-heavy step, one call per
// group per page, so the shared budget bounds it: when it is exhausted the
// remaining groups are recorded as a Partial gap, never silently skipped. A
// single group's denied or errored membership is a recorded gap that does not
// stop the other groups. A batched read (Graph $batch) to cut round-trips is a
// noted follow-up; service principals as members are a known Graph v1.0 gap, also
// a follow-up.
func (c *IdentityCollector) expandGroupMembers(ctx context.Context, sink collect.Sink) error {
	if len(c.groupIDs) == 0 {
		return nil
	}
	const service = "entra.groupMembers"
	total := 0
	reason := ""
	for _, gid := range c.groupIDs {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: total, Reason: "cancelled"})
			return err
		}
		n, gap := c.groupMembers(ctx, sink, gid)
		total += n
		if gap != "" {
			reason = gap
			if gap == "budget exhausted" {
				// No budget remains, so the rest would only record the same gap.
				break
			}
		}
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: total, Reason: reason})
}

// groupMembers reads one group's direct members, emitting each as a node (typed
// from its @odata.type) and a member-of edge to the group. It returns how many
// members it emitted and, if the read did not fully complete, the reason (a
// denial, a throttle, an unexpected error, the budget, or the page limit). One
// group's failure is never fatal to the rest.
func (c *IdentityCollector) groupMembers(ctx context.Context, sink collect.Sink, groupID string) (int, string) {
	url := graphBaseURL + "/groups/" + groupID + "/members?$select=id"
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return count, "page limit reached"
		}
		if !c.budget.Spend() {
			return count, "budget exhausted"
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			switch {
			case isDenied(err):
				return count, "denied"
			case isThrottle(err):
				return count, "throttled"
			default:
				return count, redact.String(err.Error())
			}
		}
		_ = sink.Evidence(c.evidence("group.members", body))
		var env memberEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			return count, redact.String(err.Error())
		}
		for _, m := range env.Value {
			if m.ID == "" {
				continue
			}
			_ = sink.Node(memberNode(m.ODataType, m.ID))
			_ = sink.Link(collect.Link{SourceNativeID: m.ID, TargetNativeID: groupID, Kind: model.EdgeMemberOf})
			count++
		}
		if env.NextLink == "" {
			return count, ""
		}
		url = env.NextLink
	}
}

// memberEnvelope is a group-members page: a directoryObjects collection whose
// items carry an id and an @odata.type discriminator.
type memberEnvelope struct {
	Value []struct {
		ID        string `json:"id"`
		ODataType string `json:"@odata.type"`
	} `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// memberNode maps a group member to a node, keyed by its object id so it dedups
// with the identity pass's node of the same id, typed from its @odata.type.
func memberNode(odataType, id string) collect.Node {
	var t model.NodeType
	switch odataType {
	case "#microsoft.graph.group":
		t = model.NodeGroup // a nested group membership
	case "#microsoft.graph.servicePrincipal":
		t = model.NodeWorkload
	case "#microsoft.graph.device":
		t = model.NodeEndpointDevice
	default: // user, orgContact, or an inaccessible object: a human/opaque identity
		t = model.NodeIdentity
	}
	return collect.Node{Type: t, NativeID: id}
}

// paginate reads one Graph list resource fully, following @odata.nextLink, and
// records completeness. A denied or throttled read is an expected, represented
// gap (Denied or Partial); an unexpected error is surfaced so the run reports it.
// A page is never reported Complete when a fetch failed.
func (c *IdentityCollector) paginate(ctx context.Context, sink collect.Sink, service, path string, emit func(collect.Sink, json.RawMessage) (int, error)) error {
	url := graphBaseURL + path
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			// The endpoint kept returning a next-page link past the bound: stop and
			// record the gap rather than following it forever.
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "page limit reached"})
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return nil
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence(service, body))
		var env graphEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := emit(sink, env.Value)
		if err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if env.NextLink == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return nil
		}
		url = env.NextLink
	}
}

// graphEnvelope is the shared shape of a Graph list response: the value array
// and the opaque next-page link.
type graphEnvelope struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"@odata.nextLink"`
}

func (c *IdentityCollector) emitUsers(sink collect.Sink, raw json.RawMessage) (int, error) {
	var users []struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
		AccountEnabled    *bool  `json:"accountEnabled"`
	}
	if err := json.Unmarshal(raw, &users); err != nil {
		return 0, err
	}
	for _, u := range users {
		_ = sink.Node(collect.Node{Type: model.NodeIdentity, NativeID: u.ID, Name: u.DisplayName,
			Attributes: attrs("upn", u.UserPrincipalName, "enabled", boolAttr(u.AccountEnabled))})
	}
	return len(users), nil
}

func (c *IdentityCollector) emitGroups(sink collect.Sink, raw json.RawMessage) (int, error) {
	var groups []struct {
		ID              string `json:"id"`
		DisplayName     string `json:"displayName"`
		SecurityEnabled *bool  `json:"securityEnabled"`
	}
	if err := json.Unmarshal(raw, &groups); err != nil {
		return 0, err
	}
	for _, g := range groups {
		_ = sink.Node(collect.Node{Type: model.NodeGroup, NativeID: g.ID, Name: g.DisplayName,
			Attributes: attrs("security_enabled", boolAttr(g.SecurityEnabled))})
		if g.ID != "" {
			c.groupIDs = append(c.groupIDs, g.ID)
		}
	}
	return len(groups), nil
}

// emitServicePrincipals maps service principals to workload (machine identity)
// nodes: a service principal is a non-human identity, distinct from a human user.
func (c *IdentityCollector) emitServicePrincipals(sink collect.Sink, raw json.RawMessage) (int, error) {
	var sps []struct {
		ID                   string `json:"id"`
		AppID                string `json:"appId"`
		DisplayName          string `json:"displayName"`
		ServicePrincipalType string `json:"servicePrincipalType"`
	}
	if err := json.Unmarshal(raw, &sps); err != nil {
		return 0, err
	}
	for _, sp := range sps {
		_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: sp.ID, Name: sp.DisplayName,
			Attributes: attrs("app_id", sp.AppID, "sp_type", sp.ServicePrincipalType)})
	}
	return len(sps), nil
}

func (c *IdentityCollector) scope() collect.Scope { return collect.Scope{Account: c.tenantID} }

// evidence builds a redacted, secret-free envelope for one Graph read. The raw
// JSON body is the evidence; it still passes through redaction as defence in
// depth even though the reads return no secret value.
func (c *IdentityCollector) evidence(service string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "entra", Operation: service, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: graphAPIVersion, Collector: identityCollectorID},
	}
}

// completeness classifies a Graph error into a completeness record with a
// redacted reason.
func (c *IdentityCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{
		Service: service, Region: collect.Global, Scope: c.scope(),
		Status: status, Collected: collected, Reason: redact.String(err.Error()),
	}
}

// graphClient is the production graphAPI: it mints a Graph-scoped token from the
// shared credential and issues read-only GETs.
type graphClient struct {
	cred azcore.TokenCredential
	http *http.Client
}

func (g *graphClient) get(ctx context.Context, url string) ([]byte, error) {
	return azureGet(ctx, g.cred, g.http, graphScope, url)
}

func attrs(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func boolAttr(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}
