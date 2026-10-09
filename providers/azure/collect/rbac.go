package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// rbacCollectorID is the stable id this collector is credited with.
const rbacCollectorID = "collector:azure.rbac.assignments"

const (
	// armBaseURL is the Azure Resource Manager endpoint. The collector only ever
	// issues read-only GETs against the list resources below.
	armBaseURL = "https://management.azure.com"
	// managementScope is the ARM token scope. The credential resolved for identity
	// (which draws an ARM token for the tenants list) draws a management token here
	// too; it is one credential, the same plane, a different resource path.
	managementScope = "https://management.azure.com/.default"
	// subscriptionsAPIVersion and authorizationAPIVersion are the doc-verified API
	// versions (2026-09-19).
	subscriptionsAPIVersion = "2022-12-01"
	authorizationAPIVersion = "2022-04-01"
)

// armAPI is the read-only ARM surface the collector uses: fetch a list URL (the
// base resource, then each nextLink) and return the raw JSON body. It is an
// interface so tests inject a stub and never touch the network, a real token, or
// the SDK.
type armAPI interface {
	get(ctx context.Context, url string) ([]byte, error)
}

// RBACCollector reads a tenant's Azure RBAC authorization graph: the role
// assignments that grant principals roles at a scope. Azure RBAC lives on the
// Resource Manager plane and is subscription-scoped, so the collector enumerates
// the accessible subscriptions and reads each one's role assignments; management
// groups and cross-tenant scopes are a noted follow-up. The three reads were
// verified against the Azure REST reference (2026-09-19): each is a read-only GET,
// paginated by nextLink, and returns no secret value.
type RBACCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewRBACCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewRBACCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *RBACCollector {
	return &RBACCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newRBACCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newRBACCollector(tenantID string, api armAPI) *RBACCollector {
	return &RBACCollector{tenantID: tenantID, api: api}
}

func (c *RBACCollector) ID() string               { return rbacCollectorID }
func (c *RBACCollector) Provider() model.Provider { return model.Azure }

func rbacRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Azure, Profile: permissions.Discovery, Permission: p, By: rbacCollectorID}
	}
	return []permissions.Requirement{
		req("Microsoft.Authorization/roleAssignments/read"),
		req("Microsoft.Authorization/roleDefinitions/read"),
		req("Microsoft.Authorization/denyAssignments/read"),
	}
}

func init() {
	for _, r := range rbacRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *RBACCollector) Requirements() []permissions.Requirement { return rbacRequirements() }

// Collect enumerates the accessible subscriptions and, for each, reads its role
// assignments (resolving role names), emitting a subscription node, the assigned
// role and principal nodes, and a member-to-role grant edge per assignment. RBAC
// is a global management-plane read, so there is one region: "global".
func (c *RBACCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "rbac.subscriptions", tenantScope, subscriptionsAPIVersion,
		fmt.Sprintf("%s/subscriptions?api-version=%s", armBaseURL, subscriptionsAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []subscription
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			subs = append(subs, page...)
			return len(page), nil
		})
	if err != nil {
		return err
	}

	for _, sub := range subs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sub.SubscriptionID == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeSubscription, NativeID: sub.SubscriptionID, Name: sub.DisplayName,
			Attributes: attrs("state", sub.State)})
		scope := collect.Scope{Account: c.tenantID, Resource: sub.SubscriptionID}
		names := c.roleNames(ctx, sink, sub.SubscriptionID, scope)
		c.roleAssignments(ctx, sink, sub.SubscriptionID, scope, names)
		c.denyAssignments(ctx, sink, sub.SubscriptionID, scope)
	}
	return nil
}

// roleMeta is the resolved name, type, and privilege classification of a role
// definition. privilege is derived from the role's actual permission actions
// (ADR-0022 Layer A), not its name.
type roleMeta struct {
	name       string
	typ        string
	privilege  string
	escalation string
}

// roleNames reads the subscription's role definitions into a guid-to-name map,
// best-effort: a failure records its own completeness gap and returns what was
// resolved, so assignments still collect (with unresolved role names).
func (c *RBACCollector) roleNames(ctx context.Context, sink collect.Sink, subID string, scope collect.Scope) map[string]roleMeta {
	names := map[string]roleMeta{}
	_ = c.pageThrough(ctx, sink, "rbac.roleDefinitions", scope, authorizationAPIVersion,
		fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=%s", armBaseURL, subID, authorizationAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []roleDefinition
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			for _, rd := range page {
				if rd.Name != "" {
					level, esc := classifyAzureRole(rd.Properties.Permissions)
					names[rd.Name] = roleMeta{name: rd.Properties.RoleName, typ: rd.Properties.Type, privilege: level, escalation: strings.Join(esc, ",")}
				}
			}
			return len(page), nil
		})
	return names
}

// roleAssignments reads the subscription's role assignments, emitting for each a
// role node (name resolved from names), a principal node, and a grant edge
// carrying the assignment's scope and condition.
func (c *RBACCollector) roleAssignments(ctx context.Context, sink collect.Sink, subID string, scope collect.Scope, names map[string]roleMeta) {
	_ = c.pageThrough(ctx, sink, "rbac.roleAssignments", scope, authorizationAPIVersion,
		fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=%s", armBaseURL, subID, authorizationAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []roleAssignment
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			for _, ra := range page {
				p := ra.Properties
				if p.PrincipalID == "" || p.RoleDefinitionID == "" {
					continue
				}
				guid := lastSegment(p.RoleDefinitionID)
				meta := names[guid]
				ra := []string{"role_type", meta.typ}
				if meta.privilege != "" {
					ra = append(ra, "privilege_level", meta.privilege)
				}
				if meta.escalation != "" {
					ra = append(ra, "escalation_actions", meta.escalation)
				}
				_ = sink.Node(collect.Node{Type: model.NodeRole, NativeID: guid, Name: meta.name, Attributes: attrs(ra...)})
				node, ok := rbacPrincipalNode(p.PrincipalID, p.PrincipalType)
				if !ok {
					continue
				}
				_ = sink.Node(node)
				_ = sink.Link(collect.Link{SourceNativeID: p.PrincipalID, TargetNativeID: guid, Kind: model.EdgeAssumes,
					Conditions: attrs("scope", p.Scope, "condition", p.Condition)})
			}
			return len(page), nil
		})
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending
// budget per page and recording evidence and completeness for service at scope.
// handle receives each page's raw value array and returns how many items it
// processed. A denied or throttled read is a represented gap (returns nil); an
// unexpected error is surfaced; a page is never reported Complete on a failure.
func (c *RBACCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(rbacGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(rbacGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(rbacGap(service, scope, collect.Partial, count, "budget exhausted"))
			return nil
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence(service, apiVersion, scope, body))
		var list armList
		if err := json.Unmarshal(body, &list); err != nil {
			_ = sink.Complete(rbacGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(rbacGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(rbacGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

// armList is the shared shape of an ARM list response.
type armList struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"nextLink"`
}

type subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
	TenantID       string `json:"tenantId"`
}

type roleDefinition struct {
	Name       string `json:"name"`
	Properties struct {
		RoleName    string            `json:"roleName"`
		Type        string            `json:"type"`
		Permissions []azurePermission `json:"permissions"`
	} `json:"properties"`
}

type roleAssignment struct {
	Properties struct {
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		Scope            string `json:"scope"`
		Condition        string `json:"condition"`
	} `json:"properties"`
}

// rbacPrincipalNode maps a role-assignment principal to a provider-neutral node,
// keyed by its object id so it dedups with the Entra collector's node of the same
// id. The principal type comes from the assignment.
func rbacPrincipalNode(id, ptype string) (collect.Node, bool) {
	if id == "" {
		return collect.Node{}, false
	}
	var t model.NodeType
	switch ptype {
	case "Group", "ForeignGroup":
		t = model.NodeGroup
	case "ServicePrincipal", "AgentServicePrincipal":
		t = model.NodeWorkload
	case "Device":
		t = model.NodeEndpointDevice
	default: // User, AgentUser, or unknown: a human/opaque identity
		t = model.NodeIdentity
	}
	return collect.Node{Type: t, NativeID: id, Attributes: attrs("principal_type", ptype)}, true
}

// lastSegment returns the part of an ARM id after its final slash (a role
// definition's guid), so a built-in role (a tenant-level id) and a
// subscription-scoped id for the same role resolve to one node.
func lastSegment(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

func (c *RBACCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "rbac", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: rbacCollectorID},
	}
}

func (c *RBACCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return rbacGap(service, scope, status, collected, redact.String(err.Error()))
}

func rbacGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}

// armClient is the production armAPI: it mints a management-scoped token from the
// shared credential and issues read-only GETs.
type armClient struct {
	cred azcore.TokenCredential
	http *http.Client
}

func (a *armClient) get(ctx context.Context, url string) ([]byte, error) {
	return azureGet(ctx, a.cred, a.http, managementScope, url)
}
