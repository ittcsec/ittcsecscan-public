package collect

import (
	"context"
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// appRoleAssignmentCollectorID is the stable id this collector is credited with.
const appRoleAssignmentCollectorID = "collector:azure.entra.appRoleAssignments"

// AppRoleAssignmentCollector reads the application permissions granted to the
// tenant's service principals: the app-role assignments where a service principal
// (an app registration's identity or a managed identity) has been granted an app
// role on a resource API, most importantly the Microsoft Graph application
// permissions (User.Read.All, Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory,
// and the like). An over-permissioned app credential is one of the highest-impact
// standing grants in a tenant, and it is invisible to the RBAC (Azure Resource
// Manager) collector, which reads a different authorization plane.
//
// It is read over Microsoft Graph with Application.Read.All (already held). The
// appRoleId on an assignment is an opaque GUID whose meaning lives on the resource
// service principal's own appRoles collection, so this collector resolves the name
// from that collection at collection time (never a static, drift-prone GUID table,
// ADR-0036 amendment 3): pass one reads every service principal's appRoles to build
// the resolver and the set of principals to query; pass two reads each principal's
// appRoleAssignments and resolves each appRoleId against the resolver. A GUID that
// cannot be resolved is recorded verbatim with resolved=false, never guessed.
//
// Graph shape mirrors the RBAC collector: each granted app role is a role node,
// each principal a workload node, and the grant an assumes edge from principal to
// role carrying the grant type and resource. No privilege verdict is synthesized
// (there is no effective-privilege engine for Graph app permissions yet); the
// permission value is recorded as the ground fact.
type AppRoleAssignmentCollector struct {
	tenantID string
	api      graphAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
	// resourceAppID maps a resource service principal's object id to its application id
	// (the stable appId, e.g. Microsoft Graph's 00000003-...), gathered during the
	// catalog pass so a grant carries resource_app_id and a rule can match a resource API
	// by its appId rather than its display name. Set during Collect; read when emitting.
	resourceAppID map[string]string
}

// NewAppRoleAssignmentCollector builds the collector with a Graph client that mints
// a Graph-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewAppRoleAssignmentCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *AppRoleAssignmentCollector {
	return &AppRoleAssignmentCollector{tenantID: tenantID, api: &graphClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newAppRoleAssignmentCollector is the injectable constructor tests use with a stub.
func newAppRoleAssignmentCollector(tenantID string, api graphAPI) *AppRoleAssignmentCollector {
	return &AppRoleAssignmentCollector{tenantID: tenantID, api: api}
}

func (c *AppRoleAssignmentCollector) ID() string               { return appRoleAssignmentCollectorID }
func (c *AppRoleAssignmentCollector) Provider() model.Provider { return model.Azure }

func appRoleAssignmentRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.Azure, Profile: permissions.Discovery,
		Permission: "Application.Read.All", By: appRoleAssignmentCollectorID,
	}}
}

func init() {
	for _, r := range appRoleAssignmentRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permission the collector needs.
func (c *AppRoleAssignmentCollector) Requirements() []permissions.Requirement {
	return appRoleAssignmentRequirements()
}

// appRoleMeta is one resolvable app role on a resource service principal.
type appRoleMeta struct {
	value       string
	displayName string
}

// Collect resolves the app-role catalog, then reads each principal's app-role
// assignments and emits the grant graph.
func (c *AppRoleAssignmentCollector) Collect(ctx context.Context, sink collect.Sink) error {
	resolver, principals, catalogOK, err := c.readCatalog(ctx, sink)
	if err != nil {
		return err
	}
	return c.readAssignments(ctx, sink, resolver, principals, catalogOK)
}

// readCatalog reads every service principal's id, display name, and appRoles,
// building the appRoleId resolver (keyed by resource SP object id, then appRole
// GUID) and the list of principal ids to query in pass two. It records the
// entra.appRoleCatalog completeness; a denied or throttled read is a represented
// gap, after which pass two has nothing resolvable and is itself recorded honestly.
func (c *AppRoleAssignmentCollector) readCatalog(ctx context.Context, sink collect.Sink) (map[string]map[string]appRoleMeta, []servicePrincipalRef, bool, error) {
	const service = "entra.appRoleCatalog"
	resolver := map[string]map[string]appRoleMeta{}
	c.resourceAppID = map[string]string{}
	var principals []servicePrincipalRef
	url := graphBaseURL + "/servicePrincipals?$select=id,appId,displayName,appRoles"
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return resolver, principals, false, sink.Complete(c.gap(service, collect.Partial, count, "page limit reached"))
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(service, collect.Partial, count, "cancelled"))
			return resolver, principals, false, err
		}
		if !c.budget.Spend() {
			return resolver, principals, false, sink.Complete(c.gap(service, collect.Partial, count, "budget exhausted"))
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) {
				return resolver, principals, false, nil
			}
			return resolver, principals, false, err
		}
		var env struct {
			Value []struct {
				ID          string `json:"id"`
				AppID       string `json:"appId"`
				DisplayName string `json:"displayName"`
				AppRoles    []struct {
					ID          string `json:"id"`
					Value       string `json:"value"`
					DisplayName string `json:"displayName"`
				} `json:"appRoles"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			_ = sink.Complete(c.gap(service, collect.Errored, count, redact.String(err.Error())))
			return resolver, principals, false, err
		}
		_ = sink.Evidence(c.evidence(service, body))
		for _, sp := range env.Value {
			if sp.ID == "" {
				continue
			}
			principals = append(principals, servicePrincipalRef{id: sp.ID, name: sp.DisplayName})
			if sp.AppID != "" {
				c.resourceAppID[sp.ID] = sp.AppID
			}
			if len(sp.AppRoles) > 0 {
				roles := make(map[string]appRoleMeta, len(sp.AppRoles))
				for _, r := range sp.AppRoles {
					if r.ID != "" {
						roles[r.ID] = appRoleMeta{value: r.Value, displayName: r.DisplayName}
					}
				}
				resolver[sp.ID] = roles
			}
			count++
		}
		if env.NextLink == "" {
			_ = sink.Complete(c.gap(service, collect.Complete, count, ""))
			return resolver, principals, true, nil
		}
		url = env.NextLink
	}
}

// servicePrincipalRef is a principal to query for its app-role assignments.
type servicePrincipalRef struct {
	id   string
	name string
}

// readAssignments reads each principal's app-role assignments, bounded by the
// shared budget (one call per principal, so the budget caps a large tenant), and
// emits the grant graph. One principal's denied or errored read is a recorded
// reason that does not stop the rest; the aggregate completeness is Partial if any
// principal did not fully read.
func (c *AppRoleAssignmentCollector) readAssignments(ctx context.Context, sink collect.Sink, resolver map[string]map[string]appRoleMeta, principals []servicePrincipalRef, catalogOK bool) error {
	const service = "entra.appRoleAssignments"
	total := 0
	reason := ""
	if !catalogOK {
		// The principal set is incomplete because the catalog read did not fully
		// complete, so this enumeration cannot be reported Complete even if every
		// queried principal read cleanly.
		reason = "app role catalog incomplete"
	}
	for _, sp := range principals {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(service, collect.Partial, total, "cancelled"))
			return err
		}
		n, gap := c.principalAssignments(ctx, sink, resolver, sp)
		total += n
		if gap != "" {
			reason = gap
			if gap == "budget exhausted" {
				break
			}
		}
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	return sink.Complete(c.gap(service, status, total, reason))
}

// principalAssignments reads one principal's app-role assignments (paginated) and
// emits, per assignment, the resolved role node, the principal node, and the
// assumes grant edge. It returns the count emitted and a reason if the read did not
// fully complete.
func (c *AppRoleAssignmentCollector) principalAssignments(ctx context.Context, sink collect.Sink, resolver map[string]map[string]appRoleMeta, sp servicePrincipalRef) (int, string) {
	url := graphBaseURL + "/servicePrincipals/" + sp.id + "/appRoleAssignments"
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
		_ = sink.Evidence(c.evidence("entra.appRoleAssignments", body))
		var env struct {
			Value []struct {
				ID                  string `json:"id"`
				PrincipalID         string `json:"principalId"`
				PrincipalType       string `json:"principalType"`
				ResourceID          string `json:"resourceId"`
				ResourceDisplayName string `json:"resourceDisplayName"`
				AppRoleID           string `json:"appRoleId"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return count, redact.String(err.Error())
		}
		for _, a := range env.Value {
			if a.PrincipalID == "" || a.ResourceID == "" || a.AppRoleID == "" {
				continue
			}
			c.emitAssignment(sink, resolver, a.PrincipalID, a.ResourceID, a.ResourceDisplayName, a.AppRoleID)
			count++
		}
		if env.NextLink == "" {
			return count, ""
		}
		url = env.NextLink
	}
}

// emitAssignment emits the role node, the principal node, and the assumes edge for
// one app-role assignment, resolving the app-role name from the resolver.
func (c *AppRoleAssignmentCollector) emitAssignment(sink collect.Sink, resolver map[string]map[string]appRoleMeta, principalID, resourceID, resourceName, appRoleID string) {
	meta, resolved := resolver[resourceID][appRoleID]
	name := meta.value
	if name == "" {
		name = appRoleID // fall back to the raw GUID; never a guessed name
	}
	roleNativeID := resourceID + "/" + appRoleID
	a := map[string]string{
		"grant_type":         "application",
		"permission":         meta.value,
		"permission_display": meta.displayName,
		"resource_name":      resourceName,
		"resource_object_id": resourceID,
		"resource_app_id":    c.resourceAppID[resourceID],
		"app_role_id":        appRoleID,
	}
	if resolved {
		a["resolved"] = "true"
	} else {
		a["resolved"] = "false"
	}
	_ = sink.Node(collect.Node{Type: model.NodeRole, NativeID: roleNativeID, Name: name, Attributes: pruneEmptyAzure(a)})
	_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: principalID})
	_ = sink.Link(collect.Link{SourceNativeID: principalID, TargetNativeID: roleNativeID, Kind: model.EdgeAssumes,
		Conditions: attrs("grant_type", "application", "resource", resourceName)})
}

func (c *AppRoleAssignmentCollector) scope() collect.Scope { return collect.Scope{Account: c.tenantID} }

func (c *AppRoleAssignmentCollector) evidence(service string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "entra", Operation: service, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: graphAPIVersion, Collector: appRoleAssignmentCollectorID},
	}
}

func (c *AppRoleAssignmentCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return c.gap(service, status, collected, redact.String(err.Error()))
}

func (c *AppRoleAssignmentCollector) gap(service string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}
