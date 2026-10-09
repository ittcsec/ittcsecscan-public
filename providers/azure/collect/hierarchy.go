package collect

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// mgCollectorID is the stable id this collector is credited with.
const mgCollectorID = "collector:azure.management.hierarchy"

// mgAPIVersion is the doc-verified Management Groups API version (2026-09-22, latest
// stable). The read returns the management-group hierarchy metadata only.
const mgAPIVersion = "2020-05-01"

// ManagementGroupCollector reads the tenant's management-group hierarchy, the Azure
// half of the account-hierarchy domain (ADR-0018 §5), alongside AWS
// Organizations and GCP org/folders. Azure management groups form the tree above
// subscriptions, and role assignments made at a management-group scope inherit down to
// every subscription beneath it, so the tree is the join the identity engine needs. In
// one read-only call it gets the tenant-root management group (whose id is the tenant
// id) with the whole child hierarchy expanded (Management Groups API 2020-05-01,
// managementGroups.get with $expand=children and $recurse=true, verified 2026-09-22).
// It makes no create, move, or delete call against the hierarchy.
//
// Each management group becomes an organization node keyed by its ARM resource id
// (ADR-0019 §2) with a hierarchy_type of management_group, and each subscription child
// is emitted as a subscription node keyed by its subscription id (so it merges with the
// node every other Azure collector emits). Every node records its parent management
// group as a parent_id forward-key fact, so the containment chain joins without a
// synthesized edge, the same discipline the GCP hierarchy collector and every other
// cross-reference in the graph follow. Per ADR-0019 §3 no verdict is synthesized. A
// denied read (the caller lacks management-group RBAC) is a represented Denied gap,
// never an inferred or silently dropped hierarchy.
type ManagementGroupCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewManagementGroupCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewManagementGroupCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *ManagementGroupCollector {
	return &ManagementGroupCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newManagementGroupCollector is the injectable constructor tests use with a stub API.
func newManagementGroupCollector(tenantID string, api armAPI) *ManagementGroupCollector {
	return &ManagementGroupCollector{tenantID: tenantID, api: api}
}

func (c *ManagementGroupCollector) ID() string               { return mgCollectorID }
func (c *ManagementGroupCollector) Provider() model.Provider { return model.Azure }

func mgRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.Azure, Profile: permissions.Discovery,
		Permission: "Microsoft.Management/managementGroups/read", By: mgCollectorID,
	}}
}

func init() {
	for _, r := range mgRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permission the collector needs.
func (c *ManagementGroupCollector) Requirements() []permissions.Requirement { return mgRequirements() }

// Collect gets the tenant-root management group with its full child hierarchy and
// emits one node per management group and subscription, each with its parent recorded
// as a forward-key fact. One completeness record is produced (management.hierarchy):
// Complete when the tree was read, Denied or Partial when the read was refused or
// throttled. A caller without management-group RBAC surfaces as Denied, never a silent
// pass.
func (c *ManagementGroupCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "management.hierarchy"
	if c.tenantID == "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "no tenant id resolved"})
	}
	if !c.budget.Spend() {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
	}
	url := fmt.Sprintf("%s/providers/Microsoft.Management/managementGroups/%s?api-version=%s&$expand=children&$recurse=true", armBaseURL, c.tenantID, mgAPIVersion)
	body, err := c.api.get(ctx, url)
	if err != nil {
		return sink.Complete(c.completeness(service, 0, err))
	}
	_ = sink.Evidence(c.evidence("managementGroups.get", body))

	var root managementGroup
	if err := json.Unmarshal(body, &root); err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Reason: redact.String(err.Error())})
		return fmt.Errorf("%s: decoding: %w", service, err)
	}

	count := 0
	if root.ID != "" {
		a := map[string]string{"hierarchy_type": "management_group", "display_name": root.Properties.DisplayName, "tenant_id": root.Properties.TenantID, "is_root": "true"}
		if p := root.Properties.Details.Parent; p != nil && p.ID != "" {
			a["parent_id"] = p.ID
			a["is_root"] = "false"
		}
		_ = sink.Node(collect.Node{Type: model.NodeOrganization, NativeID: root.ID, Name: root.Name, Attributes: pruneEmptyAzure(a)})
		count++
		count += c.walk(sink, root.ID, root.Properties.Children)
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
}

// walk emits each child of parentID (a management group or a subscription) and recurses
// into child management groups, returning the number of nodes emitted.
func (c *ManagementGroupCollector) walk(sink collect.Sink, parentID string, children []mgChild) int {
	n := 0
	for _, ch := range children {
		if ch.ID == "" {
			continue
		}
		if ch.Type == "/subscriptions" {
			// Keyed by subscription id so it merges with every other Azure collector's
			// subscription node; it gains the parent management group as a fact.
			_ = sink.Node(collect.Node{Type: model.NodeSubscription, NativeID: ch.Name, Name: ch.DisplayName,
				Attributes: attrs("parent_id", parentID, "display_name", ch.DisplayName)})
			n++
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeOrganization, NativeID: ch.ID, Name: ch.Name,
			Attributes: attrs("hierarchy_type", "management_group", "display_name", ch.DisplayName, "parent_id", parentID)})
		n++
		n += c.walk(sink, ch.ID, ch.Children)
	}
	return n
}

type managementGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Properties struct {
		TenantID    string    `json:"tenantId"`
		DisplayName string    `json:"displayName"`
		Children    []mgChild `json:"children"`
		Details     struct {
			Parent *struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"parent"`
		} `json:"details"`
	} `json:"properties"`
}

type mgChild struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	DisplayName string    `json:"displayName"`
	Children    []mgChild `json:"children"`
}

func (c *ManagementGroupCollector) scope() collect.Scope { return collect.Scope{Account: c.tenantID} }

func (c *ManagementGroupCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "management", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: mgAPIVersion, Collector: mgCollectorID},
	}
}

func (c *ManagementGroupCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: redact.String(err.Error())}
}
