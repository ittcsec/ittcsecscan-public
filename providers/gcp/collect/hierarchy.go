package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// hierarchyCollectorID is the stable id this collector is credited with.
const hierarchyCollectorID = "collector:gcp.resourcemanager.hierarchy"

const (
	// hierarchyBaseURL is the Cloud Resource Manager API v3 endpoint. The collector only
	// issues the read-only projects.get, folders.get, and organizations.get GETs; it
	// makes no create, move, or delete call against the hierarchy.
	hierarchyBaseURL = "https://cloudresourcemanager.googleapis.com/v3"
	// hierarchyAPIVersion is recorded as evidence provenance.
	hierarchyAPIVersion = "v3"
	// maxHierarchyDepth bounds the parent walk so a malformed or cyclic parent chain
	// cannot loop forever (GCP folders nest at most ~10 deep).
	maxHierarchyDepth = 32
)

// HierarchyCollector reads a GCP project's resource-hierarchy ancestry: the folders
// and organization above it, the GCP half of the account-hierarchy domain
// (ADR-0018 §5), alongside AWS Organizations and Azure management groups. Starting
// from the resolved project, it walks the parent chain up to the organization, reading
// each ancestor's metadata (Cloud Resource Manager API v3: projects.get, folders.get,
// organizations.get, all read-only GETs, verified 2026-09-22). It never creates,
// moves, or deletes a project, folder, or organization.
//
// The leaf project is emitted as a project node keyed by its project id (so it merges
// with the node the identity collector already emits), and each ancestor as an
// organization node keyed by its full resource name (ADR-0019 §2) carrying a
// hierarchy_type of folder or organization. Every node records its parent as a
// parent_id fact (the canonical id of the parent node), so the containment chain joins
// without a synthesized edge, exactly as every other cross-reference in the graph is a
// forward-key id fact and reachability edges are deferred to the reachability engine. A project with
// no parent is an explicit standalone fact; a denied ancestor read is a represented
// Partial gap, never a silent drop and never an inferred hierarchy.
type HierarchyCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewHierarchyCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3).
func NewHierarchyCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *HierarchyCollector {
	return &HierarchyCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newHierarchyCollector is the injectable constructor tests use with a stub API.
func newHierarchyCollector(projectID string, api gcpAPI) *HierarchyCollector {
	return &HierarchyCollector{projectID: projectID, api: api}
}

func (c *HierarchyCollector) ID() string               { return hierarchyCollectorID }
func (c *HierarchyCollector) Provider() model.Provider { return model.GCP }

func hierarchyRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: hierarchyCollectorID}
	}
	return []permissions.Requirement{
		req("resourcemanager.projects.get"),
		req("resourcemanager.folders.get"),
		req("resourcemanager.organizations.get"),
	}
}

func init() {
	for _, r := range hierarchyRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *HierarchyCollector) Requirements() []permissions.Requirement { return hierarchyRequirements() }

// Collect reads the project and walks its parent chain to the organization, emitting
// one node per level with its parent recorded as a forward-key fact. One completeness
// record is produced (resourcemanager.hierarchy): Complete when the whole chain was
// read (or the project is standalone), Partial when an ancestor read was denied or the
// budget ran out, Denied or Unsupported when the project read itself was refused or the
// API is disabled.
func (c *HierarchyCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "resourcemanager.hierarchy"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
	}

	body, err := c.get(ctx, sink, "projects.get", fmt.Sprintf("%s/projects/%s", hierarchyBaseURL, url.PathEscape(c.projectID)))
	if err != nil {
		_ = sink.Complete(c.completeness(service, 0, err))
		if isDenied(err) || isThrottle(err) || isServiceDisabled(err) || isBudget(err) {
			return nil
		}
		return err
	}
	var proj crmResource
	if err := json.Unmarshal(body, &proj); err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Reason: redact.String(err.Error())})
		return fmt.Errorf("%s: decoding project: %w", service, err)
	}
	// The project node is keyed by its project id so it merges with the identity
	// collector's node; it gains the parent as a forward-key fact.
	a := map[string]string{"hierarchy_type": "project", "state": proj.State, "display_name": proj.DisplayName}
	if proj.Parent != "" {
		a["parent_id"] = crmCanonical(proj.Parent)
	}
	pruneEmptyHierarchy(a)
	_ = sink.Node(collect.Node{Type: model.NodeProject, NativeID: c.projectID, Name: firstNonEmptyHierarchy(proj.DisplayName, c.projectID), Attributes: a})

	// Walk the parent chain: folders up to the organization.
	parent := proj.Parent
	for depth := 0; parent != ""; depth++ {
		if depth >= maxHierarchyDepth {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: depth, Reason: "hierarchy depth limit reached"})
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: depth, Reason: "cancelled"})
			return err
		}
		var op string
		switch {
		case strings.HasPrefix(parent, "folders/"):
			op = "folders.get"
		case strings.HasPrefix(parent, "organizations/"):
			op = "organizations.get"
		default:
			// An unrecognized parent form: record what was read and stop rather than
			// guess at a level type.
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: depth, Reason: "unrecognized parent reference"})
			return nil
		}
		body, err := c.get(ctx, sink, op, fmt.Sprintf("%s/%s", hierarchyBaseURL, parent))
		if err != nil {
			// A denied or disabled ancestor read is a represented gap: the levels read
			// so far stand, and the chain is honestly incomplete, never inferred.
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) || isBudget(err) {
				_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: depth, Reason: c.gapReason(err)})
				return nil
			}
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: depth, Reason: redact.String(err.Error())})
			return err
		}
		var node crmResource
		if err := json.Unmarshal(body, &node); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: depth, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding %s: %w", service, parent, err)
		}
		htype := "folder"
		if op == "organizations.get" {
			htype = "organization"
		}
		na := map[string]string{"hierarchy_type": htype, "state": node.State, "display_name": node.DisplayName, "directory_customer_id": node.DirectoryCustomerID}
		if node.Parent != "" {
			na["parent_id"] = crmCanonical(node.Parent)
		}
		pruneEmptyHierarchy(na)
		_ = sink.Node(collect.Node{Type: model.NodeOrganization, NativeID: crmCanonical(parent), Name: firstNonEmptyHierarchy(node.DisplayName, lastPathSegment(parent)), Attributes: na})

		if op == "organizations.get" {
			break // reached the top of the hierarchy
		}
		parent = node.Parent
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete})
}

// get spends budget, fetches a URL, and records evidence on success. It returns
// errBudget when the budget is exhausted so the caller records a Partial gap.
func (c *HierarchyCollector) get(ctx context.Context, sink collect.Sink, op, u string) ([]byte, error) {
	if !c.budget.Spend() {
		return nil, errBudget
	}
	body, err := c.api.get(ctx, u)
	if err != nil {
		return nil, err
	}
	_ = sink.Evidence(c.evidence(op, body))
	return body, nil
}

// crmResource is the subset of a Cloud Resource Manager project, folder, or
// organization the collector reads.
type crmResource struct {
	Name                string `json:"name"`
	Parent              string `json:"parent"`
	ProjectID           string `json:"projectId"`
	State               string `json:"state"`
	DisplayName         string `json:"displayName"`
	DirectoryCustomerID string `json:"directoryCustomerId"`
}

// crmCanonical returns the full resource name for a folders/{id} or organizations/{id}
// reference, the canonical key the container node is stored under (ADR-0019 §2), so a
// child's parent_id fact joins its parent node.
func crmCanonical(ref string) string {
	return "//cloudresourcemanager.googleapis.com/" + ref
}

func firstNonEmptyHierarchy(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func pruneEmptyHierarchy(a map[string]string) {
	for k, v := range a {
		if v == "" {
			delete(a, k)
		}
	}
}

func (c *HierarchyCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *HierarchyCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "resourcemanager", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: hierarchyAPIVersion, Collector: hierarchyCollectorID},
	}
}

func (c *HierarchyCollector) gapReason(err error) string {
	switch {
	case isServiceDisabled(err):
		return "api disabled"
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	case isBudget(err):
		return "budget exhausted"
	}
	return redact.String(err.Error())
}

func (c *HierarchyCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	case isBudget(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: c.gapReason(err)}
}
