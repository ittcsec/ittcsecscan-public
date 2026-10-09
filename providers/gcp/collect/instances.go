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

// instanceCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const instanceCollectorID = "collector:gcp.compute.instances"

const (
	// computeBaseURL is the Compute Engine v1 REST endpoint.
	computeBaseURL = "https://compute.googleapis.com/compute/v1"
	// computeAPIVersion is recorded as evidence provenance.
	computeAPIVersion = "v1"
	// instancesPageSize is the aggregatedList page size the collector requests.
	instancesPageSize = 500
)

// InstanceCollector reads a GCP project's Compute Engine instances and emits each
// as a compute node with the run-as edge to the service account it runs as
// (instance.serviceAccounts[].email). It reads instance metadata only; no console,
// serial-port, or screenshot content.
//
// It enumerates every zone through instances.aggregatedList, GCP's native
// server-side aggregation across all zones in one paginated call, rather than a
// client-side fan-out over a static zone set (ADR-0019 §1 records this deviation):
// aggregatedList achieves the same honest-completeness goal directly, needs no
// zone-list maintenance, hits one endpoint, and reports unreachable scopes in its
// own unreachables field. returnPartialSuccess=true is set (Google-recommended) so
// an unreachable scope is a represented gap, not a failed call. The read was
// verified against the Compute Engine API reference (v1, 2026-09-20):
// instances.aggregatedList is a read-only GET requiring compute.instances.list,
// paginated by pageToken, returning no secret value.
type InstanceCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewInstanceCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3), over the one
// bounded HTTP client. budget is the scan's shared call cap (nil is unlimited).
func NewInstanceCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *InstanceCollector {
	return &InstanceCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newInstanceCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newInstanceCollector(projectID string, api gcpAPI) *InstanceCollector {
	return &InstanceCollector{projectID: projectID, api: api}
}

func (c *InstanceCollector) ID() string               { return instanceCollectorID }
func (c *InstanceCollector) Provider() model.Provider { return model.GCP }

// instanceRequirements are the read-only permissions this collector needs
// (verified against the Compute Engine service reference, 2026-09-20), registered
// at init so the templates reconcile against real code (ADR-0016).
func instanceRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "compute.instances.list", By: instanceCollectorID},
	}
}

func init() {
	for _, r := range instanceRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *InstanceCollector) Requirements() []permissions.Requirement { return instanceRequirements() }

// Collect enumerates the project's instances across all zones via
// aggregatedList and emits a compute node plus a run-as edge per instance. It
// records one completeness for compute.instances (Compute is a single logical
// enumeration): Complete when every scope was reached, or Partial naming the
// unreachable scopes the response reported. A denied or throttled read is a
// represented gap; a disabled API is Unsupported; budget exhaustion is a Partial
// gap.
func (c *InstanceCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "compute.instances"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
	}
	base := fmt.Sprintf("%s/projects/%s/aggregated/instances?returnPartialSuccess=true&maxResults=%d", computeBaseURL, url.PathEscape(c.projectID), instancesPageSize)
	pageToken := ""
	count := 0
	unreachable := map[string]bool{}
	for page := 0; ; page++ {
		if page >= maxPages {
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
		u := base
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence("instances.aggregatedList", body))
		var agg instanceAggregatedList
		if err := json.Unmarshal(body, &agg); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, scoped := range agg.Items {
			for _, inst := range scoped.Instances {
				c.mapInstance(sink, inst)
				count++
			}
		}
		for _, u := range agg.Unreachables {
			if u != "" {
				unreachable[u] = true
			}
		}
		if agg.NextPageToken == "" {
			status := collect.Complete
			reason := ""
			if len(unreachable) > 0 {
				status = collect.Partial
				reason = "unreachable: " + joinSortedGCS(keysOf(unreachable))
			}
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: count, Reason: reason})
			return nil
		}
		pageToken = agg.NextPageToken
	}
}

// mapInstance emits one compute node (keyed by its full resource name) and a
// run-as edge to each attached service account. GCP hands the service account
// over directly on the instance (serviceAccounts[].email), so no separate
// resolution call is needed, unlike AWS instance profiles.
func (c *InstanceCollector) mapInstance(sink collect.Sink, inst gceInstance) {
	name := inst.Name
	if name == "" {
		return
	}
	zone := lastSegment(inst.Zone)
	arn := fmt.Sprintf("//compute.googleapis.com/projects/%s/zones/%s/instances/%s", c.projectID, zone, name)

	a := map[string]string{
		"instance_id":  inst.Id,
		"machine_type": lastSegment(inst.MachineType),
		"status":       inst.Status,
		"zone":         zone,
	}
	if inst.Tags != nil && len(inst.Tags.Items) > 0 {
		a["network_tags"] = joinSortedGCS(inst.Tags.Items)
	}
	for k, v := range inst.Labels {
		if k != "" {
			a["label:"+k] = v
		}
	}
	if len(inst.NetworkInterfaces) > 0 {
		ni := inst.NetworkInterfaces[0]
		a["network"] = lastSegment(ni.Network)
		a["subnetwork"] = lastSegment(ni.Subnetwork)
		a["internal_ip"] = ni.NetworkIP
		for _, ac := range ni.AccessConfigs {
			if ac.NatIP != "" {
				a["public_ip"] = ac.NatIP // an external IP: the reachability-relevant fact
				break
			}
		}
	}
	if s := inst.ShieldedInstanceConfig; s != nil {
		a["shielded_secure_boot"] = boolAttr(s.EnableSecureBoot)
		a["shielded_vtpm"] = boolAttr(s.EnableVtpm)
		a["shielded_integrity_monitoring"] = boolAttr(s.EnableIntegrityMonitoring)
	}
	if len(inst.ServiceAccounts) > 0 {
		a["service_account_email"] = inst.ServiceAccounts[0].Email
		a["service_account_scopes"] = joinSortedGCS(inst.ServiceAccounts[0].Scopes)
	}
	for k, v := range a {
		if v == "" {
			delete(a, k)
		}
	}
	_ = sink.Node(collect.Node{Type: model.NodeCompute, NativeID: arn, Name: name, Attributes: a})

	// Run-as edge: the instance can act as each attached service account. The SA
	// node is keyed by its bare email, matching the service-account and IAM-policy
	// collectors, so the views merge. A minimal node is emitted so the edge does
	// not dangle when the service-account collector is not in the scan.
	for _, sa := range inst.ServiceAccounts {
		if sa.Email == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: sa.Email})
		_ = sink.Link(collect.Link{SourceNativeID: arn, TargetNativeID: sa.Email, Kind: model.EdgeAssumes})
	}
}

// instanceAggregatedList is the subset of the aggregatedList response the
// collector reads: instances grouped by scope, plus the scopes that could not be
// reached (returnPartialSuccess=true).
type instanceAggregatedList struct {
	Items map[string]struct {
		Instances []gceInstance `json:"instances"`
	} `json:"items"`
	Unreachables  []string `json:"unreachables"`
	NextPageToken string   `json:"nextPageToken"`
}

// gceInstance is the subset of the Instance resource the collector reads (verified
// against the Compute Engine API reference, 2026-09-20).
type gceInstance struct {
	Id          string            `json:"id"`
	Name        string            `json:"name"`
	Zone        string            `json:"zone"`        // a full URL; the zone is its last segment
	MachineType string            `json:"machineType"` // a full URL; the type is its last segment
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Tags        *struct {
		Items []string `json:"items"`
	} `json:"tags"`
	ServiceAccounts []struct {
		Email  string   `json:"email"`
		Scopes []string `json:"scopes"`
	} `json:"serviceAccounts"`
	NetworkInterfaces []struct {
		Network       string `json:"network"`
		Subnetwork    string `json:"subnetwork"`
		NetworkIP     string `json:"networkIP"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
	ShieldedInstanceConfig *struct {
		EnableSecureBoot          *bool `json:"enableSecureBoot"`
		EnableVtpm                *bool `json:"enableVtpm"`
		EnableIntegrityMonitoring *bool `json:"enableIntegrityMonitoring"`
	} `json:"shieldedInstanceConfig"`
}

// lastSegment returns the substring after the final "/", used to reduce a GCE full
// URL (zone, machineType, network) to its short name.
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// keysOf returns a set's keys.
func keysOf(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func (c *InstanceCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *InstanceCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "compute", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: computeAPIVersion, Collector: instanceCollectorID},
	}
}

func (c *InstanceCollector) completeness(service string, collected int, err error) collect.Completeness {
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
		Status: status, Collected: collected, Reason: redact.String(err.Error()),
	}
}
