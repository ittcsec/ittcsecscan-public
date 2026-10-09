package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// networkCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const networkCollectorID = "collector:gcp.compute.network"

// networkPageSize is the page size the collector requests for every list.
const networkPageSize = 500

// NetworkCollector reads a GCP project's VPC networking topology: networks,
// subnetworks, firewall rules, and routes, plus the reachability edge of the
// network (Cloud Routers with their Cloud NAT config, reserved external and
// internal addresses, and load-balancer forwarding rules), regional and global. It
// is the configuration input the reachability engine consumes, the GCP
// counterpart of the AWS network collector, and it produces the same
// nodes-and-attributes-only shape so both clouds' topology looks structurally
// identical to whatever consumes it later (a Cloud NAT router maps to the same
// gateway node type as an AWS NAT gateway, a reserved address to the same endpoint
// node type as an Elastic IP).
//
// Per ADR-0019 §3 it emits nodes and attributes only, no edges: reachability
// (routes_to, exposed_to) is the output. Firewall allow/deny rules, route
// next-hops, VPC peerings, and subnet secondary ranges are recorded as sorted
// canonical-JSON facts, and cross-references (the network a subnet, firewall, or
// route belongs to, and a route's next-hop target) are recorded as id facts, so
// the reachability engine can join them later. It never concludes that anything is
// public or reachable; "no ingress rule" and "flow logs off" are recorded as
// facts, never gaps.
//
// Enumeration matches each resource to its native shape (ADR-0020): global
// resources (networks, firewalls, routes, global addresses, global forwarding
// rules) use a plain list; regional resources (subnetworks, routers, addresses,
// forwarding rules) use aggregatedList (server-side aggregation across all regions
// in one paginated call, with an unreachables field), the same mechanism the
// instances collector uses. The reads were verified against the Compute Engine API
// reference (discovery document revision 20260910): each is a read-only GET
// requiring the matching compute.*.list permission, paginated by pageToken,
// returning no secret value.
type NetworkCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewNetworkCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3), over the one
// bounded HTTP client. budget is the scan's shared call cap (nil is unlimited).
func NewNetworkCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *NetworkCollector {
	return &NetworkCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newNetworkCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newNetworkCollector(projectID string, api gcpAPI) *NetworkCollector {
	return &NetworkCollector{projectID: projectID, api: api}
}

func (c *NetworkCollector) ID() string               { return networkCollectorID }
func (c *NetworkCollector) Provider() model.Provider { return model.GCP }

// networkRequirements are the read-only permissions this collector needs (verified
// against the Compute Engine service reference, 2026-09-20), registered at init so
// the templates reconcile against real code (ADR-0016).
func networkRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: networkCollectorID}
	}
	return []permissions.Requirement{
		req("compute.networks.list"),
		req("compute.subnetworks.list"),
		req("compute.firewalls.list"),
		req("compute.routes.list"),
		req("compute.routers.list"),
		req("compute.addresses.list"),
		req("compute.globalAddresses.list"),
		req("compute.forwardingRules.list"),
		req("compute.globalForwardingRules.list"),
	}
}

func init() {
	for _, r := range networkRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *NetworkCollector) Requirements() []permissions.Requirement { return networkRequirements() }

// netResource is one VPC enumeration: its completeness service name, the API
// operation (for evidence), the path under the project (global or aggregated),
// whether it is an aggregatedList (so the unreachables field is honoured), and a
// decoder that maps one page's items to nodes and reports the page's count,
// unreachable scopes, and next-page token.
type netResource struct {
	service    string
	operation  string
	path       string
	aggregated bool
	decode     func(sink collect.Sink, body []byte) (n int, unreachable []string, next string, err error)
}

// resources is the fixed, ordered enumeration list: deterministic output and
// deterministic budget consumption. Networks come first so a reader sees the VPCs
// before the resources that reference them.
func (c *NetworkCollector) resources() []netResource {
	return []netResource{
		{"compute.networks", "networks.list", "global/networks", false, c.decodeNetworks},
		{"compute.subnetworks", "subnetworks.aggregatedList", "aggregated/subnetworks", true, c.decodeSubnetworks},
		{"compute.firewalls", "firewalls.list", "global/firewalls", false, c.decodeFirewalls},
		{"compute.routes", "routes.list", "global/routes", false, c.decodeRoutes},
		// The reachability edge of the network: Cloud NAT (egress), reserved external
		// and internal addresses, and load-balancer forwarding rules (ingress). Same
		// substrate, same collector; regional resources use aggregatedList and their
		// global counterparts a plain list (ADR-0020).
		{"compute.routers", "routers.aggregatedList", "aggregated/routers", true, c.decodeRouters},
		{"compute.addresses", "addresses.aggregatedList", "aggregated/addresses", true, c.decodeAddresses},
		{"compute.globalAddresses", "globalAddresses.list", "global/addresses", false, c.decodeGlobalAddresses},
		{"compute.forwardingRules", "forwardingRules.aggregatedList", "aggregated/forwardingRules", true, c.decodeForwardingRules},
		{"compute.globalForwardingRules", "globalForwardingRules.list", "global/forwardingRules", false, c.decodeGlobalForwardingRules},
	}
}

// Collect enumerates every resource in the fixed order, recording one completeness
// record per resource. A denied read is a Denied gap, a disabled API is
// Unsupported, a throttle is Partial, and budget exhaustion marks the resources not
// yet reached Partial "budget exhausted"; none becomes a pass. For subnetworks an
// unreachable scope reported in the response makes that one record Partial. An
// unexpected error is Errored, the rest still run, and the errors surface.
func (c *NetworkCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		for _, r := range c.resources() {
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
		}
		return nil
	}
	var errs []error
	exhausted := false
	for _, r := range c.resources() {
		if exhausted {
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
			continue
		}
		budgetOut, err := c.enumerate(ctx, sink, r)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, err)
		}
		exhausted = budgetOut
	}
	return errors.Join(errs...)
}

// enumerate paginates one resource and records its completeness. It reports whether
// the budget ran out. A denied, throttled, or service-disabled read is a
// represented gap and collection continues; anything else surfaces.
func (c *NetworkCollector) enumerate(ctx context.Context, sink collect.Sink, r netResource) (budgetOut bool, err error) {
	params := "maxResults=" + strconv.Itoa(networkPageSize)
	if r.aggregated {
		params += "&returnPartialSuccess=true"
	}
	base := fmt.Sprintf("%s/projects/%s/%s?%s", computeBaseURL, url.PathEscape(c.projectID), r.path, params)
	pageToken := ""
	count := 0
	unreachable := map[string]bool{}
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "page limit reached"})
			return false, nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return true, nil
		}
		u := base
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			_ = sink.Complete(c.completeness(r.service, count, err))
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return false, nil
			}
			return false, err
		}
		_ = sink.Evidence(c.evidence(r.operation, body))
		n, unreach, next, derr := r.decode(sink, body)
		if derr != nil {
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(derr.Error())})
			return false, fmt.Errorf("%s: decoding page: %w", r.service, derr)
		}
		count += n
		for _, s := range unreach {
			if s != "" {
				unreachable[s] = true
			}
		}
		if next == "" {
			status := collect.Complete
			reason := ""
			if len(unreachable) > 0 {
				status = collect.Partial
				reason = "unreachable: " + joinSortedGCS(keysOf(unreachable))
			}
			_ = sink.Complete(collect.Completeness{Service: r.service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: count, Reason: reason})
			return false, nil
		}
		pageToken = next
	}
}

// resourceName builds a GCP full resource name for a compute resource under this
// project (ADR-0019 §2), for example
// //compute.googleapis.com/projects/{p}/global/networks/{name}.
func (c *NetworkCollector) resourceName(scope, kind, name string) string {
	return fmt.Sprintf("//compute.googleapis.com/projects/%s/%s/%s/%s", c.projectID, scope, kind, name)
}

func (c *NetworkCollector) decodeNetworks(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items         []gcpNetwork `json:"items"`
		NextPageToken string       `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	for _, n := range page.Items {
		c.mapNetwork(sink, n)
	}
	return len(page.Items), nil, page.NextPageToken, nil
}

func (c *NetworkCollector) mapNetwork(sink collect.Sink, n gcpNetwork) {
	if n.Name == "" {
		return
	}
	a := map[string]string{
		"network_id":                 n.Id,
		"legacy_ipv4_range":          n.IPv4Range, // set only on legacy networks
		"gateway_ipv4":               n.GatewayIPv4,
		"internal_ipv6_range":        n.InternalIpv6Range,
		"firewall_policy":            lastSegment(n.FirewallPolicy),
		"firewall_enforcement_order": n.NetworkFirewallPolicyEnforcementOrder,
		"auto_create_subnetworks":    boolAttr(n.AutoCreateSubnetworks),
		"enable_ula_internal_ipv6":   boolAttr(n.EnableUlaInternalIpv6),
		"subnetwork_count":           strconv.Itoa(len(n.Subnetworks)),
	}
	if n.RoutingConfig != nil {
		a["routing_mode"] = n.RoutingConfig.RoutingMode
	}
	if n.Mtu > 0 {
		a["mtu"] = strconv.Itoa(n.Mtu)
	}
	if len(n.Peerings) > 0 {
		peerings := make([]peeringFact, 0, len(n.Peerings))
		for _, p := range n.Peerings {
			peerings = append(peerings, peeringFact{
				Name: p.Name, Network: p.Network, State: p.State,
				ExchangeSubnetRoutes:  boolPtr(p.ExchangeSubnetRoutes),
				ExportCustomRoutes:    boolPtr(p.ExportCustomRoutes),
				ImportCustomRoutes:    boolPtr(p.ImportCustomRoutes),
				ExportSubnetWithPubIP: boolPtr(p.ExportSubnetRoutesWithPublicIp),
				ImportSubnetWithPubIP: boolPtr(p.ImportSubnetRoutesWithPublicIp),
			})
		}
		sort.Slice(peerings, func(i, j int) bool { return peerings[i].Name < peerings[j].Name })
		a["peerings"] = canonicalJSON(peerings)
	}
	_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: c.resourceName("global", "networks", n.Name), Name: n.Name, Attributes: pruneEmptyGCP(a)})
}

func (c *NetworkCollector) decodeSubnetworks(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items map[string]struct {
			Subnetworks []gcpSubnetwork `json:"subnetworks"`
		} `json:"items"`
		Unreachables  []string `json:"unreachables"`
		NextPageToken string   `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	n := 0
	for _, scoped := range page.Items {
		for _, s := range scoped.Subnetworks {
			c.mapSubnetwork(sink, s)
			n++
		}
	}
	return n, page.Unreachables, page.NextPageToken, nil
}

func (c *NetworkCollector) mapSubnetwork(sink collect.Sink, s gcpSubnetwork) {
	if s.Name == "" {
		return
	}
	region := lastSegment(s.Region)
	// Flow logs: the newer logConfig.enable governs when present, else the legacy
	// enableFlowLogs toggle. Absent means off, recorded as a fact.
	flow := s.EnableFlowLogs
	if s.LogConfig != nil {
		flow = s.LogConfig.Enable
	}
	a := map[string]string{
		"subnetwork_id":              s.Id,
		"network":                    lastSegment(s.Network),
		"ip_cidr_range":              s.IpCidrRange,
		"region":                     region,
		"gateway_address":            s.GatewayAddress,
		"purpose":                    s.Purpose,
		"role":                       s.Role,
		"stack_type":                 s.StackType,
		"ipv6_access_type":           s.Ipv6AccessType,
		"ipv6_cidr_range":            s.Ipv6CidrRange,
		"internal_ipv6_prefix":       s.InternalIpv6Prefix,
		"external_ipv6_prefix":       s.ExternalIpv6Prefix,
		"private_ipv6_google_access": s.PrivateIpv6GoogleAccess,
		"state":                      s.State,
		// These two are security-relevant defaults: absent means off, recorded as an
		// explicit fact (false), never dropped (decision c, not-configured is a fact).
		"private_ip_google_access": boolOrFalse(s.PrivateIpGoogleAccess),
		"flow_logs":                boolOrFalse(flow),
	}
	if len(s.SecondaryIpRanges) > 0 {
		ranges := make([]secondaryRangeFact, 0, len(s.SecondaryIpRanges))
		for _, r := range s.SecondaryIpRanges {
			ranges = append(ranges, secondaryRangeFact{RangeName: r.RangeName, IpCidrRange: r.IpCidrRange})
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].RangeName < ranges[j].RangeName })
		a["secondary_ranges"] = canonicalJSON(ranges)
	}
	_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: c.resourceName("regions/"+region, "subnetworks", s.Name), Name: s.Name, Attributes: pruneEmptyGCP(a)})
}

func (c *NetworkCollector) decodeFirewalls(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items         []gcpFirewall `json:"items"`
		NextPageToken string        `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	for _, f := range page.Items {
		c.mapFirewall(sink, f)
	}
	return len(page.Items), nil, page.NextPageToken, nil
}

func (c *NetworkCollector) mapFirewall(sink collect.Sink, f gcpFirewall) {
	if f.Name == "" {
		return
	}
	a := map[string]string{
		"firewall_id": f.Id,
		"network":     lastSegment(f.Network),
		"direction":   f.Direction,
		"priority":    strconv.Itoa(f.Priority),
		// A firewall is enabled unless disabled is true; absent means enabled,
		// recorded as an explicit fact (false).
		"disabled":                boolOrFalse(f.Disabled),
		"source_ranges":           joinSortedGCS(f.SourceRanges),
		"destination_ranges":      joinSortedGCS(f.DestinationRanges),
		"source_tags":             joinSortedGCS(f.SourceTags),
		"target_tags":             joinSortedGCS(f.TargetTags),
		"source_service_accounts": joinSortedGCS(f.SourceServiceAccounts),
		"target_service_accounts": joinSortedGCS(f.TargetServiceAccounts),
		// Rules are recorded in full, including an empty list, because "no rules" is
		// itself a fact. Exactly one of allowed or denied is populated per rule.
		"allowed_rules": protoRules(f.Allowed),
		"denied_rules":  protoRules(f.Denied),
	}
	if f.LogConfig != nil {
		a["log_config_enabled"] = boolAttr(f.LogConfig.Enable)
	}
	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: c.resourceName("global", "firewalls", f.Name), Name: f.Name, Attributes: pruneEmptyGCP(a)})
}

func (c *NetworkCollector) decodeRoutes(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items         []gcpRoute `json:"items"`
		NextPageToken string     `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	for _, r := range page.Items {
		c.mapRoute(sink, r)
	}
	return len(page.Items), nil, page.NextPageToken, nil
}

func (c *NetworkCollector) mapRoute(sink collect.Sink, r gcpRoute) {
	if r.Name == "" {
		return
	}
	a := map[string]string{
		"route_id":     r.Id,
		"network":      lastSegment(r.Network),
		"dest_range":   r.DestRange,
		"priority":     strconv.Itoa(r.Priority),
		"tags":         joinSortedGCS(r.Tags),
		"route_type":   r.RouteType,
		"route_status": r.RouteStatus,
	}
	// The next hop is the reachability-critical fact (a default route to
	// default-internet-gateway means the network reaches the internet). Record the
	// first populated next-hop field as a type plus target, URL-valued hops reduced
	// to their last segment, the bare IP hop kept as is.
	for _, h := range []struct{ kind, val string }{
		{"gateway", lastSegment(r.NextHopGateway)},
		{"instance", lastSegment(r.NextHopInstance)},
		{"ip", r.NextHopIp},
		{"ilb", lastSegment(r.NextHopIlb)},
		{"vpn_tunnel", lastSegment(r.NextHopVpnTunnel)},
		{"peering", r.NextHopPeering},
		{"network", lastSegment(r.NextHopNetwork)},
		{"hub", lastSegment(r.NextHopHub)},
		{"interconnect_attachment", lastSegment(r.NextHopInterconnectAttachment)},
	} {
		if h.val != "" {
			a["next_hop_type"], a["next_hop"] = h.kind, h.val
			break
		}
	}
	_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: c.resourceName("global", "routes", r.Name), Name: r.Name, Attributes: pruneEmptyGCP(a)})
}

func (c *NetworkCollector) decodeRouters(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items map[string]struct {
			Routers []gcpRouter `json:"routers"`
		} `json:"items"`
		Unreachables  []string `json:"unreachables"`
		NextPageToken string   `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	n := 0
	for _, scoped := range page.Items {
		for _, r := range scoped.Routers {
			c.mapRouter(sink, r)
			n++
		}
	}
	return n, page.Unreachables, page.NextPageToken, nil
}

// mapRouter emits one gateway node per Cloud Router with its Cloud NAT configuration
// (the egress-to-internet signal) as a canonical-JSON fact. A router with no nats is
// recorded as such (a fact), not dropped.
func (c *NetworkCollector) mapRouter(sink collect.Sink, r gcpRouter) {
	if r.Name == "" {
		return
	}
	region := lastSegment(r.Region)
	a := map[string]string{
		"router_id":                     r.Id,
		"network":                       lastSegment(r.Network),
		"region":                        region,
		"encrypted_interconnect_router": boolAttr(r.EncryptedInterconnectRouter),
		"bgp_peer_count":                strconv.Itoa(len(r.BgpPeers)),
		"interface_count":               strconv.Itoa(len(r.Interfaces)),
	}
	nats := make([]natFact, 0, len(r.Nats))
	for _, n := range r.Nats {
		f := natFact{
			Name: n.Name, Type: n.Type, NatIPAllocateOption: n.NatIPAllocateOption,
			SourceSubnetRangesToNat: n.SourceSubnetworkIPRangesToNat,
			NatIPs:                  lastSegments(n.NatIPs),
		}
		if n.LogConfig != nil {
			f.LogEnabled = n.LogConfig.Enable
		}
		nats = append(nats, f)
	}
	sort.Slice(nats, func(i, j int) bool { return nats[i].Name < nats[j].Name })
	a["nats"] = canonicalJSON(nats)
	_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: c.resourceName("regions/"+region, "routers", r.Name), Name: r.Name, Attributes: pruneEmptyGCP(a)})
}

func (c *NetworkCollector) decodeAddresses(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items map[string]struct {
			Addresses []gcpAddress `json:"addresses"`
		} `json:"items"`
		Unreachables  []string `json:"unreachables"`
		NextPageToken string   `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	n := 0
	for _, scoped := range page.Items {
		for _, ad := range scoped.Addresses {
			c.mapAddress(sink, ad)
			n++
		}
	}
	return n, page.Unreachables, page.NextPageToken, nil
}

func (c *NetworkCollector) decodeGlobalAddresses(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items         []gcpAddress `json:"items"`
		NextPageToken string       `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	for _, ad := range page.Items {
		c.mapAddress(sink, ad)
	}
	return len(page.Items), nil, page.NextPageToken, nil
}

// mapAddress emits one endpoint node per reserved address, regional or global (a
// global address reports no region). Both external and internal addresses are
// recorded as facts; no "exposed" verdict is synthesized.
func (c *NetworkCollector) mapAddress(sink collect.Sink, ad gcpAddress) {
	if ad.Name == "" {
		return
	}
	region := lastSegment(ad.Region)
	scope, regionAttr := "global", "global"
	if region != "" {
		scope, regionAttr = "regions/"+region, region
	}
	a := map[string]string{
		"address_id":   ad.Id,
		"address":      ad.Address,
		"address_type": ad.AddressType,
		"purpose":      ad.Purpose,
		"status":       ad.Status,
		"network_tier": ad.NetworkTier,
		"ip_version":   ad.IPVersion,
		"region":       regionAttr,
		"network":      lastSegment(ad.Network),
		"subnetwork":   lastSegment(ad.Subnetwork),
		"users":        joinSortedGCS(lastSegments(ad.Users)),
	}
	if ad.PrefixLength > 0 {
		a["prefix_length"] = strconv.Itoa(ad.PrefixLength)
	}
	_ = sink.Node(collect.Node{Type: model.NodeEndpoint, NativeID: c.resourceName(scope, "addresses", ad.Name), Name: ad.Name, Attributes: pruneEmptyGCP(a)})
}

func (c *NetworkCollector) decodeForwardingRules(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items map[string]struct {
			ForwardingRules []gcpForwardingRule `json:"forwardingRules"`
		} `json:"items"`
		Unreachables  []string `json:"unreachables"`
		NextPageToken string   `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	n := 0
	for _, scoped := range page.Items {
		for _, fr := range scoped.ForwardingRules {
			c.mapForwardingRule(sink, fr)
			n++
		}
	}
	return n, page.Unreachables, page.NextPageToken, nil
}

func (c *NetworkCollector) decodeGlobalForwardingRules(sink collect.Sink, body []byte) (int, []string, string, error) {
	var page struct {
		Items         []gcpForwardingRule `json:"items"`
		NextPageToken string              `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, nil, "", err
	}
	for _, fr := range page.Items {
		c.mapForwardingRule(sink, fr)
	}
	return len(page.Items), nil, page.NextPageToken, nil
}

// mapForwardingRule emits one gateway node per forwarding rule, the load-balancer
// ingress front-end that maps an IP and port to a target or backend. The address,
// protocol, ports, scheme, and target are recorded as facts; no reachability verdict
// is synthesized.
func (c *NetworkCollector) mapForwardingRule(sink collect.Sink, fr gcpForwardingRule) {
	if fr.Name == "" {
		return
	}
	region := lastSegment(fr.Region)
	scope, regionAttr := "global", "global"
	if region != "" {
		scope, regionAttr = "regions/"+region, region
	}
	a := map[string]string{
		"forwarding_rule_id":    fr.Id,
		"ip_address":            fr.IPAddress,
		"ip_protocol":           fr.IPProtocol,
		"port_range":            fr.PortRange,
		"all_ports":             boolAttr(fr.AllPorts),
		"load_balancing_scheme": fr.LoadBalancingScheme,
		"network_tier":          fr.NetworkTier,
		"region":                regionAttr,
		"target":                lastSegment(fr.Target),
		"backend_service":       lastSegment(fr.BackendService),
		"network":               lastSegment(fr.Network),
		"subnetwork":            lastSegment(fr.Subnetwork),
		"ports":                 joinSortedGCS(fr.Ports),
		"source_ip_ranges":      joinSortedGCS(fr.SourceIPRanges),
		"allow_global_access":   boolAttr(fr.AllowGlobalAccess),
	}
	_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: c.resourceName(scope, "forwardingRules", fr.Name), Name: fr.Name, Attributes: pruneEmptyGCP(a)})
}

// natFact is one Cloud NAT configuration on a router as reported.
type natFact struct {
	Name                    string   `json:"name"`
	Type                    string   `json:"type,omitempty"`
	NatIPAllocateOption     string   `json:"nat_ip_allocate_option,omitempty"`
	NatIPs                  []string `json:"nat_ips,omitempty"`
	SourceSubnetRangesToNat string   `json:"source_subnet_ranges_to_nat,omitempty"`
	LogEnabled              *bool    `json:"log_enabled,omitempty"`
}

// gcpRouter is the subset of the Router resource the collector reads.
type gcpRouter struct {
	Id                          string     `json:"id"`
	Name                        string     `json:"name"`
	Network                     string     `json:"network"`
	Region                      string     `json:"region"`
	EncryptedInterconnectRouter *bool      `json:"encryptedInterconnectRouter"`
	Interfaces                  []struct{} `json:"interfaces"`
	BgpPeers                    []struct{} `json:"bgpPeers"`
	Nats                        []gcpNat   `json:"nats"`
}

// gcpNat is the subset of RouterNat the collector reads.
type gcpNat struct {
	Name                          string   `json:"name"`
	Type                          string   `json:"type"`
	NatIPAllocateOption           string   `json:"natIpAllocateOption"`
	NatIPs                        []string `json:"natIps"`
	SourceSubnetworkIPRangesToNat string   `json:"sourceSubnetworkIpRangesToNat"`
	LogConfig                     *struct {
		Enable *bool `json:"enable"`
	} `json:"logConfig"`
}

// gcpAddress is the subset of the Address resource the collector reads (shared by
// the regional and global address lists).
type gcpAddress struct {
	Id           string   `json:"id"`
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	AddressType  string   `json:"addressType"`
	Purpose      string   `json:"purpose"`
	Status       string   `json:"status"`
	NetworkTier  string   `json:"networkTier"`
	IPVersion    string   `json:"ipVersion"`
	PrefixLength int      `json:"prefixLength"`
	Region       string   `json:"region"`
	Network      string   `json:"network"`
	Subnetwork   string   `json:"subnetwork"`
	Users        []string `json:"users"`
}

// gcpForwardingRule is the subset of the ForwardingRule resource the collector reads
// (shared by the regional and global forwarding-rule lists).
type gcpForwardingRule struct {
	Id                  string   `json:"id"`
	Name                string   `json:"name"`
	IPAddress           string   `json:"IPAddress"`
	IPProtocol          string   `json:"IPProtocol"`
	PortRange           string   `json:"portRange"`
	Ports               []string `json:"ports"`
	AllPorts            *bool    `json:"allPorts"`
	LoadBalancingScheme string   `json:"loadBalancingScheme"`
	NetworkTier         string   `json:"networkTier"`
	Target              string   `json:"target"`
	BackendService      string   `json:"backendService"`
	Network             string   `json:"network"`
	Subnetwork          string   `json:"subnetwork"`
	Region              string   `json:"region"`
	SourceIPRanges      []string `json:"sourceIpRanges"`
	AllowGlobalAccess   *bool    `json:"allowGlobalAccess"`
}

// lastSegments reduces each string in a slice to its last path segment.
func lastSegments(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, lastSegment(x))
	}
	return out
}

// peeringFact is one VPC peering as reported.
type peeringFact struct {
	Name                  string `json:"name"`
	Network               string `json:"network,omitempty"`
	State                 string `json:"state,omitempty"`
	ExchangeSubnetRoutes  *bool  `json:"exchange_subnet_routes,omitempty"`
	ExportCustomRoutes    *bool  `json:"export_custom_routes,omitempty"`
	ImportCustomRoutes    *bool  `json:"import_custom_routes,omitempty"`
	ExportSubnetWithPubIP *bool  `json:"export_subnet_routes_with_public_ip,omitempty"`
	ImportSubnetWithPubIP *bool  `json:"import_subnet_routes_with_public_ip,omitempty"`
}

// secondaryRangeFact is one subnet secondary range as reported.
type secondaryRangeFact struct {
	RangeName   string `json:"range_name"`
	IpCidrRange string `json:"ip_cidr_range"`
}

// protoFact is one firewall protocol+ports entry as reported. Protocol "all" means
// every protocol.
type protoFact struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports,omitempty"`
}

// protoRules renders a firewall's allowed or denied list as sorted canonical JSON,
// including an empty list (which is itself a fact).
func protoRules(ps []gcpProto) string {
	out := make([]protoFact, 0, len(ps))
	for _, p := range ps {
		out = append(out, protoFact{Protocol: p.IPProtocol, Ports: p.Ports})
	}
	sort.Slice(out, func(i, j int) bool { return canonicalJSON(out[i]) < canonicalJSON(out[j]) })
	return canonicalJSON(out)
}

// gcpNetwork is the subset of the Network resource the collector reads (verified
// against the discovery document, revision 20260910).
type gcpNetwork struct {
	Id                                    string   `json:"id"`
	Name                                  string   `json:"name"`
	AutoCreateSubnetworks                 *bool    `json:"autoCreateSubnetworks"`
	IPv4Range                             string   `json:"IPv4Range"`
	GatewayIPv4                           string   `json:"gatewayIPv4"`
	InternalIpv6Range                     string   `json:"internalIpv6Range"`
	EnableUlaInternalIpv6                 *bool    `json:"enableUlaInternalIpv6"`
	FirewallPolicy                        string   `json:"firewallPolicy"`
	NetworkFirewallPolicyEnforcementOrder string   `json:"networkFirewallPolicyEnforcementOrder"`
	Mtu                                   int      `json:"mtu"`
	Subnetworks                           []string `json:"subnetworks"`
	RoutingConfig                         *struct {
		RoutingMode string `json:"routingMode"`
	} `json:"routingConfig"`
	Peerings []struct {
		Name                           string `json:"name"`
		Network                        string `json:"network"`
		State                          string `json:"state"`
		ExchangeSubnetRoutes           *bool  `json:"exchangeSubnetRoutes"`
		ExportCustomRoutes             *bool  `json:"exportCustomRoutes"`
		ImportCustomRoutes             *bool  `json:"importCustomRoutes"`
		ExportSubnetRoutesWithPublicIp *bool  `json:"exportSubnetRoutesWithPublicIp"`
		ImportSubnetRoutesWithPublicIp *bool  `json:"importSubnetRoutesWithPublicIp"`
	} `json:"peerings"`
}

// gcpSubnetwork is the subset of the Subnetwork resource the collector reads.
type gcpSubnetwork struct {
	Id                      string `json:"id"`
	Name                    string `json:"name"`
	Network                 string `json:"network"`
	IpCidrRange             string `json:"ipCidrRange"`
	Region                  string `json:"region"`
	GatewayAddress          string `json:"gatewayAddress"`
	PrivateIpGoogleAccess   *bool  `json:"privateIpGoogleAccess"`
	EnableFlowLogs          *bool  `json:"enableFlowLogs"`
	Purpose                 string `json:"purpose"`
	Role                    string `json:"role"`
	StackType               string `json:"stackType"`
	Ipv6AccessType          string `json:"ipv6AccessType"`
	Ipv6CidrRange           string `json:"ipv6CidrRange"`
	InternalIpv6Prefix      string `json:"internalIpv6Prefix"`
	ExternalIpv6Prefix      string `json:"externalIpv6Prefix"`
	PrivateIpv6GoogleAccess string `json:"privateIpv6GoogleAccess"`
	State                   string `json:"state"`
	LogConfig               *struct {
		Enable *bool `json:"enable"`
	} `json:"logConfig"`
	SecondaryIpRanges []struct {
		RangeName   string `json:"rangeName"`
		IpCidrRange string `json:"ipCidrRange"`
	} `json:"secondaryIpRanges"`
}

// gcpProto is one firewall protocol+ports entry (Firewall.allowed[]/denied[]).
type gcpProto struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}

// gcpFirewall is the subset of the Firewall resource the collector reads.
type gcpFirewall struct {
	Id                    string     `json:"id"`
	Name                  string     `json:"name"`
	Network               string     `json:"network"`
	Direction             string     `json:"direction"`
	Priority              int        `json:"priority"`
	Disabled              *bool      `json:"disabled"`
	SourceRanges          []string   `json:"sourceRanges"`
	DestinationRanges     []string   `json:"destinationRanges"`
	SourceTags            []string   `json:"sourceTags"`
	TargetTags            []string   `json:"targetTags"`
	SourceServiceAccounts []string   `json:"sourceServiceAccounts"`
	TargetServiceAccounts []string   `json:"targetServiceAccounts"`
	Allowed               []gcpProto `json:"allowed"`
	Denied                []gcpProto `json:"denied"`
	LogConfig             *struct {
		Enable *bool `json:"enable"`
	} `json:"logConfig"`
}

// gcpRoute is the subset of the Route resource the collector reads.
type gcpRoute struct {
	Id                            string   `json:"id"`
	Name                          string   `json:"name"`
	Network                       string   `json:"network"`
	DestRange                     string   `json:"destRange"`
	Priority                      int      `json:"priority"`
	Tags                          []string `json:"tags"`
	RouteType                     string   `json:"routeType"`
	RouteStatus                   string   `json:"routeStatus"`
	NextHopGateway                string   `json:"nextHopGateway"`
	NextHopInstance               string   `json:"nextHopInstance"`
	NextHopIp                     string   `json:"nextHopIp"`
	NextHopNetwork                string   `json:"nextHopNetwork"`
	NextHopVpnTunnel              string   `json:"nextHopVpnTunnel"`
	NextHopIlb                    string   `json:"nextHopIlb"`
	NextHopPeering                string   `json:"nextHopPeering"`
	NextHopHub                    string   `json:"nextHopHub"`
	NextHopInterconnectAttachment string   `json:"nextHopInterconnectAttachment"`
}

func (c *NetworkCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *NetworkCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "compute", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: computeAPIVersion, Collector: networkCollectorID},
	}
}

func (c *NetworkCollector) completeness(service string, collected int, err error) collect.Completeness {
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

// boolPtr returns a copy of a *bool for embedding in a fact struct, so an unset
// optional stays absent (omitempty) rather than becoming a default false.
func boolPtr(b *bool) *bool { return b }

// boolOrFalse renders a *bool where an absent value is a meaningful "off" default,
// so a security-relevant toggle is always recorded as an explicit fact rather than
// dropped as empty.
func boolOrFalse(b *bool) string {
	if b != nil && *b {
		return "true"
	}
	return "false"
}

// pruneEmptyGCP drops empty-string attributes so an unset optional is simply not
// asserted (a boolean is "true"/"false", never empty, so it is always kept).
func pruneEmptyGCP(a map[string]string) map[string]string {
	for k, v := range a {
		if v == "" {
			delete(a, k)
		}
	}
	return a
}

// canonicalJSON renders v as compact JSON. Callers pass sorted slices of fixed
// structs, so equal inputs always render identically.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
