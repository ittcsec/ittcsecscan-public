package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// networkCollectorID is the stable id this collector is credited with.
const networkCollectorID = "collector:azure.network"

// networkAPIVersion is the doc-verified Network Resource Provider API version
// (2026-09-21). Every List All operation returns the resource's full properties and
// no secret value.
const networkAPIVersion = "2025-09-01"

// NetworkCollector reads the tenant's Azure networking topology, the Azure
// counterpart of the AWS EC2-network and GCP VPC-networking collectors and the
// configuration input the reachability engine consumes: virtual networks
// (with their subnets), network security groups (with their rules), public IP
// addresses, and network interfaces. These live on the Resource Manager plane and
// are subscription-scoped, so the collector enumerates the accessible subscriptions
// and reads each resource type in a single paginated list.
//
// Per ADR-0019 §3 it emits nodes and attributes only, no edges: reachability is
// the output. NSG rules are recorded as sorted canonical-JSON facts, and
// cross-references (a subnet's and a NIC's NSG, a NIC's subnet and public IP and
// virtual machine) are recorded as id facts so the reachability engine can join
// them. An Azure NSG can attach to both a subnet and a network interface; that
// dual-attachment is recorded as a fact on every side (the NSG lists its subnets and
// NICs, and each subnet and NIC names its NSG), with no synthesized effective-rule
// verdict. The reads were verified against the Azure Network REST reference
// (2026-09-21): read-only GETs, paginated by nextLink, returning no secret value.
type NetworkCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewNetworkCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewNetworkCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *NetworkCollector {
	return &NetworkCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newNetworkCollector is the injectable constructor tests use with a stub API.
func newNetworkCollector(tenantID string, api armAPI) *NetworkCollector {
	return &NetworkCollector{tenantID: tenantID, api: api}
}

func (c *NetworkCollector) ID() string               { return networkCollectorID }
func (c *NetworkCollector) Provider() model.Provider { return model.Azure }

func networkRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Azure, Profile: permissions.Discovery, Permission: p, By: networkCollectorID}
	}
	return []permissions.Requirement{
		req("Microsoft.Network/virtualNetworks/read"),
		req("Microsoft.Network/networkSecurityGroups/read"),
		req("Microsoft.Network/publicIPAddresses/read"),
		req("Microsoft.Network/networkInterfaces/read"),
	}
}

func init() {
	for _, r := range networkRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *NetworkCollector) Requirements() []permissions.Requirement { return networkRequirements() }

// netResource is one networking resource type's list: its completeness service name,
// the ARM provider path, and a decoder that maps one page to nodes.
type netResource struct {
	service string
	path    string
	decode  func(c *NetworkCollector, sink collect.Sink, raw json.RawMessage) (int, error)
}

func (c *NetworkCollector) resources() []netResource {
	return []netResource{
		{"network.virtualNetworks", "Microsoft.Network/virtualNetworks", (*NetworkCollector).decodeVNets},
		{"network.networkSecurityGroups", "Microsoft.Network/networkSecurityGroups", (*NetworkCollector).decodeNSGs},
		{"network.publicIPAddresses", "Microsoft.Network/publicIPAddresses", (*NetworkCollector).decodePublicIPs},
		{"network.networkInterfaces", "Microsoft.Network/networkInterfaces", (*NetworkCollector).decodeNICs},
	}
}

// Collect enumerates the accessible subscriptions and, for each, lists virtual
// networks, network security groups, public IP addresses, and network interfaces.
// One completeness record is produced per (resource type, subscription), plus
// network.subscriptions.
func (c *NetworkCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "network.subscriptions", tenantScope, subscriptionsAPIVersion,
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
		for _, r := range c.resources() {
			decode := r.decode
			_ = c.pageThrough(ctx, sink, r.service, scope, networkAPIVersion,
				fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=%s", armBaseURL, sub.SubscriptionID, r.path, networkAPIVersion),
				func(raw json.RawMessage) (int, error) { return decode(c, sink, raw) })
		}
	}
	return nil
}

func (c *NetworkCollector) decodeVNets(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []vnet
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, v := range page {
		if v.ID == "" {
			continue
		}
		a := map[string]string{
			"azure_type":       "virtual_network",
			"location":         v.Location,
			"address_prefixes": strings.Join(v.Properties.AddressSpace.AddressPrefixes, ","),
			"ddos_protection":  boolAttr(v.Properties.EnableDdosProtection),
			"peering_count":    strconv.Itoa(len(v.Properties.VirtualNetworkPeerings)),
		}
		mapTags(a, v.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: v.ID, Name: v.Name, Attributes: pruneEmptyAzure(a)})
		for _, sn := range v.Properties.Subnets {
			if sn.ID == "" {
				continue
			}
			sa := map[string]string{
				"azure_type":     "subnet",
				"vnet_id":        v.ID,
				"address_prefix": firstNonEmpty(sn.Properties.AddressPrefix, strings.Join(sn.Properties.AddressPrefixes, ",")),
			}
			if sn.Properties.NetworkSecurityGroup != nil {
				// The subnet side of the NSG association.
				sa["nsg_id"] = sn.Properties.NetworkSecurityGroup.ID
			}
			if sn.Properties.RouteTable != nil {
				sa["route_table_id"] = sn.Properties.RouteTable.ID
			}
			_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: sn.ID, Name: sn.Name, Attributes: pruneEmptyAzure(sa)})
		}
	}
	return len(page), nil
}

func (c *NetworkCollector) decodeNSGs(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []nsg
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, g := range page {
		if g.ID == "" {
			continue
		}
		rules := make([]nsgRuleFact, 0, len(g.Properties.SecurityRules))
		for _, r := range g.Properties.SecurityRules {
			p := r.Properties
			rules = append(rules, nsgRuleFact{
				Name: r.Name, Priority: p.Priority, Direction: p.Direction, Access: p.Access, Protocol: p.Protocol,
				SourcePrefixes:      merge(p.SourceAddressPrefix, p.SourceAddressPrefixes),
				DestinationPrefixes: merge(p.DestinationAddressPrefix, p.DestinationAddressPrefixes),
				SourcePorts:         merge(p.SourcePortRange, p.SourcePortRanges),
				DestinationPorts:    merge(p.DestinationPortRange, p.DestinationPortRanges),
			})
		}
		sort.Slice(rules, func(i, j int) bool {
			if rules[i].Priority != rules[j].Priority {
				return rules[i].Priority < rules[j].Priority
			}
			return rules[i].Name < rules[j].Name
		})
		a := map[string]string{
			"azure_type":     "network_security_group",
			"location":       g.Location,
			"security_rules": canonicalJSON(rules),
			// The NSG side of the association: the subnets and NICs it is attached to.
			"associated_subnets": strings.Join(sortedIDs(subResourceIDs(g.Properties.Subnets)), ","),
			"associated_nics":    strings.Join(sortedIDs(subResourceIDs(g.Properties.NetworkInterfaces)), ","),
		}
		mapTags(a, g.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: g.ID, Name: g.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

func (c *NetworkCollector) decodePublicIPs(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []publicIP
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, ip := range page {
		if ip.ID == "" {
			continue
		}
		a := map[string]string{
			"azure_type":        "public_ip_address",
			"location":          ip.Location,
			"sku":               ip.Sku.Name,
			"ip_address":        ip.Properties.IPAddress,
			"allocation_method": ip.Properties.PublicIPAllocationMethod,
		}
		if ip.Properties.IPConfiguration != nil {
			a["ip_configuration_id"] = ip.Properties.IPConfiguration.ID
		}
		if ip.Properties.DNSSettings != nil {
			a["fqdn"] = ip.Properties.DNSSettings.Fqdn
		}
		mapTags(a, ip.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeEndpoint, NativeID: ip.ID, Name: ip.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

func (c *NetworkCollector) decodeNICs(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []nic
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, n := range page {
		if n.ID == "" {
			continue
		}
		var privIPs, pubIPs, subnetIDs []string
		for _, cfg := range n.Properties.IPConfigurations {
			if ip := cfg.Properties.PrivateIPAddress; ip != "" {
				privIPs = append(privIPs, ip)
			}
			if cfg.Properties.PublicIPAddress != nil && cfg.Properties.PublicIPAddress.ID != "" {
				pubIPs = append(pubIPs, cfg.Properties.PublicIPAddress.ID)
			}
			if cfg.Properties.Subnet != nil && cfg.Properties.Subnet.ID != "" {
				subnetIDs = append(subnetIDs, cfg.Properties.Subnet.ID)
			}
		}
		a := map[string]string{
			"azure_type":    "network_interface",
			"location":      n.Location,
			"private_ips":   strings.Join(privIPs, ","),
			"public_ip_ids": strings.Join(sortedIDs(pubIPs), ","),
			"subnet_ids":    strings.Join(sortedIDs(subnetIDs), ","),
		}
		if n.Properties.NetworkSecurityGroup != nil {
			// The NIC side of the NSG association.
			a["nsg_id"] = n.Properties.NetworkSecurityGroup.ID
		}
		if n.Properties.VirtualMachine != nil {
			// Joins onto the compute collector's VM node.
			a["virtual_machine_id"] = n.Properties.VirtualMachine.ID
		}
		mapTags(a, n.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeEndpoint, NativeID: n.ID, Name: n.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

// nsgRuleFact is one NSG security rule as reported, single and array forms merged.
type nsgRuleFact struct {
	Name                string   `json:"name"`
	Priority            int32    `json:"priority"`
	Direction           string   `json:"direction"`
	Access              string   `json:"access"`
	Protocol            string   `json:"protocol"`
	SourcePrefixes      []string `json:"source_prefixes,omitempty"`
	DestinationPrefixes []string `json:"destination_prefixes,omitempty"`
	SourcePorts         []string `json:"source_ports,omitempty"`
	DestinationPorts    []string `json:"destination_ports,omitempty"`
}

type subResource struct {
	ID string `json:"id"`
}

type vnet struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		AddressSpace struct {
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"addressSpace"`
		EnableDdosProtection   *bool             `json:"enableDdosProtection"`
		VirtualNetworkPeerings []json.RawMessage `json:"virtualNetworkPeerings"`
		Subnets                []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				AddressPrefix        string       `json:"addressPrefix"`
				AddressPrefixes      []string     `json:"addressPrefixes"`
				NetworkSecurityGroup *subResource `json:"networkSecurityGroup"`
				RouteTable           *subResource `json:"routeTable"`
			} `json:"properties"`
		} `json:"subnets"`
	} `json:"properties"`
}

type nsg struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		SecurityRules []struct {
			Name       string `json:"name"`
			Properties struct {
				Priority                   int32    `json:"priority"`
				Direction                  string   `json:"direction"`
				Access                     string   `json:"access"`
				Protocol                   string   `json:"protocol"`
				SourceAddressPrefix        string   `json:"sourceAddressPrefix"`
				SourceAddressPrefixes      []string `json:"sourceAddressPrefixes"`
				DestinationAddressPrefix   string   `json:"destinationAddressPrefix"`
				DestinationAddressPrefixes []string `json:"destinationAddressPrefixes"`
				SourcePortRange            string   `json:"sourcePortRange"`
				SourcePortRanges           []string `json:"sourcePortRanges"`
				DestinationPortRange       string   `json:"destinationPortRange"`
				DestinationPortRanges      []string `json:"destinationPortRanges"`
			} `json:"properties"`
		} `json:"securityRules"`
		Subnets           []subResource `json:"subnets"`
		NetworkInterfaces []subResource `json:"networkInterfaces"`
	} `json:"properties"`
}

type publicIP struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	Sku      struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		IPAddress                string       `json:"ipAddress"`
		PublicIPAllocationMethod string       `json:"publicIPAllocationMethod"`
		IPConfiguration          *subResource `json:"ipConfiguration"`
		DNSSettings              *struct {
			Fqdn string `json:"fqdn"`
		} `json:"dnsSettings"`
	} `json:"properties"`
}

type nic struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		IPConfigurations []struct {
			Properties struct {
				PrivateIPAddress string       `json:"privateIPAddress"`
				Subnet           *subResource `json:"subnet"`
				PublicIPAddress  *subResource `json:"publicIPAddress"`
			} `json:"properties"`
		} `json:"ipConfigurations"`
		NetworkSecurityGroup *subResource `json:"networkSecurityGroup"`
		VirtualMachine       *subResource `json:"virtualMachine"`
	} `json:"properties"`
}

// merge combines a single value and an array form of the same field, dropping empties.
func merge(single string, many []string) []string {
	var out []string
	if single != "" {
		out = append(out, single)
	}
	out = append(out, many...)
	return out
}

func subResourceIDs(rs []subResource) []string {
	var out []string
	for _, r := range rs {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	return out
}

func sortedIDs(ids []string) []string {
	sort.Strings(ids)
	return ids
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func mapTags(a, tags map[string]string) {
	for k, v := range tags {
		if k != "" {
			a["tag:"+k] = v
		}
	}
}

// canonicalJSON renders v as compact JSON. Callers pass sorted slices of fixed
// structs, so equal inputs render identically.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending
// budget per page and recording evidence and completeness for service at scope. A
// denied or throttled read is a represented gap (returns nil); an unexpected error
// is surfaced; a page is never reported Complete on a failure.
func (c *NetworkCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(networkGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(networkGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(networkGap(service, scope, collect.Partial, count, "budget exhausted"))
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
			_ = sink.Complete(networkGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(networkGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(networkGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *NetworkCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "network", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: networkCollectorID},
	}
}

func (c *NetworkCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return networkGap(service, scope, status, collected, redact.String(err.Error()))
}

func networkGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}
