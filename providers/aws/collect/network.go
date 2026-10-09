package collect

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// networkCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const networkCollectorID = "collector:aws.ec2.network"

// networkAPI is the read-only EC2 surface the collector uses: ten Describe reads
// at the List access level (EC2 service authorization reference, verified
// 2026-09-19). None returns a secret value, user data, console output, or a
// password (those getters are refused by the read-only gate). Each call takes
// optFns so the collector targets one declared region at a time.
type networkAPI interface {
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
	DescribeEgressOnlyInternetGateways(context.Context, *ec2.DescribeEgressOnlyInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeEgressOnlyInternetGatewaysOutput, error)
	DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

// NetworkCollector reads the account's VPC networking topology in each declared
// region (ADR-0019 §1): VPCs, subnets, route tables, internet / egress-only /
// NAT gateways, security groups, network ACLs, network interfaces, and Elastic
// IPs. It is the configuration input the reachability engine consumes.
//
// Per ADR-0019 §3 it emits nodes and attributes only, no edges: reachability
// (routes_to, exposed_to) is the output. Routes, rules, public addresses,
// and cross-resource references are recorded as provider facts (ids, and sorted
// canonical JSON for structured lists), so the reachability engine can join them
// by (region, id) later. It never concludes that anything is public or reachable.
// Every node carries its region and owner account, so a shared resource (a VPC
// owned by another account) is keyed under its real owner, not the scanner's.
type NetworkCollector struct {
	account string
	api     networkAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewNetworkCollector builds the collector with a read-only EC2 client from the
// adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewNetworkCollector(account string, cfg awssdk.Config, budget *collect.Budget) *NetworkCollector {
	return &NetworkCollector{account: account, api: ec2.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

// newNetworkCollector is the injectable constructor tests use with a stub API and
// an explicit region list. It has no budget (unlimited).
func newNetworkCollector(account string, api networkAPI, regions []string) *NetworkCollector {
	return &NetworkCollector{account: account, api: api, regions: regions}
}

func (c *NetworkCollector) ID() string               { return networkCollectorID }
func (c *NetworkCollector) Provider() model.Provider { return model.AWS }

// networkRequirements are the read-only permissions this collector needs. Each
// EC2 Describe maps to an ec2: action of the same name at the List access level
// (EC2 service authorization reference, verified 2026-09-19). Registered at init
// so the templates reconcile against real code (ADR-0016).
func networkRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: networkCollectorID}
	}
	return []permissions.Requirement{
		req("ec2:DescribeVpcs"),
		req("ec2:DescribeSubnets"),
		req("ec2:DescribeRouteTables"),
		req("ec2:DescribeInternetGateways"),
		req("ec2:DescribeEgressOnlyInternetGateways"),
		req("ec2:DescribeNatGateways"),
		req("ec2:DescribeSecurityGroups"),
		req("ec2:DescribeNetworkAcls"),
		req("ec2:DescribeNetworkInterfaces"),
		req("ec2:DescribeAddresses"),
	}
}

func init() {
	for _, r := range networkRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *NetworkCollector) Requirements() []permissions.Requirement { return networkRequirements() }

// networkService is one EC2 enumeration: a completeness service name, the API
// operation (for evidence), and a page function that performs one call, emits the
// page's nodes, and returns the response, item count, and next-page token.
type networkService struct {
	name      string
	operation string
	page      func(ctx context.Context, sink collect.Sink, region string, token *string) (resp any, n int, next *string, err error)
}

// services is the fixed, ordered enumeration list: deterministic output and
// deterministic budget consumption.
func (c *NetworkCollector) services() []networkService {
	return []networkService{
		{"ec2.vpcs", "DescribeVpcs", c.pageVpcs},
		{"ec2.subnets", "DescribeSubnets", c.pageSubnets},
		{"ec2.routeTables", "DescribeRouteTables", c.pageRouteTables},
		{"ec2.internetGateways", "DescribeInternetGateways", c.pageInternetGateways},
		{"ec2.egressOnlyInternetGateways", "DescribeEgressOnlyInternetGateways", c.pageEgressOnlyInternetGateways},
		{"ec2.natGateways", "DescribeNatGateways", c.pageNatGateways},
		{"ec2.securityGroups", "DescribeSecurityGroups", c.pageSecurityGroups},
		{"ec2.networkAcls", "DescribeNetworkAcls", c.pageNetworkAcls},
		{"ec2.networkInterfaces", "DescribeNetworkInterfaces", c.pageNetworkInterfaces},
		{"ec2.addresses", "DescribeAddresses", c.pageAddresses},
	}
}

// Collect enumerates every service in every declared region, sequentially
// (ADR-0019 §1), recording one completeness record per (service, region). A
// denied, throttled, not-enabled, or unreachable (transport failure) enumeration
// is a represented gap and collection continues; a not-enabled region is
// Unsupported, and a transport failure is a non-fatal Partial "unreachable" so one
// unreachable region never sinks the scan (ADR-0018 §4). Budget exhaustion marks
// every (service, region) not yet reached Partial "budget exhausted". An
// unexpected error is Errored, the rest still run, and the errors surface.
func (c *NetworkCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		for _, svc := range c.services() {
			if exhausted {
				_ = sink.Complete(collect.Completeness{Service: svc.name, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
				continue
			}
			budgetOut, err := c.enumerate(ctx, sink, region, svc)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				errs = append(errs, err)
			}
			exhausted = budgetOut
		}
	}
	return errors.Join(errs...)
}

// enumerate paginates one service in one region and records its completeness. It
// reports whether the budget ran out.
func (c *NetworkCollector) enumerate(ctx context.Context, sink collect.Sink, region string, svc networkService) (budgetOut bool, err error) {
	count := 0
	var token *string
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: svc.name, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: svc.name, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return true, nil
		}
		resp, n, next, err := svc.page(ctx, sink, region, token)
		if err != nil {
			// Separate genuine cancellation of the scan's own context from a
			// per-request failure (a dial timeout wraps context.DeadlineExceeded but
			// leaves the scan context live): the former is "cancelled", the latter is
			// classified below.
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(collect.Completeness{Service: svc.name, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
				return false, cerr
			}
			_ = sink.Complete(c.completeness(svc.name, region, count, err))
			if isRegionNotEnabled(err) || isDenied(err) || isThrottle(err) || isTransport(err) {
				return false, nil
			}
			return false, err
		}
		_ = sink.Evidence(c.evidence(svc.operation, region, resp))
		count += n
		if next == nil || *next == "" {
			_ = sink.Complete(collect.Completeness{Service: svc.name, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return false, nil
		}
		token = next
	}
}

// ec2ARN builds the documented EC2 resource ARN
// arn:aws:ec2:${region}:${owner}:${type}/${id}, using the resource's own owner
// account when the provider reports one (a shared resource can be owned by another
// account). Only the aws partition is collected (see regions.go).
func (c *NetworkCollector) ec2ARN(region, owner, resourceType, id string) string {
	if owner == "" {
		owner = c.account
	}
	return "arn:aws:ec2:" + region + ":" + owner + ":" + resourceType + "/" + id
}

// base is the attribute set every network node carries: its AWS type, provider
// id, region, and owner account, so the reachability engine can join references
// by (region, id).
func base(awsType, id, region, owner string) map[string]string {
	return map[string]string{"aws_type": awsType, "resource_id": id, "region": region, "owner_id": owner}
}

// tagAttrs records tags as tag:<key> attributes and returns the Name tag.
func tagAttrs(a map[string]string, tags []ec2types.Tag) string {
	name := ""
	for _, t := range tags {
		k := deref(t.Key)
		if k == "" {
			continue
		}
		a["tag:"+k] = deref(t.Value)
		if k == "Name" {
			name = deref(t.Value)
		}
	}
	return name
}

func (c *NetworkCollector) pageVpcs(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, v := range out.Vpcs {
		id, owner := deref(v.VpcId), deref(v.OwnerId)
		if id == "" {
			continue
		}
		a := base("vpc", id, region, owner)
		a["state"] = string(v.State)
		a["is_default"] = boolAttr(v.IsDefault)
		a["instance_tenancy"] = string(v.InstanceTenancy)
		a["dhcp_options_id"] = deref(v.DhcpOptionsId)
		var v4, v6 []string
		for _, b := range v.CidrBlockAssociationSet {
			if cidr := deref(b.CidrBlock); cidr != "" {
				v4 = append(v4, cidr)
			}
		}
		if len(v4) == 0 && deref(v.CidrBlock) != "" {
			v4 = append(v4, deref(v.CidrBlock))
		}
		for _, b := range v.Ipv6CidrBlockAssociationSet {
			if cidr := deref(b.Ipv6CidrBlock); cidr != "" {
				v6 = append(v6, cidr)
			}
		}
		a["cidr_blocks"] = joinSorted(v4)
		a["ipv6_cidr_blocks"] = joinSorted(v6)
		if v.BlockPublicAccessStates != nil {
			a["igw_block_public_access"] = string(v.BlockPublicAccessStates.InternetGatewayBlockMode)
		}
		name := tagAttrs(a, v.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: c.ec2ARN(region, owner, "vpc", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.Vpcs), out.NextToken, nil
}

func (c *NetworkCollector) pageSubnets(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, s := range out.Subnets {
		id, owner := deref(s.SubnetId), deref(s.OwnerId)
		if id == "" {
			continue
		}
		a := base("subnet", id, region, owner)
		a["vpc_id"] = deref(s.VpcId)
		a["state"] = string(s.State)
		a["cidr_block"] = deref(s.CidrBlock)
		var v6 []string
		for _, b := range s.Ipv6CidrBlockAssociationSet {
			if cidr := deref(b.Ipv6CidrBlock); cidr != "" {
				v6 = append(v6, cidr)
			}
		}
		a["ipv6_cidr_blocks"] = joinSorted(v6)
		a["availability_zone"] = deref(s.AvailabilityZone)
		a["map_public_ip_on_launch"] = boolAttr(s.MapPublicIpOnLaunch)
		a["assign_ipv6_on_creation"] = boolAttr(s.AssignIpv6AddressOnCreation)
		a["default_for_az"] = boolAttr(s.DefaultForAz)
		a["ipv6_native"] = boolAttr(s.Ipv6Native)
		if s.BlockPublicAccessStates != nil {
			a["igw_block_public_access"] = string(s.BlockPublicAccessStates.InternetGatewayBlockMode)
		}
		name := tagAttrs(a, s.Tags)
		arn := deref(s.SubnetArn) // the provider's own ARN when it reports one
		if arn == "" {
			arn = c.ec2ARN(region, owner, "subnet", id)
		}
		_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: arn, Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.Subnets), out.NextToken, nil
}

// routeFact is one route as the provider reported it. Target is the id of the
// next hop and TargetType names which field it came from.
type routeFact struct {
	Destination string `json:"destination"`
	TargetType  string `json:"target_type,omitempty"`
	Target      string `json:"target,omitempty"`
	State       string `json:"state,omitempty"`
	Origin      string `json:"origin,omitempty"`
}

func routeOf(r ec2types.Route) routeFact {
	f := routeFact{
		Destination: firstNonEmpty(deref(r.DestinationCidrBlock), deref(r.DestinationIpv6CidrBlock), deref(r.DestinationPrefixListId)),
		State:       string(r.State),
		Origin:      string(r.Origin),
	}
	for _, t := range []struct{ kind, id string }{
		{"gateway", deref(r.GatewayId)},
		{"nat_gateway", deref(r.NatGatewayId)},
		{"egress_only_internet_gateway", deref(r.EgressOnlyInternetGatewayId)},
		{"transit_gateway", deref(r.TransitGatewayId)},
		{"vpc_peering_connection", deref(r.VpcPeeringConnectionId)},
		{"network_interface", deref(r.NetworkInterfaceId)},
		{"instance", deref(r.InstanceId)},
		{"local_gateway", deref(r.LocalGatewayId)},
		{"carrier_gateway", deref(r.CarrierGatewayId)},
		{"core_network", deref(r.CoreNetworkArn)},
	} {
		if t.id != "" {
			f.TargetType, f.Target = t.kind, t.id
			break
		}
	}
	return f
}

func (c *NetworkCollector) pageRouteTables(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, rt := range out.RouteTables {
		id, owner := deref(rt.RouteTableId), deref(rt.OwnerId)
		if id == "" {
			continue
		}
		a := base("route_table", id, region, owner)
		a["vpc_id"] = deref(rt.VpcId)
		routes := make([]routeFact, 0, len(rt.Routes))
		for _, r := range rt.Routes {
			routes = append(routes, routeOf(r))
		}
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Destination != routes[j].Destination {
				return routes[i].Destination < routes[j].Destination
			}
			return routes[i].Target < routes[j].Target
		})
		a["routes"] = canonicalJSON(routes)
		var subnets, gateways []string
		for _, as := range rt.Associations {
			if as.Main != nil && *as.Main {
				a["main"] = "true"
			}
			if s := deref(as.SubnetId); s != "" {
				subnets = append(subnets, s)
			}
			if g := deref(as.GatewayId); g != "" {
				gateways = append(gateways, g)
			}
		}
		a["associated_subnet_ids"] = joinSorted(subnets)
		a["associated_gateway_ids"] = joinSorted(gateways)
		name := tagAttrs(a, rt.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeNetwork, NativeID: c.ec2ARN(region, owner, "route-table", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.RouteTables), out.NextToken, nil
}

// attachments renders gateway attachments as sorted "vpc-id:state" pairs.
func attachments(as []ec2types.InternetGatewayAttachment) string {
	var out []string
	for _, a := range as {
		if v := deref(a.VpcId); v != "" {
			out = append(out, v+":"+string(a.State))
		}
	}
	return joinSorted(out)
}

func (c *NetworkCollector) pageInternetGateways(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, g := range out.InternetGateways {
		id, owner := deref(g.InternetGatewayId), deref(g.OwnerId)
		if id == "" {
			continue
		}
		a := base("internet_gateway", id, region, owner)
		a["attachments"] = attachments(g.Attachments)
		name := tagAttrs(a, g.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: c.ec2ARN(region, owner, "internet-gateway", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.InternetGateways), out.NextToken, nil
}

func (c *NetworkCollector) pageEgressOnlyInternetGateways(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeEgressOnlyInternetGateways(ctx, &ec2.DescribeEgressOnlyInternetGatewaysInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, g := range out.EgressOnlyInternetGateways {
		id := deref(g.EgressOnlyInternetGatewayId)
		if id == "" {
			continue
		}
		// The API reports no owner for an egress-only gateway; the ARN uses the
		// scanned account and owner_id is left unset rather than guessed.
		a := base("egress_only_internet_gateway", id, region, "")
		a["attachments"] = attachments(g.Attachments)
		name := tagAttrs(a, g.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: c.ec2ARN(region, "", "egress-only-internet-gateway", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.EgressOnlyInternetGateways), out.NextToken, nil
}

// natAddress is one NAT gateway address as reported.
type natAddress struct {
	PublicIP           string `json:"public_ip,omitempty"`
	PrivateIP          string `json:"private_ip,omitempty"`
	AllocationID       string `json:"allocation_id,omitempty"`
	NetworkInterfaceID string `json:"network_interface_id,omitempty"`
	Status             string `json:"status,omitempty"`
}

func (c *NetworkCollector) pageNatGateways(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, g := range out.NatGateways {
		id := deref(g.NatGatewayId)
		if id == "" {
			continue
		}
		// The API reports no owner for a NAT gateway; see the egress-only gateway.
		a := base("nat_gateway", id, region, "")
		a["vpc_id"] = deref(g.VpcId)
		a["subnet_id"] = deref(g.SubnetId)
		a["state"] = string(g.State)
		a["connectivity_type"] = string(g.ConnectivityType)
		addrs := make([]natAddress, 0, len(g.NatGatewayAddresses))
		for _, ad := range g.NatGatewayAddresses {
			addrs = append(addrs, natAddress{
				PublicIP: deref(ad.PublicIp), PrivateIP: deref(ad.PrivateIp), AllocationID: deref(ad.AllocationId),
				NetworkInterfaceID: deref(ad.NetworkInterfaceId), Status: string(ad.Status),
			})
		}
		sort.Slice(addrs, func(i, j int) bool {
			return addrs[i].PrivateIP+addrs[i].PublicIP < addrs[j].PrivateIP+addrs[j].PublicIP
		})
		if len(addrs) > 0 {
			a["addresses"] = canonicalJSON(addrs)
		}
		name := tagAttrs(a, g.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: c.ec2ARN(region, "", "natgateway", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.NatGateways), out.NextToken, nil
}

// sgRule is one security-group permission for one source or destination as
// reported. Exactly one of CIDR, IPv6CIDR, PrefixList, or Group is set. Protocol
// "-1" means all protocols.
type sgRule struct {
	Protocol   string `json:"protocol"`
	FromPort   *int32 `json:"from_port,omitempty"`
	ToPort     *int32 `json:"to_port,omitempty"`
	CIDR       string `json:"cidr,omitempty"`
	IPv6CIDR   string `json:"ipv6_cidr,omitempty"`
	PrefixList string `json:"prefix_list,omitempty"`
	Group      string `json:"group,omitempty"`
	GroupOwner string `json:"group_owner,omitempty"`
}

func sgRules(perms []ec2types.IpPermission) string {
	out := []sgRule{}
	for _, p := range perms {
		r := sgRule{Protocol: deref(p.IpProtocol), FromPort: p.FromPort, ToPort: p.ToPort}
		for _, x := range p.IpRanges {
			rr := r
			rr.CIDR = deref(x.CidrIp)
			out = append(out, rr)
		}
		for _, x := range p.Ipv6Ranges {
			rr := r
			rr.IPv6CIDR = deref(x.CidrIpv6)
			out = append(out, rr)
		}
		for _, x := range p.PrefixListIds {
			rr := r
			rr.PrefixList = deref(x.PrefixListId)
			out = append(out, rr)
		}
		for _, x := range p.UserIdGroupPairs {
			rr := r
			rr.Group, rr.GroupOwner = deref(x.GroupId), deref(x.UserId)
			out = append(out, rr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return canonicalJSON(out[i]) < canonicalJSON(out[j]) })
	return canonicalJSON(out)
}

func (c *NetworkCollector) pageSecurityGroups(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, g := range out.SecurityGroups {
		id, owner := deref(g.GroupId), deref(g.OwnerId)
		if id == "" {
			continue
		}
		a := base("security_group", id, region, owner)
		a["vpc_id"] = deref(g.VpcId)
		a["group_name"] = deref(g.GroupName)
		// Rules are recorded in full, including an empty list, because "no rules"
		// is itself a fact (for egress, no rule means no egress is allowed).
		a["ingress_rules"] = sgRules(g.IpPermissions)
		a["egress_rules"] = sgRules(g.IpPermissionsEgress)
		name := tagAttrs(a, g.Tags)
		arn := deref(g.SecurityGroupArn) // the provider's own ARN when it reports one
		if arn == "" {
			arn = c.ec2ARN(region, owner, "security-group", id)
		}
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: arn, Name: firstNonEmpty(name, deref(g.GroupName), id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.SecurityGroups), out.NextToken, nil
}

// aclEntry is one network ACL entry as reported.
type aclEntry struct {
	RuleNumber int32  `json:"rule_number"`
	Egress     bool   `json:"egress"`
	Protocol   string `json:"protocol"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr,omitempty"`
	IPv6CIDR   string `json:"ipv6_cidr,omitempty"`
	FromPort   *int32 `json:"from_port,omitempty"`
	ToPort     *int32 `json:"to_port,omitempty"`
	ICMPType   *int32 `json:"icmp_type,omitempty"`
	ICMPCode   *int32 `json:"icmp_code,omitempty"`
}

func (c *NetworkCollector) pageNetworkAcls(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, n := range out.NetworkAcls {
		id, owner := deref(n.NetworkAclId), deref(n.OwnerId)
		if id == "" {
			continue
		}
		a := base("network_acl", id, region, owner)
		a["vpc_id"] = deref(n.VpcId)
		a["is_default"] = boolAttr(n.IsDefault)
		entries := make([]aclEntry, 0, len(n.Entries))
		for _, e := range n.Entries {
			en := aclEntry{Protocol: deref(e.Protocol), Action: string(e.RuleAction), CIDR: deref(e.CidrBlock), IPv6CIDR: deref(e.Ipv6CidrBlock)}
			if e.RuleNumber != nil {
				en.RuleNumber = *e.RuleNumber
			}
			if e.Egress != nil {
				en.Egress = *e.Egress
			}
			if e.PortRange != nil {
				en.FromPort, en.ToPort = e.PortRange.From, e.PortRange.To
			}
			if e.IcmpTypeCode != nil {
				en.ICMPType, en.ICMPCode = e.IcmpTypeCode.Type, e.IcmpTypeCode.Code
			}
			entries = append(entries, en)
		}
		// NACL evaluation order matters, so entries are ordered by direction then
		// rule number, exactly as AWS evaluates them.
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Egress != entries[j].Egress {
				return !entries[i].Egress
			}
			if entries[i].RuleNumber != entries[j].RuleNumber {
				return entries[i].RuleNumber < entries[j].RuleNumber
			}
			return canonicalJSON(entries[i]) < canonicalJSON(entries[j])
		})
		a["entries"] = canonicalJSON(entries)
		var subnets []string
		for _, as := range n.Associations {
			if s := deref(as.SubnetId); s != "" {
				subnets = append(subnets, s)
			}
		}
		a["associated_subnet_ids"] = joinSorted(subnets)
		name := tagAttrs(a, n.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: c.ec2ARN(region, owner, "network-acl", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.NetworkAcls), out.NextToken, nil
}

func (c *NetworkCollector) pageNetworkInterfaces(ctx context.Context, sink collect.Sink, region string, token *string) (any, int, *string, error) {
	out, err := c.api.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NextToken: token}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, n := range out.NetworkInterfaces {
		id, owner := deref(n.NetworkInterfaceId), deref(n.OwnerId)
		if id == "" {
			continue
		}
		a := base("network_interface", id, region, owner)
		a["vpc_id"] = deref(n.VpcId)
		a["subnet_id"] = deref(n.SubnetId)
		a["interface_type"] = string(n.InterfaceType)
		a["status"] = string(n.Status)
		a["availability_zone"] = deref(n.AvailabilityZone)
		a["requester_managed"] = boolAttr(n.RequesterManaged)
		a["source_dest_check"] = boolAttr(n.SourceDestCheck)
		var privs, v6 []string
		for _, p := range n.PrivateIpAddresses {
			if ip := deref(p.PrivateIpAddress); ip != "" {
				privs = append(privs, ip)
			}
		}
		if len(privs) == 0 && deref(n.PrivateIpAddress) != "" {
			privs = append(privs, deref(n.PrivateIpAddress))
		}
		for _, p := range n.Ipv6Addresses {
			if ip := deref(p.Ipv6Address); ip != "" {
				v6 = append(v6, ip)
			}
		}
		a["private_ips"] = joinSorted(privs)
		a["ipv6_addresses"] = joinSorted(v6)
		if as := n.Association; as != nil {
			a["public_ip"] = deref(as.PublicIp)
			a["public_ip_owner"] = deref(as.IpOwnerId)
			a["public_ip_allocation_id"] = deref(as.AllocationId)
			a["public_dns_name"] = deref(as.PublicDnsName)
		}
		var groups []string
		for _, g := range n.Groups {
			if gid := deref(g.GroupId); gid != "" {
				groups = append(groups, gid)
			}
		}
		a["security_group_ids"] = joinSorted(groups)
		if at := n.Attachment; at != nil {
			a["attached_instance_id"] = deref(at.InstanceId)
			a["attached_instance_owner"] = deref(at.InstanceOwnerId)
			a["attachment_status"] = string(at.Status)
		}
		name := tagAttrs(a, n.TagSet)
		_ = sink.Node(collect.Node{Type: model.NodeEndpoint, NativeID: c.ec2ARN(region, owner, "network-interface", id), Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
	}
	return out, len(out.NetworkInterfaces), out.NextToken, nil
}

// pageAddresses reads the region's Elastic IPs. DescribeAddresses is not
// paginated (verified against the vendored SDK: no NextToken), so token is ignored
// and next is always nil.
func (c *NetworkCollector) pageAddresses(ctx context.Context, sink collect.Sink, region string, _ *string) (any, int, *string, error) {
	out, err := c.api.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{}, inRegion(region))
	if err != nil {
		return nil, 0, nil, err
	}
	n := 0
	for _, ad := range out.Addresses {
		// The documented ARN is keyed by allocation id; an address without one has
		// no documented ARN and is not emitted as a node.
		alloc := deref(ad.AllocationId)
		if alloc == "" {
			continue
		}
		n++
		a := base("elastic_ip", alloc, region, "")
		a["public_ip"] = deref(ad.PublicIp)
		a["domain"] = string(ad.Domain)
		a["association_id"] = deref(ad.AssociationId)
		a["network_interface_id"] = deref(ad.NetworkInterfaceId)
		a["network_interface_owner"] = deref(ad.NetworkInterfaceOwnerId)
		a["instance_id"] = deref(ad.InstanceId)
		a["private_ip"] = deref(ad.PrivateIpAddress)
		a["network_border_group"] = deref(ad.NetworkBorderGroup)
		name := tagAttrs(a, ad.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeEndpoint, NativeID: c.ec2ARN(region, "", "elastic-ip", alloc), Name: firstNonEmpty(name, deref(ad.PublicIp), alloc), Attributes: pruneEmpty(a)})
	}
	return out, n, nil, nil
}

func (c *NetworkCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one EC2 page. These
// Describe responses carry configuration only; they still pass through redaction
// as defence in depth.
func (c *NetworkCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "ec2", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: ec2APIVersion, Collector: networkCollectorID},
	}
}

// completeness classifies an EC2 error into a completeness record. A not-enabled
// region is Unsupported, a denial Denied, a throttle Partial, a transport failure
// a non-fatal Partial "unreachable" (ADR-0018 §4), anything else Errored.
func (c *NetworkCollector) completeness(service, region string, collected int, err error) collect.Completeness {
	status := collect.Errored
	reason := redact.String(err.Error())
	switch {
	case isRegionNotEnabled(err):
		status = collect.Unsupported
		reason = "region not enabled"
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	case isTransport(err):
		status = collect.Partial
		reason = "unreachable"
	}
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
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
