package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func i32(v int32) *int32 { return &v }

// stubNet is an offline networkAPI: the same estate in every region (VPCs may be
// paginated), recording each call's region, with per-(operation, region) error
// injection.
type stubNet struct {
	vpcPages [][]ec2types.Vpc
	subnets  []ec2types.Subnet
	rts      []ec2types.RouteTable
	igws     []ec2types.InternetGateway
	eigws    []ec2types.EgressOnlyInternetGateway
	nats     []ec2types.NatGateway
	sgs      []ec2types.SecurityGroup
	acls     []ec2types.NetworkAcl
	enis     []ec2types.NetworkInterface
	addrs    []ec2types.Address

	errs    map[string]error // "Operation@region" -> error
	calls   int
	regions []string
}

func (s *stubNet) hit(op string, o []func(*ec2.Options)) error {
	s.calls++
	r := ec2Region(o)
	s.regions = append(s.regions, r)
	return s.errs[op+"@"+r]
}

func (s *stubNet) DescribeVpcs(_ context.Context, in *ec2.DescribeVpcsInput, o ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	if err := s.hit("DescribeVpcs", o); err != nil {
		return nil, err
	}
	page := 0
	if in.NextToken != nil {
		page = int((*in.NextToken)[0] - '0')
	}
	out := &ec2.DescribeVpcsOutput{}
	if page < len(s.vpcPages) {
		out.Vpcs = s.vpcPages[page]
	}
	if page+1 < len(s.vpcPages) {
		out.NextToken = ptr(string(rune('0' + page + 1)))
	}
	return out, nil
}

func (s *stubNet) DescribeSubnets(_ context.Context, _ *ec2.DescribeSubnetsInput, o ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if err := s.hit("DescribeSubnets", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeSubnetsOutput{Subnets: s.subnets}, nil
}

func (s *stubNet) DescribeRouteTables(_ context.Context, _ *ec2.DescribeRouteTablesInput, o ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if err := s.hit("DescribeRouteTables", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeRouteTablesOutput{RouteTables: s.rts}, nil
}

func (s *stubNet) DescribeInternetGateways(_ context.Context, _ *ec2.DescribeInternetGatewaysInput, o ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	if err := s.hit("DescribeInternetGateways", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeInternetGatewaysOutput{InternetGateways: s.igws}, nil
}

func (s *stubNet) DescribeEgressOnlyInternetGateways(_ context.Context, _ *ec2.DescribeEgressOnlyInternetGatewaysInput, o ...func(*ec2.Options)) (*ec2.DescribeEgressOnlyInternetGatewaysOutput, error) {
	if err := s.hit("DescribeEgressOnlyInternetGateways", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeEgressOnlyInternetGatewaysOutput{EgressOnlyInternetGateways: s.eigws}, nil
}

func (s *stubNet) DescribeNatGateways(_ context.Context, _ *ec2.DescribeNatGatewaysInput, o ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	if err := s.hit("DescribeNatGateways", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeNatGatewaysOutput{NatGateways: s.nats}, nil
}

func (s *stubNet) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, o ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if err := s.hit("DescribeSecurityGroups", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: s.sgs}, nil
}

func (s *stubNet) DescribeNetworkAcls(_ context.Context, _ *ec2.DescribeNetworkAclsInput, o ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	if err := s.hit("DescribeNetworkAcls", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeNetworkAclsOutput{NetworkAcls: s.acls}, nil
}

func (s *stubNet) DescribeNetworkInterfaces(_ context.Context, _ *ec2.DescribeNetworkInterfacesInput, o ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if err := s.hit("DescribeNetworkInterfaces", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: s.enis}, nil
}

func (s *stubNet) DescribeAddresses(_ context.Context, _ *ec2.DescribeAddressesInput, o ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if err := s.hit("DescribeAddresses", o); err != nil {
		return nil, err
	}
	return &ec2.DescribeAddressesOutput{Addresses: s.addrs}, nil
}

// estate is one small but complete public-facing VPC: a public subnet routed to
// an internet gateway, a security group open to the world on SSH with no egress
// rule, a network ACL, an interface with a public IP, an Elastic IP, a NAT
// gateway, and an egress-only gateway. Subnet and security group carry the
// provider's own ARN.
func estate() *stubNet {
	return &stubNet{
		vpcPages: [][]ec2types.Vpc{{{
			VpcId: ptr("vpc-1"), OwnerId: ptr(acctID), State: ec2types.VpcStateAvailable, IsDefault: bptr(false),
			CidrBlockAssociationSet: []ec2types.VpcCidrBlockAssociation{{CidrBlock: ptr("10.0.0.0/16")}},
			BlockPublicAccessStates: &ec2types.BlockPublicAccessStates{InternetGatewayBlockMode: ec2types.BlockPublicAccessModeOff},
			Tags:                    []ec2types.Tag{{Key: ptr("Name"), Value: ptr("prod")}},
		}}},
		subnets: []ec2types.Subnet{{
			SubnetId: ptr("subnet-1"), SubnetArn: ptr("arn:aws:ec2:us-east-1:" + acctID + ":subnet/subnet-1"), OwnerId: ptr(acctID),
			VpcId: ptr("vpc-1"), CidrBlock: ptr("10.0.1.0/24"), AvailabilityZone: ptr("us-east-1a"), MapPublicIpOnLaunch: bptr(true),
		}},
		rts: []ec2types.RouteTable{{
			RouteTableId: ptr("rtb-1"), OwnerId: ptr(acctID), VpcId: ptr("vpc-1"),
			Routes: []ec2types.Route{
				{DestinationCidrBlock: ptr("10.0.0.0/16"), GatewayId: ptr("local"), State: ec2types.RouteStateActive},
				{DestinationCidrBlock: ptr("0.0.0.0/0"), GatewayId: ptr("igw-1"), State: ec2types.RouteStateActive},
			},
			Associations: []ec2types.RouteTableAssociation{{SubnetId: ptr("subnet-1")}},
		}},
		igws:  []ec2types.InternetGateway{{InternetGatewayId: ptr("igw-1"), OwnerId: ptr(acctID), Attachments: []ec2types.InternetGatewayAttachment{{VpcId: ptr("vpc-1"), State: ec2types.AttachmentStatusAttached}}}},
		eigws: []ec2types.EgressOnlyInternetGateway{{EgressOnlyInternetGatewayId: ptr("eigw-1")}},
		nats:  []ec2types.NatGateway{{NatGatewayId: ptr("nat-1"), VpcId: ptr("vpc-1"), SubnetId: ptr("subnet-1"), State: ec2types.NatGatewayStateAvailable}},
		sgs: []ec2types.SecurityGroup{{
			GroupId: ptr("sg-1"), GroupName: ptr("ssh"), OwnerId: ptr(acctID), VpcId: ptr("vpc-1"),
			SecurityGroupArn: ptr("arn:aws:ec2:us-east-1:" + acctID + ":security-group/sg-1"),
			IpPermissions: []ec2types.IpPermission{{IpProtocol: ptr("tcp"), FromPort: i32(22), ToPort: i32(22),
				IpRanges: []ec2types.IpRange{{CidrIp: ptr("0.0.0.0/0")}}, Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: ptr("::/0")}}}},
			// No egress permissions: recorded as an empty list, a fact.
		}},
		acls: []ec2types.NetworkAcl{{
			NetworkAclId: ptr("acl-1"), OwnerId: ptr(acctID), VpcId: ptr("vpc-1"), IsDefault: bptr(true),
			Entries: []ec2types.NetworkAclEntry{
				{RuleNumber: i32(32767), Egress: bptr(false), Protocol: ptr("-1"), RuleAction: ec2types.RuleActionDeny, CidrBlock: ptr("0.0.0.0/0")},
				{RuleNumber: i32(100), Egress: bptr(false), Protocol: ptr("-1"), RuleAction: ec2types.RuleActionAllow, CidrBlock: ptr("0.0.0.0/0")},
				{RuleNumber: i32(100), Egress: bptr(true), Protocol: ptr("-1"), RuleAction: ec2types.RuleActionAllow, CidrBlock: ptr("0.0.0.0/0")},
			},
			Associations: []ec2types.NetworkAclAssociation{{SubnetId: ptr("subnet-1")}},
		}},
		enis: []ec2types.NetworkInterface{{
			NetworkInterfaceId: ptr("eni-1"), OwnerId: ptr(acctID), VpcId: ptr("vpc-1"), SubnetId: ptr("subnet-1"),
			PrivateIpAddress: ptr("10.0.1.10"), InterfaceType: ec2types.NetworkInterfaceTypeInterface,
			Association: &ec2types.NetworkInterfaceAssociation{PublicIp: ptr("203.0.113.10"), AllocationId: ptr("eipalloc-1")},
			Groups:      []ec2types.GroupIdentifier{{GroupId: ptr("sg-1")}},
			Attachment:  &ec2types.NetworkInterfaceAttachment{InstanceId: ptr("i-1")},
		}},
		addrs: []ec2types.Address{
			{AllocationId: ptr("eipalloc-1"), PublicIp: ptr("203.0.113.10"), Domain: ec2types.DomainTypeVpc, NetworkInterfaceId: ptr("eni-1")},
			{PublicIp: ptr("198.51.100.7")}, // no allocation id: no documented ARN, not emitted
		},
		errs: map[string]error{},
	}
}

func runNetwork(t *testing.T, api networkAPI, regions ...string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newNetworkCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestNetworkMapsEstate proves each resource type becomes a node of the right
// model type, keyed by its canonical ARN (the provider's own when reported), with
// routes, rules, and public addresses recorded as facts, and no edges.
func TestNetworkMapsEstate(t *testing.T) {
	s := runNetwork(t, estate(), "us-east-1")

	want := map[string]model.NodeType{
		"arn:aws:ec2:us-east-1:" + acctID + ":vpc/vpc-1":                           model.NodeNetwork,
		"arn:aws:ec2:us-east-1:" + acctID + ":subnet/subnet-1":                     model.NodeNetwork,
		"arn:aws:ec2:us-east-1:" + acctID + ":route-table/rtb-1":                   model.NodeNetwork,
		"arn:aws:ec2:us-east-1:" + acctID + ":internet-gateway/igw-1":              model.NodeGateway,
		"arn:aws:ec2:us-east-1:" + acctID + ":egress-only-internet-gateway/eigw-1": model.NodeGateway,
		"arn:aws:ec2:us-east-1:" + acctID + ":natgateway/nat-1":                    model.NodeGateway,
		"arn:aws:ec2:us-east-1:" + acctID + ":security-group/sg-1":                 model.NodeControl,
		"arn:aws:ec2:us-east-1:" + acctID + ":network-acl/acl-1":                   model.NodeControl,
		"arn:aws:ec2:us-east-1:" + acctID + ":network-interface/eni-1":             model.NodeEndpoint,
		"arn:aws:ec2:us-east-1:" + acctID + ":elastic-ip/eipalloc-1":               model.NodeEndpoint,
	}
	if len(s.Nodes) != len(want) {
		t.Errorf("nodes = %d, want %d (the address with no allocation id must not be emitted)", len(s.Nodes), len(want))
	}
	for arn, tp := range want {
		if _, ok := nodeNamed(s, tp, arn); !ok {
			t.Errorf("missing %s node %s", tp, arn)
		}
	}

	vpc, _ := nodeNamed(s, model.NodeNetwork, "arn:aws:ec2:us-east-1:"+acctID+":vpc/vpc-1")
	for k, v := range map[string]string{"aws_type": "vpc", "resource_id": "vpc-1", "region": "us-east-1", "cidr_blocks": "10.0.0.0/16", "igw_block_public_access": "off", "tag:Name": "prod"} {
		if vpc.Attributes[k] != v {
			t.Errorf("vpc %s = %q, want %q", k, vpc.Attributes[k], v)
		}
	}
	if vpc.Name != "prod" {
		t.Errorf("vpc name = %q, want the Name tag", vpc.Name)
	}

	rt, _ := nodeNamed(s, model.NodeNetwork, "arn:aws:ec2:us-east-1:"+acctID+":route-table/rtb-1")
	var routes []routeFact
	if err := json.Unmarshal([]byte(rt.Attributes["routes"]), &routes); err != nil {
		t.Fatalf("routes attr: %v", err)
	}
	if len(routes) != 2 || routes[0].Destination != "0.0.0.0/0" || routes[0].Target != "igw-1" || routes[0].TargetType != "gateway" {
		t.Errorf("routes = %+v, want the default route to igw-1 first (sorted)", routes)
	}

	sg, _ := nodeNamed(s, model.NodeControl, "arn:aws:ec2:us-east-1:"+acctID+":security-group/sg-1")
	var in []sgRule
	if err := json.Unmarshal([]byte(sg.Attributes["ingress_rules"]), &in); err != nil {
		t.Fatalf("ingress attr: %v", err)
	}
	if len(in) != 2 {
		t.Fatalf("ingress rules = %+v, want one per source (IPv4 and IPv6)", in)
	}
	if sg.Attributes["egress_rules"] != "[]" {
		t.Errorf("egress_rules = %q, want [] (no rules is a fact)", sg.Attributes["egress_rules"])
	}

	acl, _ := nodeNamed(s, model.NodeControl, "arn:aws:ec2:us-east-1:"+acctID+":network-acl/acl-1")
	var entries []aclEntry
	if err := json.Unmarshal([]byte(acl.Attributes["entries"]), &entries); err != nil {
		t.Fatalf("entries attr: %v", err)
	}
	if len(entries) != 3 || entries[0].RuleNumber != 100 || entries[0].Egress || entries[1].RuleNumber != 32767 || !entries[2].Egress {
		t.Errorf("entries = %+v, want ingress by rule number then egress", entries)
	}

	eni, _ := nodeNamed(s, model.NodeEndpoint, "arn:aws:ec2:us-east-1:"+acctID+":network-interface/eni-1")
	for k, v := range map[string]string{"public_ip": "203.0.113.10", "security_group_ids": "sg-1", "attached_instance_id": "i-1", "subnet_id": "subnet-1"} {
		if eni.Attributes[k] != v {
			t.Errorf("eni %s = %q, want %q", k, eni.Attributes[k], v)
		}
	}

	if len(s.Links) != 0 {
		t.Errorf("links = %d, want 0 (reachability edges are the reachability engine's job)", len(s.Links))
	}
	for _, c := range s.Completeness {
		if c.Status != collect.Complete {
			t.Errorf("%s@%s = %s, want complete", c.Service, c.Region, c.Status)
		}
	}
	if len(s.Completeness) != len(newNetworkCollector(acctID, nil, nil).services()) {
		t.Errorf("completeness records = %d, want one per service", len(s.Completeness))
	}
}

// TestNetworkRegionalFanOut proves every service is called once per region, in
// order, each targeted at its region, with per-(service,region) completeness and
// region-scoped ARNs.
func TestNetworkRegionalFanOut(t *testing.T) {
	api := estate()
	regions := []string{"us-east-1", "eu-west-1"}
	s := runNetwork(t, api, regions...)
	n := len(newNetworkCollector(acctID, nil, nil).services())
	if api.calls != n*len(regions) {
		t.Errorf("calls = %d, want %d", api.calls, n*len(regions))
	}
	for i, r := range api.regions {
		if want := regions[i/n]; r != want {
			t.Fatalf("call %d targeted %q, want %q (sequential, declared order)", i, r, want)
		}
	}
	if _, ok := nodeNamed(s, model.NodeNetwork, "arn:aws:ec2:eu-west-1:"+acctID+":vpc/vpc-1"); !ok {
		t.Error("eu-west-1 VPC not keyed by its own region")
	}
	if c := instCompleteness(s, "ec2.vpcs", "eu-west-1"); c.Status != collect.Complete {
		t.Errorf("ec2.vpcs@eu-west-1 = %+v, want complete", c)
	}
}

// TestNetworkPaginates proves NextToken pages are followed and counted.
func TestNetworkPaginates(t *testing.T) {
	api := estate()
	api.vpcPages = [][]ec2types.Vpc{
		{{VpcId: ptr("vpc-a"), OwnerId: ptr(acctID)}},
		{{VpcId: ptr("vpc-b"), OwnerId: ptr(acctID)}},
		{{VpcId: ptr("vpc-c"), OwnerId: ptr(acctID)}},
	}
	s := runNetwork(t, api, "us-east-1")
	if c := instCompleteness(s, "ec2.vpcs", "us-east-1"); c.Status != collect.Complete || c.Collected != 3 {
		t.Errorf("ec2.vpcs = %+v, want complete with 3", c)
	}
	if n := nodesByType(s)[model.NodeNetwork]; n != 5 { // 3 VPCs + subnet + route table
		t.Errorf("network nodes = %d, want 5", n)
	}
}

// TestNetworkDeniedRegionIsGap proves a denial in one region is a Denied record
// for that (service, region) only; everything else still completes.
func TestNetworkDeniedRegionIsGap(t *testing.T) {
	api := estate()
	api.errs["DescribeSecurityGroups@eu-west-1"] = apiErr("UnauthorizedOperation")
	s := runNetwork(t, api, "us-east-1", "eu-west-1")
	if c := instCompleteness(s, "ec2.securityGroups", "eu-west-1"); c.Status != collect.Denied {
		t.Errorf("ec2.securityGroups@eu-west-1 = %+v, want denied", c)
	}
	if c := instCompleteness(s, "ec2.networkAcls", "eu-west-1"); c.Status != collect.Complete {
		t.Errorf("later services in the denied region must still run: %+v", c)
	}
}

// TestNetworkUnreachableRegionIsPartialGap proves a transport failure (no API
// error code) is a non-fatal Partial "unreachable" gap for that region only.
func TestNetworkUnreachableRegionIsPartialGap(t *testing.T) {
	api := estate()
	api.errs["DescribeVpcs@me-south-1"] = errors.New("dial tcp: connection timed out")
	var s collect.Scan
	err := newNetworkCollector(acctID, api, []string{"us-east-1", "me-south-1"}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("one region's transport failure must not fail the run: %v", err)
	}
	if c := instCompleteness(s, "ec2.vpcs", "me-south-1"); c.Status != collect.Partial || c.Reason != "unreachable" {
		t.Errorf("ec2.vpcs@me-south-1 = %+v, want partial unreachable", c)
	}
	if c := instCompleteness(s, "ec2.vpcs", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.vpcs@us-east-1 = %+v, want complete", c)
	}
}

// TestNetworkDialTimeoutIsNonFatalGap proves the case the live run caught: a dial
// timeout, whose error wraps context.DeadlineExceeded while the scan context is
// still live, is a non-fatal Partial "unreachable" gap for that region, not a
// fatal error that sinks the whole sweep.
func TestNetworkDialTimeoutIsNonFatalGap(t *testing.T) {
	api := estate()
	api.errs["DescribeVpcs@me-south-1"] = fmt.Errorf("operation error EC2: DescribeVpcs, exceeded maximum number of attempts, 2, request send failed, dial tcp 99.82.136.87:443: %w", context.DeadlineExceeded)
	var s collect.Scan
	err := newNetworkCollector(acctID, api, []string{"us-east-1", "me-south-1"}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("a dial timeout must not fail the run: %v", err)
	}
	if c := instCompleteness(s, "ec2.vpcs", "me-south-1"); c.Status != collect.Partial || c.Reason != "unreachable" {
		t.Errorf("ec2.vpcs@me-south-1 = %+v, want partial unreachable", c)
	}
	if c := instCompleteness(s, "ec2.vpcs", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.vpcs@us-east-1 = %+v, want complete", c)
	}
}

// TestNetworkRegionNotEnabledIsUnsupported proves an opt-in region not enabled is
// a recorded Unsupported gap.
func TestNetworkRegionNotEnabledIsUnsupported(t *testing.T) {
	api := estate()
	api.errs["DescribeVpcs@ap-east-1"] = apiErr("OptInRequired")
	s := runNetwork(t, api, "us-east-1", "ap-east-1")
	if c := instCompleteness(s, "ec2.vpcs", "ap-east-1"); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("ec2.vpcs@ap-east-1 = %+v, want unsupported 'region not enabled'", c)
	}
}

// TestNetworkUnexpectedErrorSurfaces proves an unexpected error is Errored and
// returned, while the remaining enumerations still run.
func TestNetworkUnexpectedErrorSurfaces(t *testing.T) {
	api := estate()
	api.errs["DescribeVpcs@us-east-1"] = apiErr("InternalError")
	var s collect.Scan
	err := newNetworkCollector(acctID, api, []string{"us-east-1", "eu-west-1"}).Collect(context.Background(), &s)
	if err == nil {
		t.Fatal("unexpected error must surface")
	}
	if c := instCompleteness(s, "ec2.vpcs", "us-east-1"); c.Status != collect.Errored {
		t.Errorf("ec2.vpcs@us-east-1 = %+v, want error", c)
	}
	if c := instCompleteness(s, "ec2.vpcs", "eu-west-1"); c.Status != collect.Complete {
		t.Errorf("other regions must still collect: %+v", c)
	}
}

// TestNetworkBudgetExhaustionMarksUnreached proves the shared budget bounds the
// fan-out: once it runs out, every (service, region) not yet reached is Partial
// "budget exhausted", none skipped.
func TestNetworkBudgetExhaustionMarksUnreached(t *testing.T) {
	api := estate()
	regions := []string{"us-east-1", "eu-west-1"}
	c := newNetworkCollector(acctID, api, regions)
	c.budget = collect.NewBudget(3)
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 3 {
		t.Errorf("made %d calls under a 3-call budget", api.calls)
	}
	n := len(c.services())
	if len(s.Completeness) != n*len(regions) {
		t.Fatalf("completeness records = %d, want %d", len(s.Completeness), n*len(regions))
	}
	exhausted := 0
	for _, rec := range s.Completeness {
		if rec.Status == collect.Partial && rec.Reason == "budget exhausted" {
			exhausted++
		}
	}
	if exhausted != n*len(regions)-3 {
		t.Errorf("budget-exhausted records = %d, want %d", exhausted, n*len(regions)-3)
	}
}

// TestNetworkCancellation proves a cancelled context stops the scan.
func TestNetworkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var s collect.Scan
	err := newNetworkCollector(acctID, estate(), []string{"us-east-1"}).Collect(ctx, &s)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestNetworkDeterministic proves identical inputs produce identical nodes.
func TestNetworkDeterministic(t *testing.T) {
	a := runNetwork(t, estate(), "us-east-1", "eu-west-1")
	b := runNetwork(t, estate(), "us-east-1", "eu-west-1")
	if !reflect.DeepEqual(a.Nodes, b.Nodes) {
		t.Error("network nodes differ between identical runs")
	}
}

// TestNetworkEvidenceRedactsToken proves the evidence body is scrubbed.
func TestNetworkEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Q", 16)
	api := estate()
	api.vpcPages[0][0].Tags = append(api.vpcPages[0][0].Tags, ec2types.Tag{Key: ptr("note"), Value: ptr(token)})
	s := runNetwork(t, api, "us-east-1")
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token-like value: %s", e.Operation)
		}
	}
}
