package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubVPCE is an offline vpcEndpointAPI: a per-region slice of endpoints and an
// optional per-region error ("DescribeVpcEndpoints@region").
type stubVPCE struct {
	byRegion map[string][]ec2types.VpcEndpoint
	errs     map[string]error
}

func (s *stubVPCE) DescribeVpcEndpoints(_ context.Context, _ *ec2.DescribeVpcEndpointsInput, o ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	r := ec2Region(o)
	if err := s.errs["DescribeVpcEndpoints@"+r]; err != nil {
		return nil, err
	}
	return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: s.byRegion[r]}, nil
}

func runVPCE(t *testing.T, api vpcEndpointAPI, regions ...string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newVPCEndpointCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func endpoint(id, typ, svc string, policy string) ec2types.VpcEndpoint {
	e := ec2types.VpcEndpoint{
		VpcEndpointId:   ptr(id),
		VpcEndpointType: ec2types.VpcEndpointType(typ),
		ServiceName:     ptr(svc),
		VpcId:           ptr("vpc-1"),
		State:           ec2types.StateAvailable,
		OwnerId:         ptr(acctID),
	}
	if policy != "" {
		e.PolicyDocument = ptr(policy)
	}
	return e
}

func gatewayNode(s collect.Scan, idSuffix string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeGateway && strings.HasSuffix(n.NativeID, idSuffix) {
			return n, true
		}
	}
	return collect.Node{}, false
}

const (
	defaultEndpointPolicy = `{"Statement":[{"Action":"*","Effect":"Allow","Principal":"*","Resource":"*"}]}`
	// A customized, still-open policy: wildcard principal and action, but NOT the
	// single-statement default (it adds a second statement), and no condition.
	openCustomPolicy = `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999:root"},"Action":"s3:GetObject","Resource":"*"}]}`
	// A locked-down policy: a specific principal, a condition narrows it.
	scopedPolicy = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc"}}}]}`
)

// TestVPCEndpointPolicyFacts proves each endpoint becomes a gateway node with the
// structural policy facts a rule needs, and that the facts are descriptive, not a
// verdict: the AWS default is marked policy_default, a customized open policy is
// wildcard+unconditional but not default, and a scoped policy is neither wildcard
// nor unconditional.
func TestVPCEndpointPolicyFacts(t *testing.T) {
	s := runVPCE(t, &stubVPCE{byRegion: map[string][]ec2types.VpcEndpoint{
		"us-east-1": {
			endpoint("vpce-default", "Gateway", "com.amazonaws.us-east-1.s3", defaultEndpointPolicy),
			endpoint("vpce-open", "Interface", "com.amazonaws.us-east-1.ssm", openCustomPolicy),
			endpoint("vpce-scoped", "Gateway", "com.amazonaws.us-east-1.dynamodb", scopedPolicy),
			endpoint("vpce-nopolicy", "Interface", "com.amazonaws.us-east-1.ec2", ""),
		},
	}}, "us-east-1")

	if c := completenessOf(s, "ec2.vpcEndpoints"); c.Status != collect.Complete || c.Collected != 4 {
		t.Fatalf("ec2.vpcEndpoints = %+v, want complete/4", c)
	}

	def, ok := gatewayNode(s, "vpc-endpoint/vpce-default")
	if !ok {
		t.Fatal("default endpoint node missing")
	}
	if def.Attributes["policy_default"] != "true" || def.Attributes["endpoint_type"] != "Gateway" {
		t.Errorf("default endpoint facts = %+v", def.Attributes)
	}

	open, ok := gatewayNode(s, "vpc-endpoint/vpce-open")
	if !ok {
		t.Fatal("open endpoint node missing")
	}
	if open.Attributes["policy_default"] != "false" || open.Attributes["policy_principal_wildcard"] != "true" ||
		open.Attributes["policy_action_wildcard"] != "true" || open.Attributes["policy_has_condition"] != "false" {
		t.Errorf("open endpoint facts = %+v, want non-default wildcard/unconditional", open.Attributes)
	}

	scoped, ok := gatewayNode(s, "vpc-endpoint/vpce-scoped")
	if !ok {
		t.Fatal("scoped endpoint node missing")
	}
	if scoped.Attributes["policy_principal_wildcard"] != "false" || scoped.Attributes["policy_has_condition"] != "true" {
		t.Errorf("scoped endpoint facts = %+v, want no-wildcard/with-condition", scoped.Attributes)
	}

	nop, ok := gatewayNode(s, "vpc-endpoint/vpce-nopolicy")
	if !ok {
		t.Fatal("no-policy endpoint node missing")
	}
	if nop.Attributes["has_policy"] != "false" {
		t.Errorf("no-policy endpoint should record has_policy=false: %+v", nop.Attributes)
	}
}

// TestVPCEndpointRegionNotEnabledIsUnsupported proves an opt-in region that is not
// enabled is an Unsupported gap, never a silent skip, and the other region still
// reports.
func TestVPCEndpointRegionNotEnabledIsUnsupported(t *testing.T) {
	s := runVPCE(t, &stubVPCE{
		byRegion: map[string][]ec2types.VpcEndpoint{"us-east-1": {endpoint("vpce-1", "Gateway", "s3", "")}},
		errs:     map[string]error{"DescribeVpcEndpoints@ap-east-1": apiErr("OptInRequired")},
	}, "us-east-1", "ap-east-1")

	if c := completenessOf2(s, "ec2.vpcEndpoints", "ap-east-1"); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("ap-east-1 = %+v, want unsupported/region not enabled", c)
	}
	if c := completenessOf2(s, "ec2.vpcEndpoints", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("us-east-1 = %+v, want complete", c)
	}
}

// TestVPCEndpointDeniedIsGap proves a denied read is a Denied gap with no nodes.
func TestVPCEndpointDeniedIsGap(t *testing.T) {
	s := runVPCE(t, &stubVPCE{errs: map[string]error{"DescribeVpcEndpoints@us-east-1": apiErr("UnauthorizedOperation")}}, "us-east-1")
	if statusOf(s, "ec2.vpcEndpoints") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "ec2.vpcEndpoints"))
	}
	if nodesByType(s)[model.NodeGateway] != 0 {
		t.Error("no gateway nodes should be emitted on a denied read")
	}
}

// completenessOf2 returns the completeness for a (service, region) pair.
func completenessOf2(s collect.Scan, service, region string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service && c.Region == region {
			return c
		}
	}
	return collect.Completeness{}
}
