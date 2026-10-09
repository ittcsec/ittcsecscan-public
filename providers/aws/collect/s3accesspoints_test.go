package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func s3cRegion(o []func(*s3control.Options)) string {
	opt := &s3control.Options{}
	for _, f := range o {
		f(opt)
	}
	return opt.Region
}

// stubRegions is an offline regionStatusAPI: it returns each region's opt-in status,
// or an error.
type stubRegions struct {
	optIn map[string]string // region -> OptInStatus (opt-in-not-required | opted-in | not-opted-in)
	err   error
}

func (s *stubRegions) DescribeRegions(_ context.Context, _ *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	var regs []ec2types.Region
	for r, st := range s.optIn {
		regs = append(regs, ec2types.Region{RegionName: ptr(r), OptInStatus: ptr(st)})
	}
	return &ec2.DescribeRegionsOutput{Regions: regs}, nil
}

// allEnabled builds a stubRegions that marks every named region enabled.
func allEnabled(regions ...string) *stubRegions {
	optIn := map[string]string{}
	for _, r := range regions {
		optIn[r] = "opt-in-not-required"
	}
	return &stubRegions{optIn: optIn}
}

// stubS3AP is an offline s3AccessPointAPI keyed by region and access point name.
type stubS3AP struct {
	byRegion   map[string][]s3ctypes.AccessPoint
	public     map[string]bool   // name -> IsPublic
	policies   map[string]string // name -> policy JSON (absent -> NoSuchAccessPointPolicy)
	errs       map[string]error  // "ListAccessPoints@region", "status@name", "policy@name"
	listedRegs []string          // regions ListAccessPoints was actually called in
}

func (s *stubS3AP) ListAccessPoints(_ context.Context, _ *s3control.ListAccessPointsInput, o ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error) {
	r := s3cRegion(o)
	s.listedRegs = append(s.listedRegs, r)
	if err := s.errs["ListAccessPoints@"+r]; err != nil {
		return nil, err
	}
	return &s3control.ListAccessPointsOutput{AccessPointList: s.byRegion[r]}, nil
}

func (s *stubS3AP) GetAccessPointPolicyStatus(_ context.Context, in *s3control.GetAccessPointPolicyStatusInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error) {
	name := deref(in.Name)
	if err := s.errs["status@"+name]; err != nil {
		return nil, err
	}
	if _, has := s.policies[name]; !has {
		return nil, apiErr("NoSuchAccessPointPolicy")
	}
	return &s3control.GetAccessPointPolicyStatusOutput{PolicyStatus: &s3ctypes.PolicyStatus{IsPublic: s.public[name]}}, nil
}

func (s *stubS3AP) GetAccessPointPolicy(_ context.Context, in *s3control.GetAccessPointPolicyInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyOutput, error) {
	name := deref(in.Name)
	if err := s.errs["policy@"+name]; err != nil {
		return nil, err
	}
	pol, has := s.policies[name]
	if !has {
		return nil, apiErr("NoSuchAccessPointPolicy")
	}
	return &s3control.GetAccessPointPolicyOutput{Policy: ptr(pol)}, nil
}

func runS3AP(t *testing.T, api s3AccessPointAPI, regions ...string) collect.Scan {
	t.Helper()
	// Default: every region under test is enabled (opt-in-not-required).
	return runS3APEC2(t, api, allEnabled(regions...), regions...)
}

func runS3APEC2(t *testing.T, api s3AccessPointAPI, ec2api regionStatusAPI, regions ...string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newS3AccessPointCollector(acctID, api, ec2api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func accessPoint(name, bucket string, origin s3ctypes.NetworkOrigin) s3ctypes.AccessPoint {
	return s3ctypes.AccessPoint{
		Name:           ptr(name),
		Bucket:         ptr(bucket),
		NetworkOrigin:  origin,
		AccessPointArn: ptr("arn:aws:s3:us-east-1:" + acctID + ":accesspoint/" + name),
		Alias:          ptr(name + "-alias"),
	}
}

func endpointNode(s collect.Scan, nameSuffix string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeEndpoint && strings.HasSuffix(n.NativeID, nameSuffix) {
			return n, true
		}
	}
	return collect.Node{}, false
}

const openAPPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`

// TestS3AccessPointPublic proves an Internet-origin public access point with a
// wildcard-principal policy is recorded is_public=true, network_origin=Internet,
// resource_policy=open, and a routes_to edge to its bucket node is emitted.
func TestS3AccessPointPublic(t *testing.T) {
	s := runS3AP(t, &stubS3AP{
		byRegion: map[string][]s3ctypes.AccessPoint{"us-east-1": {accessPoint("pub", "data-bucket", s3ctypes.NetworkOriginInternet)}},
		public:   map[string]bool{"pub": true},
		policies: map[string]string{"pub": openAPPolicy},
	}, "us-east-1")

	if c := s3apCompletenessAt(s, "s3.accessPoints", "us-east-1"); c.Status != collect.Complete || c.Collected != 1 {
		t.Fatalf("s3.accessPoints = %+v, want complete/1", c)
	}
	n, ok := endpointNode(s, "accesspoint/pub")
	if !ok {
		t.Fatal("access point node not emitted")
	}
	for k, want := range map[string]string{
		"is_public": "true", "network_origin": "Internet", "resource_policy": "open",
		"policy_principal_wildcard": "true", "bucket": "data-bucket",
	} {
		if n.Attributes[k] != want {
			t.Errorf("fact %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	found := false
	for _, l := range s.Links {
		if l.Kind == model.EdgeRoutesTo && strings.HasSuffix(l.SourceNativeID, "accesspoint/pub") && l.TargetNativeID == "arn:aws:s3:::data-bucket" {
			found = true
		}
	}
	if !found {
		t.Errorf("no routes_to edge to the bucket node: %+v", s.Links)
	}
}

// TestS3AccessPointVPCNoPolicy proves a VPC-origin access point with no policy is
// recorded is_public=false, network_origin=VPC, resource_policy=none.
func TestS3AccessPointVPCNoPolicy(t *testing.T) {
	s := runS3AP(t, &stubS3AP{
		byRegion: map[string][]s3ctypes.AccessPoint{"us-east-1": {accessPoint("vpc", "b", s3ctypes.NetworkOriginVpc)}},
		// no policy entry -> status and policy both return NoSuchAccessPointPolicy
	}, "us-east-1")
	n, ok := endpointNode(s, "accesspoint/vpc")
	if !ok {
		t.Fatal("access point node not emitted")
	}
	for k, want := range map[string]string{"is_public": "false", "network_origin": "VPC", "resource_policy": "none"} {
		if n.Attributes[k] != want {
			t.Errorf("fact %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
}

// TestS3AccessPointDeniedListIsGap proves a denied list is Denied with no nodes and
// an honest Complete/0 access pass.
func TestS3AccessPointDeniedListIsGap(t *testing.T) {
	s := runS3AP(t, &stubS3AP{errs: map[string]error{"ListAccessPoints@us-east-1": apiErr("AccessDenied")}}, "us-east-1")
	if statusOf(s, "s3.accessPoints") != collect.Denied {
		t.Errorf("s3.accessPoints = %s, want denied", statusOf(s, "s3.accessPoints"))
	}
	if c := s3apCompletenessAt(s, "s3.accessPointAccess", "us-east-1"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("s3.accessPointAccess = %+v, want complete/0", c)
	}
	if nodesByType(s)[model.NodeEndpoint] != 0 {
		t.Error("no access point nodes should be emitted on a denied list")
	}
}

// TestS3AccessPointStatusFailureIsUnknown proves an access point whose policy-status
// read failed is is_public=unknown and the access pass is Partial with the reason.
func TestS3AccessPointStatusFailureIsUnknown(t *testing.T) {
	s := runS3AP(t, &stubS3AP{
		byRegion: map[string][]s3ctypes.AccessPoint{"us-east-1": {accessPoint("x", "b", s3ctypes.NetworkOriginInternet)}},
		errs:     map[string]error{"status@x": apiErr("AccessDenied")},
	}, "us-east-1")
	n, ok := endpointNode(s, "accesspoint/x")
	if !ok || n.Attributes["is_public"] != "unknown" {
		t.Errorf("access point with failed status read is_public = %q (ok=%v), want unknown", n.Attributes["is_public"], ok)
	}
	if c := s3apCompletenessAt(s, "s3.accessPointAccess", "us-east-1"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("s3.accessPointAccess = %+v, want partial/denied", c)
	}
}

// TestS3AccessPointNotOptedInIsUnsupported proves that a region EC2 reports as
// not-opted-in is recorded Unsupported from the authoritative opt-in status, and S3
// Control is not called there at all (so a disabled region never even risks an
// ambiguous AccessDenied).
func TestS3AccessPointNotOptedInIsUnsupported(t *testing.T) {
	api := &stubS3AP{byRegion: map[string][]s3ctypes.AccessPoint{"us-east-1": {accessPoint("a", "b", s3ctypes.NetworkOriginInternet)}}}
	ec2api := &stubRegions{optIn: map[string]string{"us-east-1": "opt-in-not-required", "ap-east-1": "not-opted-in"}}
	s := runS3APEC2(t, api, ec2api, "us-east-1", "ap-east-1")

	if c := s3apCompletenessAt(s, "s3.accessPoints", "ap-east-1"); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("ap-east-1 = %+v, want unsupported/region not enabled", c)
	}
	for _, r := range api.listedRegs {
		if r == "ap-east-1" {
			t.Error("S3 Control ListAccessPoints must not be called in a not-opted-in region")
		}
	}
	if c := s3apCompletenessAt(s, "s3.accessPoints", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("us-east-1 = %+v, want complete", c)
	}
}

// TestS3AccessPointEnabledRegionDeniedStaysDenied proves the key guarantee: in a
// region the account HAS opted into, an AccessDenied from S3 Control is a genuine
// permission denial and is recorded Denied, never reclassified to Unsupported.
func TestS3AccessPointEnabledRegionDeniedStaysDenied(t *testing.T) {
	api := &stubS3AP{errs: map[string]error{"ListAccessPoints@us-east-1": apiErr("AccessDenied")}}
	ec2api := &stubRegions{optIn: map[string]string{"us-east-1": "opt-in-not-required"}}
	s := runS3APEC2(t, api, ec2api, "us-east-1")
	if c := s3apCompletenessAt(s, "s3.accessPoints", "us-east-1"); c.Status != collect.Denied {
		t.Errorf("us-east-1 = %+v, want denied (a real denial in an enabled region is never reclassified)", c)
	}
}

// TestS3AccessPointRegionStatusUnknownFallsBackLiterally proves that if the region
// opt-in read itself fails, the collector attempts every region and classifies each
// error literally (AccessDenied stays Denied), so a real denial is still never masked.
func TestS3AccessPointRegionStatusUnknownFallsBackLiterally(t *testing.T) {
	api := &stubS3AP{errs: map[string]error{"ListAccessPoints@ap-east-1": apiErr("AccessDenied")}}
	ec2api := &stubRegions{err: apiErr("AccessDenied")} // region status unavailable
	s := runS3APEC2(t, api, ec2api, "ap-east-1")

	if c := s3apCompletenessAt(s, "s3.regionOptInStatus", "global"); c.Status != collect.Denied {
		t.Errorf("s3.regionOptInStatus = %+v, want denied (the status read failed)", c)
	}
	if c := s3apCompletenessAt(s, "s3.accessPoints", "ap-east-1"); c.Status != collect.Denied {
		t.Errorf("ap-east-1 = %+v, want denied (no inference when region status is unknown)", c)
	}
}

func s3apCompletenessAt(s collect.Scan, service, region string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service && c.Region == region {
			return c
		}
	}
	return collect.Completeness{}
}
