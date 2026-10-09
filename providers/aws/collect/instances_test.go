package collect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestIsTransportClassification proves the shared transient classifier treats the
// three transient shapes as retryable (so they become a per-region gap, never a
// fatal scan error) while a genuine modeled API error stays non-transient.
func TestIsTransportClassification(t *testing.T) {
	// Retry exhaustion wrapping a modeled API error: how a real 503 surfaces (caught
	// live against CloudTrail, where UnknownError/503 was wrapped in MaxAttemptsError
	// and the plain API-error check misclassified it as fatal).
	retryExhausted := &retry.MaxAttemptsError{Attempt: 2, Err: apiErr("UnknownError")}
	if !isTransport(retryExhausted) {
		t.Error("retry exhaustion must be transient")
	}
	// A 5xx server response that still carries an API error code is transient.
	server503 := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusServiceUnavailable}},
		Err:      apiErr("ServiceUnavailable"),
	}
	if !isTransport(server503) {
		t.Error("a 5xx server response must be transient")
	}
	// A plain non-API transport failure (dial timeout, reset) is transient.
	if !isTransport(errors.New("dial tcp: i/o timeout")) {
		t.Error("a transport failure must be transient")
	}
	// A genuine modeled API error (a real denial) must NOT be transient, or a real
	// permission gap would be masked as a retryable blip.
	if isTransport(apiErr("AccessDenied")) {
		t.Error("a modeled API error must not be transient")
	}
	// A 4xx response error is a client error, not transient.
	client403 := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}},
		Err:      apiErr("AccessDenied"),
	}
	if isTransport(client403) {
		t.Error("a 4xx response must not be transient")
	}
}

const acctID = "123456789012"

// stubEC2Inst is an offline instancesEC2API. It returns the same instances in
// every region (or paginated pages), records each call's region, and can inject a
// per-region error.
type stubEC2Inst struct {
	instances []ec2types.Instance
	pages     [][]ec2types.Instance // if set, paginated; NextToken chains
	errs      map[string]error      // region -> error
	calls     int
	regions   []string
}

func ec2Region(opts []func(*ec2.Options)) string {
	var o ec2.Options
	for _, f := range opts {
		f(&o)
	}
	return o.Region
}

func (s *stubEC2Inst) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, o ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	s.calls++
	r := ec2Region(o)
	s.regions = append(s.regions, r)
	if err := s.errs[r]; err != nil {
		return nil, err
	}
	if len(s.pages) > 0 {
		page := 0
		if in.NextToken != nil {
			page = int((*in.NextToken)[0] - '0')
		}
		out := &ec2.DescribeInstancesOutput{}
		if page < len(s.pages) {
			out.Reservations = []ec2types.Reservation{{Instances: s.pages[page]}}
		}
		if page+1 < len(s.pages) {
			out.NextToken = ptr(string(rune('0' + page + 1)))
		}
		return out, nil
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: s.instances}}}, nil
}

// stubProfiles is an offline instanceProfileAPI mapping a profile name to its
// role, with per-profile error injection.
type stubProfiles struct {
	roleARN  map[string]string // profile name -> role ARN ("" absent = profile with no role)
	roleName map[string]string // profile name -> role name
	errs     map[string]error  // profile name -> error
	calls    int
}

func (s *stubProfiles) GetInstanceProfile(_ context.Context, in *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	s.calls++
	name := deref(in.InstanceProfileName)
	if err := s.errs[name]; err != nil {
		return nil, err
	}
	out := &iam.GetInstanceProfileOutput{InstanceProfile: &iamtypes.InstanceProfile{InstanceProfileName: ptr(name)}}
	if arn := s.roleARN[name]; arn != "" {
		out.InstanceProfile.Roles = []iamtypes.Role{{Arn: ptr(arn), RoleName: ptr(s.roleName[name])}}
	}
	return out, nil
}

// oneInstance is an instance with an instance profile, a public IP, a security
// group, and a Name tag, in the given reservation shape.
func oneInstance() []ec2types.Instance {
	return []ec2types.Instance{{
		InstanceId:         ptr("i-1"),
		InstanceType:       ec2types.InstanceTypeT3Micro,
		State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		ImageId:            ptr("ami-1"),
		VpcId:              ptr("vpc-1"),
		SubnetId:           ptr("subnet-1"),
		PrivateIpAddress:   ptr("10.0.0.5"),
		PublicIpAddress:    ptr("203.0.113.5"),
		PublicDnsName:      ptr("ec2-203-0-113-5.compute.amazonaws.com"),
		Placement:          &ec2types.Placement{AvailabilityZone: ptr("us-east-1a")},
		SecurityGroups:     []ec2types.GroupIdentifier{{GroupId: ptr("sg-1")}},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: ptr("arn:aws:iam::" + acctID + ":instance-profile/prof-1")},
		Tags:               []ec2types.Tag{{Key: ptr("Name"), Value: ptr("web")}},
	}}
}

func profilesFor() *stubProfiles {
	return &stubProfiles{
		roleARN:  map[string]string{"prof-1": "arn:aws:iam::" + acctID + ":role/app"},
		roleName: map[string]string{"prof-1": "app"},
		errs:     map[string]error{},
	}
}

func runInstances(t *testing.T, ec2api instancesEC2API, iamapi instanceProfileAPI, regions ...string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newInstanceCollector(acctID, ec2api, iamapi, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func instCompleteness(s collect.Scan, service, region string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service && c.Region == region {
			return c
		}
	}
	return collect.Completeness{}
}

// TestInstancesMapsAndRunAsEdge proves an instance becomes a compute node keyed by
// its synthesized ARN with its metadata as facts, and the run-as edge resolves to
// the role its instance profile grants (keyed by role ARN).
func TestInstancesMapsAndRunAsEdge(t *testing.T) {
	s := runInstances(t, &stubEC2Inst{instances: oneInstance()}, profilesFor(), "us-east-1")

	arn := "arn:aws:ec2:us-east-1:" + acctID + ":instance/i-1"
	n, ok := nodeNamed(s, model.NodeCompute, arn)
	if !ok {
		t.Fatalf("instance not keyed by ARN %s", arn)
	}
	for k, v := range map[string]string{
		"instance_id": "i-1", "instance_type": "t3.micro", "state": "running", "region": "us-east-1",
		"availability_zone": "us-east-1a", "vpc_id": "vpc-1", "subnet_id": "subnet-1",
		"private_ip": "10.0.0.5", "public_ip": "203.0.113.5", "security_group_ids": "sg-1",
		"iam_instance_profile_arn": "arn:aws:iam::" + acctID + ":instance-profile/prof-1", "tag:Name": "web",
	} {
		if n.Attributes[k] != v {
			t.Errorf("attr %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if n.Name != "web" {
		t.Errorf("name = %q, want the Name tag", n.Name)
	}

	roleARN := "arn:aws:iam::" + acctID + ":role/app"
	if _, ok := nodeNamed(s, model.NodeRole, roleARN); !ok {
		t.Error("run-as target role node not emitted")
	}
	var found bool
	for _, l := range s.Links {
		if l.SourceNativeID == arn && l.TargetNativeID == roleARN {
			if l.Kind != model.EdgeAssumes {
				t.Errorf("run-as edge kind = %s, want assumes", l.Kind)
			}
			found = true
		}
	}
	if !found {
		t.Error("missing instance -> role run-as edge")
	}
	if c := instCompleteness(s, "ec2.instanceRoles", collect.Global); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("ec2.instanceRoles = %+v, want complete with 1", c)
	}
}

// TestInstancesNoProfileNoEdge proves an instance without an instance profile
// yields no run-as edge and no role node, and is not a gap.
func TestInstancesNoProfileNoEdge(t *testing.T) {
	inst := oneInstance()
	inst[0].IamInstanceProfile = nil
	prof := profilesFor()
	s := runInstances(t, &stubEC2Inst{instances: inst}, prof, "us-east-1")
	if len(s.Links) != 0 {
		t.Errorf("links = %+v, want none", s.Links)
	}
	if prof.calls != 0 {
		t.Errorf("GetInstanceProfile calls = %d, want 0", prof.calls)
	}
	if c := instCompleteness(s, "ec2.instanceRoles", collect.Global); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("ec2.instanceRoles = %+v, want complete with 0", c)
	}
}

// TestInstancesRegionalFanOut proves each region is enumerated, targeted at its
// own region, with region-scoped ARNs and per-region completeness, and a shared
// profile resolved once.
func TestInstancesRegionalFanOut(t *testing.T) {
	ec2api := &stubEC2Inst{instances: oneInstance()}
	prof := profilesFor()
	regions := []string{"us-east-1", "eu-west-1"}
	s := runInstances(t, ec2api, prof, regions...)
	if ec2api.calls != 2 {
		t.Errorf("DescribeInstances calls = %d, want 2 (one per region)", ec2api.calls)
	}
	for i, r := range ec2api.regions {
		if r != regions[i] {
			t.Errorf("call %d targeted %q, want %q", i, r, regions[i])
		}
	}
	if _, ok := nodeNamed(s, model.NodeCompute, "arn:aws:ec2:eu-west-1:"+acctID+":instance/i-1"); !ok {
		t.Error("eu-west-1 instance not keyed by its own region")
	}
	// The same profile appears in both regions but is resolved once.
	if prof.calls != 1 {
		t.Errorf("GetInstanceProfile calls = %d, want 1 (profile resolved once)", prof.calls)
	}
	for _, r := range regions {
		if c := instCompleteness(s, "ec2.instances", r); c.Status != collect.Complete {
			t.Errorf("ec2.instances@%s = %+v, want complete", r, c)
		}
	}
}

// TestInstancesRegionNotEnabledIsUnsupported proves an opt-in region the account
// has not enabled is a recorded Unsupported gap, not Denied and not an error.
func TestInstancesRegionNotEnabledIsUnsupported(t *testing.T) {
	ec2api := &stubEC2Inst{instances: oneInstance(), errs: map[string]error{"ap-east-1": apiErr("OptInRequired")}}
	s := runInstances(t, ec2api, profilesFor(), "us-east-1", "ap-east-1")
	if c := instCompleteness(s, "ec2.instances", "ap-east-1"); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("ec2.instances@ap-east-1 = %+v, want unsupported 'region not enabled'", c)
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.instances@us-east-1 = %+v, want complete", c)
	}
}

// TestInstancesDeniedRegionIsGap proves a denied region is a Denied gap, the other
// regions still collect, and the run is not an error.
func TestInstancesDeniedRegionIsGap(t *testing.T) {
	ec2api := &stubEC2Inst{instances: oneInstance(), errs: map[string]error{"eu-west-1": apiErr("UnauthorizedOperation")}}
	s := runInstances(t, ec2api, profilesFor(), "us-east-1", "eu-west-1")
	if c := instCompleteness(s, "ec2.instances", "eu-west-1"); c.Status != collect.Denied {
		t.Errorf("ec2.instances@eu-west-1 = %+v, want denied", c)
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.instances@us-east-1 = %+v, want complete", c)
	}
}

// TestInstancesTransportErrorIsNonFatalGap proves a transport failure (a dial
// timeout with no API error code, as a not-enabled or unreachable region can
// produce) is a non-fatal Partial "unreachable" gap for that region only: the run
// does not fail and the other regions still collect (ADR-0018 §4). This is the
// case live verification caught against a real unreachable regional endpoint.
func TestInstancesTransportErrorIsNonFatalGap(t *testing.T) {
	ec2api := &stubEC2Inst{instances: oneInstance(), errs: map[string]error{
		"me-south-1": errors.New("dial tcp 99.82.136.87:443: connectex: connection timed out"),
	}}
	var s collect.Scan
	err := newInstanceCollector(acctID, ec2api, profilesFor(), []string{"us-east-1", "me-south-1"}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("one region's transport failure must not fail the run: %v", err)
	}
	if c := instCompleteness(s, "ec2.instances", "me-south-1"); c.Status != collect.Partial || c.Reason != "unreachable" {
		t.Errorf("ec2.instances@me-south-1 = %+v, want partial unreachable", c)
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.instances@us-east-1 = %+v, want complete (a peer region's transport failure must not block it)", c)
	}
}

// TestInstancesDialTimeoutIsNonFatalGap proves the exact case the live run caught:
// a dial timeout, whose error wraps context.DeadlineExceeded while the scan's own
// context is still live, is a non-fatal Partial "unreachable" gap for that region,
// not a fatal error that sinks the scan.
func TestInstancesDialTimeoutIsNonFatalGap(t *testing.T) {
	dialTimeout := fmt.Errorf("operation error EC2: DescribeInstances, exceeded maximum number of attempts, 2, request send failed, dial tcp 99.82.136.87:443: %w", context.DeadlineExceeded)
	ec2api := &stubEC2Inst{instances: oneInstance(), errs: map[string]error{"me-south-1": dialTimeout}}
	var s collect.Scan
	err := newInstanceCollector(acctID, ec2api, profilesFor(), []string{"us-east-1", "me-south-1"}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("a dial timeout must not fail the run: %v", err)
	}
	if c := instCompleteness(s, "ec2.instances", "me-south-1"); c.Status != collect.Partial || c.Reason != "unreachable" {
		t.Errorf("ec2.instances@me-south-1 = %+v, want partial unreachable", c)
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.instances@us-east-1 = %+v, want complete", c)
	}
}

// cancelingEC2 cancels the scan context during the call, then returns a
// cancellation-wrapping error, to exercise the after-call ctx.Err() guard.
type cancelingEC2 struct{ cancel context.CancelFunc }

func (c *cancelingEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	c.cancel()
	return nil, fmt.Errorf("request send failed: %w", context.Canceled)
}

// TestInstancesScanCancellationIsNotUnreachable proves genuine cancellation of the
// scan's own context is recorded "cancelled" and surfaced, never misclassified as
// an "unreachable" transport gap.
func TestInstancesScanCancellationIsNotUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var s collect.Scan
	err := newInstanceCollector(acctID, &cancelingEC2{cancel: cancel}, profilesFor(), []string{"us-east-1"}).Collect(ctx, &s)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Reason != "cancelled" {
		t.Errorf("ec2.instances@us-east-1 = %+v, want reason cancelled", c)
	}
}

// TestInstancesProfileDeniedIsGapNotFatal proves a denied GetInstanceProfile is a
// Partial gap on ec2.instanceRoles; the instance node is still emitted, without a
// run-as edge, and the run does not fail.
func TestInstancesProfileDeniedIsGapNotFatal(t *testing.T) {
	prof := profilesFor()
	prof.errs["prof-1"] = apiErr("AccessDenied")
	s := runInstances(t, &stubEC2Inst{instances: oneInstance()}, prof, "us-east-1")
	if _, ok := nodeNamed(s, model.NodeCompute, "arn:aws:ec2:us-east-1:"+acctID+":instance/i-1"); !ok {
		t.Error("instance node must still be emitted when its profile read is denied")
	}
	if len(s.Links) != 0 {
		t.Errorf("links = %+v, want none (role unresolved)", s.Links)
	}
	if c := instCompleteness(s, "ec2.instanceRoles", collect.Global); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("ec2.instanceRoles = %+v, want partial denied", c)
	}
}

// TestInstancesBudgetExhaustion proves the shared budget bounds the fan-out: with
// budget for one region's read, the next region and role resolution are Partial
// "budget exhausted", none silently skipped.
func TestInstancesBudgetExhaustion(t *testing.T) {
	ec2api := &stubEC2Inst{instances: oneInstance()}
	prof := profilesFor()
	c := newInstanceCollector(acctID, ec2api, prof, []string{"us-east-1", "eu-west-1"})
	c.budget = collect.NewBudget(1)
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ec2api.calls != 1 {
		t.Errorf("DescribeInstances calls = %d, want 1", ec2api.calls)
	}
	if prof.calls != 0 {
		t.Errorf("GetInstanceProfile calls = %d, want 0 (budget gone)", prof.calls)
	}
	if got := instCompleteness(s, "ec2.instances", "eu-west-1"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("ec2.instances@eu-west-1 = %+v, want partial budget-exhausted", got)
	}
	if got := instCompleteness(s, "ec2.instanceRoles", collect.Global); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("ec2.instanceRoles = %+v, want partial budget-exhausted", got)
	}
}

// TestInstancesPaginates proves NextToken pages are followed and counted.
func TestInstancesPaginates(t *testing.T) {
	i2 := oneInstance()
	i2[0].InstanceId = ptr("i-2")
	i2[0].IamInstanceProfile = nil
	ec2api := &stubEC2Inst{pages: [][]ec2types.Instance{oneInstance(), i2}}
	s := runInstances(t, ec2api, profilesFor(), "us-east-1")
	if n := nodesByType(s)[model.NodeCompute]; n != 2 {
		t.Errorf("compute nodes = %d, want 2", n)
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("ec2.instances = %+v, want complete with 2", c)
	}
}

// TestInstancesUnexpectedErrorSurfaces proves an unexpected error is Errored and
// returned, while the other regions still collect.
func TestInstancesUnexpectedErrorSurfaces(t *testing.T) {
	ec2api := &stubEC2Inst{instances: oneInstance(), errs: map[string]error{"us-east-1": apiErr("InternalError")}}
	var s collect.Scan
	err := newInstanceCollector(acctID, ec2api, profilesFor(), []string{"us-east-1", "eu-west-1"}).Collect(context.Background(), &s)
	if err == nil {
		t.Fatal("unexpected error must surface")
	}
	if c := instCompleteness(s, "ec2.instances", "us-east-1"); c.Status != collect.Errored {
		t.Errorf("ec2.instances@us-east-1 = %+v, want error", c)
	}
	if c := instCompleteness(s, "ec2.instances", "eu-west-1"); c.Status != collect.Complete {
		t.Errorf("other regions must still collect: %+v", c)
	}
}

func TestIsRegionNotEnabled(t *testing.T) {
	for _, code := range []string{"OptInRequired", "AuthFailure", "UnauthorizedOperation.RegionDisabled"} {
		if !isRegionNotEnabled(apiErr(code)) {
			t.Errorf("%s should be region-not-enabled", code)
		}
	}
	if isRegionNotEnabled(apiErr("AccessDenied")) {
		t.Error("AccessDenied must not be region-not-enabled")
	}
}

func TestIsTransport(t *testing.T) {
	if !isTransport(errors.New("dial tcp: connection refused")) {
		t.Error("a non-API error should be transport")
	}
	// A dial timeout wraps context.DeadlineExceeded but is a transport failure, not
	// a scan cancellation (the caller separates those via ctx.Err()). This is the
	// case the live run caught: it must be transport, or a fast-fail dial timeout
	// would wrongly sink the whole scan.
	if !isTransport(fmt.Errorf("dial tcp 99.82.136.87:443: %w", context.DeadlineExceeded)) {
		t.Error("a dial timeout wrapping DeadlineExceeded should be transport")
	}
	if isTransport(apiErr("OptInRequired")) {
		t.Error("a modeled API error must not be transport")
	}
	if isTransport(nil) {
		t.Error("nil is not transport")
	}
}

func TestLastSegment(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::1:instance-profile/prof-1":           "prof-1",
		"arn:aws:iam::1:instance-profile/team/path/prof-2": "prof-2",
		"bare": "bare",
	}
	for in, want := range cases {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInstancesEvidenceRedactsToken proves the evidence body is scrubbed.
func TestInstancesEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Q", 16)
	inst := oneInstance()
	inst[0].Tags = append(inst[0].Tags, ec2types.Tag{Key: ptr("note"), Value: ptr(token)})
	s := runInstances(t, &stubEC2Inst{instances: inst}, profilesFor(), "us-east-1")
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token-like value: %s", e.Operation)
		}
	}
}

// TestDefaultRegionsFullCommercialSet pins Option 1: the full commercial set (all
// 34 aws-partition Regions, default plus opt-in), deduplicated and versioned.
func TestDefaultRegionsFullCommercialSet(t *testing.T) {
	if len(defaultRegions) != 34 {
		t.Errorf("default regions = %d, want 34 (full commercial set)", len(defaultRegions))
	}
	seen := map[string]bool{}
	for _, r := range defaultRegions {
		if seen[r] {
			t.Errorf("duplicate region %s", r)
		}
		seen[r] = true
	}
	// Both an enabled-by-default and an opt-in region must be present (Option 1).
	if !seen["us-east-1"] || !seen["ap-east-1"] {
		t.Error("full commercial set must include both default (us-east-1) and opt-in (ap-east-1) regions")
	}
	if regionSetVersion == "" {
		t.Error("region set must be versioned")
	}
}
