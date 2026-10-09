package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	in2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	matypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubSecurity is an offline securityAPI: the same estate in every region, with
// per-"service@region" error injection.
type stubSecurity struct {
	detectors []string
	detector  *guardduty.GetDetectorOutput
	hub       *securityhub.DescribeHubOutput
	standards *securityhub.GetEnabledStandardsOutput
	analyzers []aatypes.AnalyzerSummary
	inspector *inspector2.BatchGetAccountStatusOutput
	macie     *macie2.GetMacieSessionOutput
	errs      map[string]error
	calls     int
	regions   []string
}

func (s *stubSecurity) hit(op, region string) error {
	s.calls++
	s.regions = append(s.regions, region)
	return s.errs[op+"@"+region]
}

func (s *stubSecurity) ListDetectors(_ context.Context, region string, _ *guardduty.ListDetectorsInput) (*guardduty.ListDetectorsOutput, error) {
	if err := s.hit("guardduty", region); err != nil {
		return nil, err
	}
	return &guardduty.ListDetectorsOutput{DetectorIds: s.detectors}, nil
}

func (s *stubSecurity) GetDetector(_ context.Context, region string, _ *guardduty.GetDetectorInput) (*guardduty.GetDetectorOutput, error) {
	if err := s.hit("getDetector", region); err != nil {
		return nil, err
	}
	if s.detector != nil {
		return s.detector, nil
	}
	return &guardduty.GetDetectorOutput{Status: gdtypes.DetectorStatusEnabled}, nil
}

func (s *stubSecurity) DescribeHub(_ context.Context, region string, _ *securityhub.DescribeHubInput) (*securityhub.DescribeHubOutput, error) {
	if err := s.hit("securityhub", region); err != nil {
		return nil, err
	}
	if s.hub != nil {
		return s.hub, nil
	}
	// The real SDK never returns (nil, nil); default to an enabled hub.
	return &securityhub.DescribeHubOutput{HubArn: ptr("arn:aws:securityhub:" + region + ":" + acctID + ":hub/default")}, nil
}

func (s *stubSecurity) GetEnabledStandards(_ context.Context, region string, _ *securityhub.GetEnabledStandardsInput) (*securityhub.GetEnabledStandardsOutput, error) {
	if err := s.hit("getStandards", region); err != nil {
		return nil, err
	}
	if s.standards != nil {
		return s.standards, nil
	}
	return &securityhub.GetEnabledStandardsOutput{}, nil
}

func (s *stubSecurity) ListAnalyzers(_ context.Context, region string, _ *accessanalyzer.ListAnalyzersInput) (*accessanalyzer.ListAnalyzersOutput, error) {
	if err := s.hit("accessanalyzer", region); err != nil {
		return nil, err
	}
	return &accessanalyzer.ListAnalyzersOutput{Analyzers: s.analyzers}, nil
}

func (s *stubSecurity) BatchGetAccountStatus(_ context.Context, region string, _ *inspector2.BatchGetAccountStatusInput) (*inspector2.BatchGetAccountStatusOutput, error) {
	if err := s.hit("inspector2", region); err != nil {
		return nil, err
	}
	if s.inspector != nil {
		return s.inspector, nil
	}
	return &inspector2.BatchGetAccountStatusOutput{}, nil
}

func (s *stubSecurity) GetMacieSession(_ context.Context, region string, _ *macie2.GetMacieSessionInput) (*macie2.GetMacieSessionOutput, error) {
	if err := s.hit("macie2", region); err != nil {
		return nil, err
	}
	if s.macie != nil {
		return s.macie, nil
	}
	// The real SDK never returns (nil, nil); default to an enabled session.
	return &macie2.GetMacieSessionOutput{Status: matypes.MacieStatusEnabled}, nil
}

func runSecurity(t *testing.T, regions []string, api securityAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newSecurityServicesCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// enablementNode finds the control node for a security service in a region.
func enablementNode(s collect.Scan, service string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.Attributes["security_service"] == service {
			return n, true
		}
	}
	return collect.Node{}, false
}

func enabledStub() *stubSecurity {
	return &stubSecurity{
		detectors: []string{"det-1"},
		detector:  &guardduty.GetDetectorOutput{Status: gdtypes.DetectorStatusEnabled, FindingPublishingFrequency: gdtypes.FindingPublishingFrequencySixHours},
		hub:       &securityhub.DescribeHubOutput{HubArn: ptr("arn:aws:securityhub:us-east-1:123456789012:hub/default"), AutoEnableControls: bptr(true)},
		standards: &securityhub.GetEnabledStandardsOutput{StandardsSubscriptions: []shtypes.StandardsSubscription{{StandardsArn: ptr("arn:aws:securityhub:::standard/aws-foundational")}}},
		analyzers: []aatypes.AnalyzerSummary{{Arn: ptr("arn:aws:access-analyzer:us-east-1:123456789012:analyzer/a1"), Name: ptr("a1"), Type: aatypes.TypeAccount, Status: aatypes.AnalyzerStatusActive}},
		inspector: &inspector2.BatchGetAccountStatusOutput{Accounts: []in2types.AccountState{{
			State:         &in2types.State{Status: in2types.StatusEnabled},
			ResourceState: &in2types.ResourceState{Ec2: &in2types.State{Status: in2types.StatusEnabled}, Ecr: &in2types.State{Status: in2types.StatusDisabled}},
		}}},
		macie: &macie2.GetMacieSessionOutput{Status: matypes.MacieStatusEnabled, FindingPublishingFrequency: matypes.FindingPublishingFrequencyFifteenMinutes},
	}
}

// TestSecurityAllEnabled proves each service becomes a control node keyed by its ARN
// (or synthesized id) with enabled=true and its status facts, and each records a
// Complete completeness.
func TestSecurityAllEnabled(t *testing.T) {
	s := runSecurity(t, oneRegion, enabledStub())

	gd, ok := enablementNode(s, "guardduty")
	if !ok || gd.Attributes["enabled"] != "true" || gd.Attributes["status"] != "ENABLED" {
		t.Errorf("guardduty node = %+v", gd.Attributes)
	}
	if gd.NativeID != "arn:aws:guardduty:us-east-1:"+acctID+":detector/det-1" {
		t.Errorf("guardduty keyed by %q, want detector ARN", gd.NativeID)
	}
	sh, _ := enablementNode(s, "securityhub")
	if sh.Attributes["enabled"] != "true" || sh.NativeID != "arn:aws:securityhub:us-east-1:123456789012:hub/default" {
		t.Errorf("securityhub node = %+v id=%q", sh.Attributes, sh.NativeID)
	}
	if !strings.Contains(sh.Attributes["enabled_standards"], "aws-foundational") {
		t.Errorf("securityhub standards = %q", sh.Attributes["enabled_standards"])
	}
	aa, _ := enablementNode(s, "accessanalyzer")
	if aa.Attributes["enabled"] != "true" || aa.Attributes["analyzer_type"] != "ACCOUNT" || aa.NativeID != "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/a1" {
		t.Errorf("accessanalyzer node = %+v id=%q", aa.Attributes, aa.NativeID)
	}
	in, _ := enablementNode(s, "inspector2")
	if in.Attributes["enabled"] != "true" || in.Attributes["ec2_scan"] != "ENABLED" || in.Attributes["ecr_scan"] != "DISABLED" {
		t.Errorf("inspector2 node = %+v", in.Attributes)
	}
	ma, _ := enablementNode(s, "macie2")
	if ma.Attributes["enabled"] != "true" || ma.Attributes["status"] != "ENABLED" {
		t.Errorf("macie2 node = %+v", ma.Attributes)
	}
	for _, svc := range securityServiceNames() {
		if statusOf(s, svc) != collect.Complete {
			t.Errorf("%s = %s, want complete", svc, statusOf(s, svc))
		}
	}
}

// TestSecurityDisabledIsExplicitFact proves that when a service reports nothing
// (no detectors, no analyzers), the collector emits an explicit enabled=false node
// (never inferred from absence) and records Complete, not a gap.
func TestSecurityDisabledIsExplicitFact(t *testing.T) {
	api := &stubSecurity{} // no detectors, no analyzers, nil hub/macie handled by errors below
	api.errs = map[string]error{
		"securityhub@us-east-1": &shtypes.InvalidAccessException{Message: ptr("not subscribed to Security Hub")},
		"macie2@us-east-1":      &matypes.ResourceNotFoundException{Message: ptr("Macie is not enabled")},
	}
	s := runSecurity(t, oneRegion, api)
	for _, svc := range []string{"guardduty", "accessanalyzer", "securityhub", "macie2"} {
		n, ok := enablementNode(s, svc)
		if !ok {
			t.Errorf("%s: expected an explicit enablement node", svc)
			continue
		}
		if n.Attributes["enabled"] != "false" {
			t.Errorf("%s enabled = %q, want false", svc, n.Attributes["enabled"])
		}
	}
	for _, svc := range []string{svcGuardDuty, svcAccessAnalyzer, svcSecurityHub, svcMacie} {
		if statusOf(s, svc) != collect.Complete {
			t.Errorf("%s = %s, want complete (not enabled is a fact, not a gap)", svc, statusOf(s, svc))
		}
	}
}

// TestSecurityMacieAmbiguousDenialIsGapNotDisabled proves the critical safety rule:
// a plain AccessDenied from Macie (which could be a missing permission, not a
// disabled service) is a Denied gap, and the collector does NOT fabricate an
// enabled=false node.
func TestSecurityMacieAmbiguousDenialIsGapNotDisabled(t *testing.T) {
	api := &stubSecurity{}
	api.errs = map[string]error{"macie2@us-east-1": apiErr("AccessDeniedException")}
	s := runSecurity(t, oneRegion, api)
	if _, ok := enablementNode(s, "macie2"); ok {
		t.Error("must NOT assert a macie enablement state on an ambiguous AccessDenied")
	}
	if statusOf(s, svcMacie) != collect.Denied {
		t.Errorf("%s = %s, want denied (ambiguous denial is a gap, never a fabricated disabled)", svcMacie, statusOf(s, svcMacie))
	}
}

// TestSecurityHubAccessDeniedIsGapNotDisabled proves that a plain AccessDenied from
// Security Hub (as opposed to the specific InvalidAccessException) is a Denied gap,
// not a fabricated disabled state.
func TestSecurityHubAccessDeniedIsGapNotDisabled(t *testing.T) {
	api := &stubSecurity{}
	api.errs = map[string]error{"securityhub@us-east-1": apiErr("AccessDeniedException")}
	s := runSecurity(t, oneRegion, api)
	if _, ok := enablementNode(s, "securityhub"); ok {
		t.Error("must NOT assert a securityhub enablement state on a plain AccessDenied")
	}
	if statusOf(s, svcSecurityHub) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcSecurityHub, statusOf(s, svcSecurityHub))
	}
}

// TestSecuritySubscriptionRequiredIsUnsupportedNotFabricated proves that
// SubscriptionRequiredException (the account/credential is not enrolled in the
// service, seen live even in always-on regions) is a represented Unsupported
// "subscription required" gap, never a fatal error and never a fabricated
// enabled=false node.
func TestSecuritySubscriptionRequiredIsUnsupportedNotFabricated(t *testing.T) {
	api := &stubSecurity{errs: map[string]error{"guardduty@us-east-1": apiErr("SubscriptionRequiredException")}}
	s := runSecurity(t, oneRegion, api)
	c := completenessOf(s, svcGuardDuty)
	if c.Status != collect.Unsupported || c.Reason != "subscription required" {
		t.Errorf("%s = %+v, want unsupported subscription-required", svcGuardDuty, c)
	}
	if _, ok := enablementNode(s, "guardduty"); ok {
		t.Error("must NOT emit an enablement node on a subscription-required read")
	}
}

// TestSecurityRegionNotEnabled proves an opt-in region the account has not enabled is
// Unsupported "region not enabled".
func TestSecurityRegionNotEnabled(t *testing.T) {
	api := &stubSecurity{errs: map[string]error{"guardduty@us-east-1": apiErr("UnrecognizedClientException")}}
	s := runSecurity(t, oneRegion, api)
	if c := completenessOf(s, svcGuardDuty); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("%s = %+v, want unsupported region-not-enabled", svcGuardDuty, c)
	}
}

// TestSecurityOneServiceDeniedOthersRun proves a denial on one service does not stop
// the others.
func TestSecurityOneServiceDeniedOthersRun(t *testing.T) {
	api := enabledStub()
	api.errs = map[string]error{"guardduty@us-east-1": apiErr("AccessDenied")}
	s := runSecurity(t, oneRegion, api)
	if statusOf(s, svcGuardDuty) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcGuardDuty, statusOf(s, svcGuardDuty))
	}
	if statusOf(s, svcInspector2) != collect.Complete {
		t.Error("inspector2 should still collect when guardduty is denied")
	}
}

// TestSecurityFanOutAllRegions proves every region is visited with five records each.
func TestSecurityFanOutAllRegions(t *testing.T) {
	regions := []string{"us-east-1", "eu-west-1"}
	api := &stubSecurity{errs: map[string]error{
		"securityhub@us-east-1": &shtypes.InvalidAccessException{}, "securityhub@eu-west-1": &shtypes.InvalidAccessException{},
		"macie2@us-east-1": &matypes.ResourceNotFoundException{}, "macie2@eu-west-1": &matypes.ResourceNotFoundException{},
	}}
	s := runSecurity(t, regions, api)
	if len(s.Completeness) != 10 { // 5 services x 2 regions
		t.Errorf("completeness records = %d, want 10", len(s.Completeness))
	}
}

// TestSecurityBudgetExhaustion proves the shared budget bounds the sweep and marks
// the services not reached Partial "budget exhausted".
func TestSecurityBudgetExhaustion(t *testing.T) {
	api := enabledStub()
	c := newSecurityServicesCollector(acctID, api, oneRegion)
	c.budget = collect.NewBudget(1) // guardduty ListDetectors only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, svc := range []string{svcSecurityHub, svcAccessAnalyzer, svcInspector2, svcMacie} {
		if got := completenessOf(s, svc); got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial budget-exhausted", svc, got)
		}
	}
}

// TestSecurityEvidenceRedactsToken proves the evidence body is scrubbed.
func TestSecurityEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Z", 16)
	api := enabledStub()
	api.hub.HubArn = ptr(token)
	s := runSecurity(t, oneRegion, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
