package collect

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	smithy "github.com/aws/smithy-go"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// securityCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const securityCollectorID = "collector:aws.securityservices"

// The completeness service names this collector records, per region.
const (
	svcGuardDuty      = "securityservices.guardduty"
	svcSecurityHub    = "securityservices.securityhub"
	svcAccessAnalyzer = "securityservices.accessAnalyzer"
	svcInspector2     = "securityservices.inspector2"
	svcMacie          = "securityservices.macie2"
)

// securityAPI is the read-only surface across the five detective-control services.
// Each method takes the target region as a string (the real implementation applies
// it as a per-call option); every operation is a read at the List or Read level
// (each service's authorization reference, verified 2026-09-20) and none modifies
// anything or returns a secret.
type securityAPI interface {
	ListDetectors(ctx context.Context, region string, in *guardduty.ListDetectorsInput) (*guardduty.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, region string, in *guardduty.GetDetectorInput) (*guardduty.GetDetectorOutput, error)
	DescribeHub(ctx context.Context, region string, in *securityhub.DescribeHubInput) (*securityhub.DescribeHubOutput, error)
	GetEnabledStandards(ctx context.Context, region string, in *securityhub.GetEnabledStandardsInput) (*securityhub.GetEnabledStandardsOutput, error)
	ListAnalyzers(ctx context.Context, region string, in *accessanalyzer.ListAnalyzersInput) (*accessanalyzer.ListAnalyzersOutput, error)
	BatchGetAccountStatus(ctx context.Context, region string, in *inspector2.BatchGetAccountStatusInput) (*inspector2.BatchGetAccountStatusOutput, error)
	GetMacieSession(ctx context.Context, region string, in *macie2.GetMacieSessionInput) (*macie2.GetMacieSessionOutput, error)
}

// awsSecurityAPI is the real securityAPI backed by the five service clients.
type awsSecurityAPI struct {
	gd *guardduty.Client
	sh *securityhub.Client
	aa *accessanalyzer.Client
	in *inspector2.Client
	ma *macie2.Client
}

func (a *awsSecurityAPI) ListDetectors(ctx context.Context, region string, in *guardduty.ListDetectorsInput) (*guardduty.ListDetectorsOutput, error) {
	return a.gd.ListDetectors(ctx, in, func(o *guardduty.Options) { o.Region = region })
}
func (a *awsSecurityAPI) GetDetector(ctx context.Context, region string, in *guardduty.GetDetectorInput) (*guardduty.GetDetectorOutput, error) {
	return a.gd.GetDetector(ctx, in, func(o *guardduty.Options) { o.Region = region })
}
func (a *awsSecurityAPI) DescribeHub(ctx context.Context, region string, in *securityhub.DescribeHubInput) (*securityhub.DescribeHubOutput, error) {
	return a.sh.DescribeHub(ctx, in, func(o *securityhub.Options) { o.Region = region })
}
func (a *awsSecurityAPI) GetEnabledStandards(ctx context.Context, region string, in *securityhub.GetEnabledStandardsInput) (*securityhub.GetEnabledStandardsOutput, error) {
	return a.sh.GetEnabledStandards(ctx, in, func(o *securityhub.Options) { o.Region = region })
}
func (a *awsSecurityAPI) ListAnalyzers(ctx context.Context, region string, in *accessanalyzer.ListAnalyzersInput) (*accessanalyzer.ListAnalyzersOutput, error) {
	return a.aa.ListAnalyzers(ctx, in, func(o *accessanalyzer.Options) { o.Region = region })
}
func (a *awsSecurityAPI) BatchGetAccountStatus(ctx context.Context, region string, in *inspector2.BatchGetAccountStatusInput) (*inspector2.BatchGetAccountStatusOutput, error) {
	return a.in.BatchGetAccountStatus(ctx, in, func(o *inspector2.Options) { o.Region = region })
}
func (a *awsSecurityAPI) GetMacieSession(ctx context.Context, region string, in *macie2.GetMacieSessionInput) (*macie2.GetMacieSessionOutput, error) {
	return a.ma.GetMacieSession(ctx, in, func(o *macie2.Options) { o.Region = region })
}

// SecurityServicesCollector reads the enablement and health posture of the account's
// detective-control services in each declared region (ADR-0019 §1): GuardDuty,
// Security Hub, IAM Access Analyzer, Inspector, and Macie. It answers the bounded
// question "is each control turned on and healthy," not the open-ended one of
// ingesting each service's finding datasets.
//
// Per ADR-0019 §3 it emits nodes and attributes only, no edges, and records raw
// enablement facts (enabled, status, features) without judging whether a disabled
// service is a finding: that is the rule engine's job. A service being not enabled
// is recorded as an explicit enabled=false fact, never inferred from absence and
// never a Denied gap. Two services signal "not enabled" through an exception
// (Security Hub InvalidAccessException, Macie ResourceNotFoundException); the
// collector maps only those specific, unambiguous types to enabled=false. An
// ambiguous denial (a plain AccessDenied, which could equally be a missing
// permission) is left as an honest gap rather than asserting a disabled state,
// because a wrongly asserted disabled control would be a fabricated security fact.
type SecurityServicesCollector struct {
	account string
	api     securityAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewSecurityServicesCollector builds the collector with read-only clients for the
// five services from the adapter's resolved config (ADR-0018 §3).
func NewSecurityServicesCollector(account string, cfg awssdk.Config, budget *collect.Budget) *SecurityServicesCollector {
	return &SecurityServicesCollector{
		account: account,
		api: &awsSecurityAPI{
			gd: guardduty.NewFromConfig(cfg), sh: securityhub.NewFromConfig(cfg),
			aa: accessanalyzer.NewFromConfig(cfg), in: inspector2.NewFromConfig(cfg),
			ma: macie2.NewFromConfig(cfg),
		},
		budget:  budget,
		regions: defaultRegions,
	}
}

// newSecurityServicesCollector is the injectable constructor tests use.
func newSecurityServicesCollector(account string, api securityAPI, regions []string) *SecurityServicesCollector {
	return &SecurityServicesCollector{account: account, api: api, regions: regions}
}

func (c *SecurityServicesCollector) ID() string               { return securityCollectorID }
func (c *SecurityServicesCollector) Provider() model.Provider { return model.AWS }

// securityRequirements are the read-only permissions this collector needs (each
// service's authorization reference, verified 2026-09-20). Registered at init so the
// templates reconcile against real code (ADR-0016).
func securityRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: securityCollectorID}
	}
	return []permissions.Requirement{
		req("guardduty:ListDetectors"),
		req("guardduty:GetDetector"),
		req("securityhub:DescribeHub"),
		req("securityhub:GetEnabledStandards"),
		req("access-analyzer:ListAnalyzers"),
		req("inspector2:BatchGetAccountStatus"),
		req("macie2:GetMacieSession"),
	}
}

func init() {
	for _, r := range securityRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *SecurityServicesCollector) Requirements() []permissions.Requirement {
	return securityRequirements()
}

// securityServiceNames lists every completeness service, in order, for marking the
// services not reached once the shared budget is exhausted.
func securityServiceNames() []string {
	return []string{svcGuardDuty, svcSecurityHub, svcAccessAnalyzer, svcInspector2, svcMacie}
}

// Collect reads each service's posture in every declared region, sequentially. A
// denied, throttled, not-enabled (region), or unreachable read is a represented gap
// and the other services and regions still run; budget exhaustion marks every
// (service, region) not yet reached Partial "budget exhausted". An unexpected error
// is Errored, the rest still run, and the errors surface.
func (c *SecurityServicesCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			for _, s := range securityServiceNames() {
				_ = sink.Complete(c.budgetGap(s, region))
			}
			continue
		}
		budgetOut, err := c.collectRegion(ctx, sink, region)
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

// securityStep is one service's posture read: its completeness name and the function
// that performs it, returning whether the budget ran out and any surfaced error.
type securityStep struct {
	name string
	run  func(ctx context.Context, sink collect.Sink, region string) (bool, error)
}

func (c *SecurityServicesCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	steps := []securityStep{
		{svcGuardDuty, c.collectGuardDuty},
		{svcSecurityHub, c.collectSecurityHub},
		{svcAccessAnalyzer, c.collectAccessAnalyzer},
		{svcInspector2, c.collectInspector2},
		{svcMacie, c.collectMacie},
	}
	var errs []error
	for i, step := range steps {
		bo, err := step.run(ctx, sink, region)
		errs = appendErr(errs, err)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if bo {
			for _, later := range steps[i+1:] {
				_ = sink.Complete(c.budgetGap(later.name, region))
			}
			return true, errors.Join(errs...)
		}
	}
	return false, errors.Join(errs...)
}

func (c *SecurityServicesCollector) collectGuardDuty(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcGuardDuty, region))
		return true, nil
	}
	out, err := c.api.ListDetectors(ctx, region, &guardduty.ListDetectorsInput{})
	if err != nil {
		return c.readError(ctx, sink, svcGuardDuty, region, err)
	}
	_ = sink.Evidence(c.evidence("guardduty", "ListDetectors", region, out))
	if len(out.DetectorIds) == 0 {
		c.emitEnablement(sink, region, "guardduty", c.synthID("guardduty", region), false, nil)
		_ = sink.Complete(c.complete(svcGuardDuty, region, 0))
		return false, nil
	}
	count := 0
	for _, id := range out.DetectorIds {
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcGuardDuty, region))
			return true, nil
		}
		det, err := c.api.GetDetector(ctx, region, &guardduty.GetDetectorInput{DetectorId: &id})
		attrs := map[string]string{"detector_id": id}
		enabled := true
		if err == nil {
			_ = sink.Evidence(c.evidence("guardduty", "GetDetector", region, det))
			attrs["status"] = string(det.Status)
			attrs["finding_publishing_frequency"] = string(det.FindingPublishingFrequency)
			enabled = det.Status == "ENABLED"
		}
		arn := "arn:aws:guardduty:" + region + ":" + c.account + ":detector/" + id
		c.emitEnablement(sink, region, "guardduty", arn, enabled, attrs)
		count++
	}
	_ = sink.Complete(c.complete(svcGuardDuty, region, count))
	return false, nil
}

func (c *SecurityServicesCollector) collectSecurityHub(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcSecurityHub, region))
		return true, nil
	}
	hub, err := c.api.DescribeHub(ctx, region, &securityhub.DescribeHubInput{})
	if err != nil {
		// InvalidAccessException specifically means Security Hub is not enabled in
		// this region: a recorded enabled=false fact, not a gap. Any other error
		// (including a plain AccessDenied, which is a real permission issue) is a gap.
		var notEnabled *shtypes.InvalidAccessException
		if errors.As(err, &notEnabled) {
			c.emitEnablement(sink, region, "securityhub", c.synthID("securityhub", region), false, nil)
			_ = sink.Complete(c.complete(svcSecurityHub, region, 0))
			return false, nil
		}
		return c.readError(ctx, sink, svcSecurityHub, region, err)
	}
	_ = sink.Evidence(c.evidence("securityhub", "DescribeHub", region, hub))
	attrs := map[string]string{
		"hub_arn":              deref(hub.HubArn),
		"auto_enable_controls": boolAttr(hub.AutoEnableControls),
	}
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcSecurityHub, region))
		return true, nil
	}
	if std, err := c.api.GetEnabledStandards(ctx, region, &securityhub.GetEnabledStandardsInput{}); err == nil {
		_ = sink.Evidence(c.evidence("securityhub", "GetEnabledStandards", region, std))
		var arns []string
		for _, s := range std.StandardsSubscriptions {
			if a := deref(s.StandardsArn); a != "" {
				arns = append(arns, a)
			}
		}
		sort.Strings(arns)
		attrs["enabled_standards"] = joinSorted(arns)
		attrs["enabled_standards_count"] = strconv.Itoa(len(std.StandardsSubscriptions))
	}
	id := deref(hub.HubArn)
	if id == "" {
		id = c.synthID("securityhub", region)
	}
	c.emitEnablement(sink, region, "securityhub", id, true, attrs)
	_ = sink.Complete(c.complete(svcSecurityHub, region, 1))
	return false, nil
}

func (c *SecurityServicesCollector) collectAccessAnalyzer(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcAccessAnalyzer, region))
		return true, nil
	}
	out, err := c.api.ListAnalyzers(ctx, region, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return c.readError(ctx, sink, svcAccessAnalyzer, region, err)
	}
	_ = sink.Evidence(c.evidence("accessanalyzer", "ListAnalyzers", region, out))
	if len(out.Analyzers) == 0 {
		c.emitEnablement(sink, region, "accessanalyzer", c.synthID("accessanalyzer", region), false, nil)
		_ = sink.Complete(c.complete(svcAccessAnalyzer, region, 0))
		return false, nil
	}
	for _, a := range out.Analyzers {
		attrs := map[string]string{
			"analyzer_name": deref(a.Name),
			"analyzer_type": string(a.Type),
			"status":        string(a.Status),
		}
		c.emitEnablement(sink, region, "accessanalyzer", deref(a.Arn), a.Status == "ACTIVE", attrs)
	}
	_ = sink.Complete(c.complete(svcAccessAnalyzer, region, len(out.Analyzers)))
	return false, nil
}

func (c *SecurityServicesCollector) collectInspector2(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcInspector2, region))
		return true, nil
	}
	out, err := c.api.BatchGetAccountStatus(ctx, region, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		return c.readError(ctx, sink, svcInspector2, region, err)
	}
	_ = sink.Evidence(c.evidence("inspector2", "BatchGetAccountStatus", region, out))
	attrs := map[string]string{}
	enabled := false
	if len(out.Accounts) > 0 {
		acct := out.Accounts[0]
		if acct.State != nil {
			attrs["status"] = string(acct.State.Status)
			enabled = acct.State.Status == "ENABLED"
		}
		if r := acct.ResourceState; r != nil {
			attrs["ec2_scan"] = resourceScanStatus(r.Ec2)
			attrs["ecr_scan"] = resourceScanStatus(r.Ecr)
			attrs["lambda_scan"] = resourceScanStatus(r.Lambda)
			attrs["lambda_code_scan"] = resourceScanStatus(r.LambdaCode)
		}
	}
	c.emitEnablement(sink, region, "inspector2", c.synthID("inspector2", region), enabled, attrs)
	_ = sink.Complete(c.complete(svcInspector2, region, 1))
	return false, nil
}

func (c *SecurityServicesCollector) collectMacie(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcMacie, region))
		return true, nil
	}
	out, err := c.api.GetMacieSession(ctx, region, &macie2.GetMacieSessionInput{})
	if err != nil {
		// ResourceNotFoundException specifically means no Macie session exists (not
		// enabled): a recorded enabled=false fact. A plain AccessDenied is ambiguous
		// (disabled vs missing permission), so it stays an honest gap rather than a
		// fabricated disabled state.
		var notEnabled *macietypes.ResourceNotFoundException
		if errors.As(err, &notEnabled) {
			c.emitEnablement(sink, region, "macie2", c.synthID("macie2", region), false, nil)
			_ = sink.Complete(c.complete(svcMacie, region, 0))
			return false, nil
		}
		return c.readError(ctx, sink, svcMacie, region, err)
	}
	_ = sink.Evidence(c.evidence("macie2", "GetMacieSession", region, out))
	attrs := map[string]string{
		"status":                       string(out.Status),
		"finding_publishing_frequency": string(out.FindingPublishingFrequency),
	}
	c.emitEnablement(sink, region, "macie2", c.synthID("macie2", region), out.Status == "ENABLED", attrs)
	_ = sink.Complete(c.complete(svcMacie, region, 1))
	return false, nil
}

// resourceScanStatus reads an Inspector per-resource scan state's status.
func resourceScanStatus(s *inspector2types.State) string {
	if s == nil {
		return ""
	}
	return string(s.Status)
}

// emitEnablement emits one control node for a service's enablement state in a region.
func (c *SecurityServicesCollector) emitEnablement(sink collect.Sink, region, service, id string, enabled bool, extra map[string]string) {
	if id == "" {
		id = c.synthID(service, region)
	}
	a := map[string]string{
		"security_service": service,
		"enabled":          strconv.FormatBool(enabled),
		"region":           region,
	}
	for k, v := range extra {
		a[k] = v
	}
	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: id, Name: service, Attributes: pruneEmpty(a)})
}

// synthID is the stable id for a service's enablement node when the service exposes
// no ARN of its own (or is not enabled).
func (c *SecurityServicesCollector) synthID(service, region string) string {
	return "aws-security:" + service + ":" + c.account + ":" + region
}

// readError records a service read's error as a completeness gap and returns whether
// the budget ran out (never, here) and the error to surface only when unexpected.
func (c *SecurityServicesCollector) readError(ctx context.Context, sink collect.Sink, service, region string, err error) (bool, error) {
	if cerr := ctx.Err(); cerr != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "cancelled"})
		return false, cerr
	}
	comp := c.completeness(service, region, err)
	_ = sink.Complete(comp)
	if comp.Status == collect.Errored {
		return false, err
	}
	return false, nil
}

func (c *SecurityServicesCollector) completeness(service, region string, err error) collect.Completeness {
	status := collect.Errored
	reason := redact.String(err.Error())
	switch {
	case isRegionNotEnabled(err):
		status = collect.Unsupported
		reason = "region not enabled"
	case isNotSubscribed(err):
		// SubscriptionRequiredException ("the access key id needs a subscription for
		// the service") means the service is not subscribed/available for this account
		// and credential, in every region including the always-on ones (confirmed
		// live). It is genuinely ambiguous between "the account is not enrolled" and
		// "this credential cannot use the service", so it is a represented Unsupported
		// gap, never a fabricated enabled=false node and never a fatal error.
		status = collect.Unsupported
		reason = "subscription required"
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	case isTransport(err):
		status = collect.Partial
		reason = "unreachable"
	}
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Reason: reason}
}

func (c *SecurityServicesCollector) complete(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: collected}
}

func (c *SecurityServicesCollector) budgetGap(service, region string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"}
}

// isNotSubscribed reports the SubscriptionRequiredException a subscription-based
// security service returns when the account and credential are not enrolled in it.
func isNotSubscribed(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == "SubscriptionRequiredException"
}

func (c *SecurityServicesCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *SecurityServicesCollector) evidence(service, operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: service, Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{Collector: securityCollectorID},
	}
}
