package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// loggingCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const loggingCollectorID = "collector:aws.logging"

// The API versions recorded as evidence provenance.
const (
	cloudTrailAPIVersion = "2013-11-01"
	configAPIVersion     = "2014-11-12"
)

// The completeness service names this collector records, per region.
const (
	svcTrails           = "cloudtrail.trails"
	svcTrailDetails     = "cloudtrail.trailDetails"
	svcConfigRecorders  = "config.recorders"
	svcDeliveryChannels = "config.deliveryChannels"
)

// loggingAPI is the read-only CloudTrail and Config surface the collector uses,
// answering "is audit logging on and healthy": trails (with their logging status and
// event scope) and Config recorders and delivery channels. Every operation is a
// read at the List or Read level (CloudTrail and Config service authorization
// references, verified 2026-09-20); none modifies anything or returns a secret.
type loggingAPI interface {
	DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
	GetEventSelectors(context.Context, *cloudtrail.GetEventSelectorsInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error)
	DescribeConfigurationRecorders(context.Context, *configservice.DescribeConfigurationRecordersInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(context.Context, *configservice.DescribeConfigurationRecorderStatusInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
	DescribeDeliveryChannels(context.Context, *configservice.DescribeDeliveryChannelsInput, ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error)
}

// awsLoggingAPI is the real loggingAPI backed by the CloudTrail and Config clients.
type awsLoggingAPI struct {
	ct *cloudtrail.Client
	cf *configservice.Client
}

func (a *awsLoggingAPI) DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, o ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return a.ct.DescribeTrails(ctx, in, o...)
}
func (a *awsLoggingAPI) GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, o ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return a.ct.GetTrailStatus(ctx, in, o...)
}
func (a *awsLoggingAPI) GetEventSelectors(ctx context.Context, in *cloudtrail.GetEventSelectorsInput, o ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	return a.ct.GetEventSelectors(ctx, in, o...)
}
func (a *awsLoggingAPI) DescribeConfigurationRecorders(ctx context.Context, in *configservice.DescribeConfigurationRecordersInput, o ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	return a.cf.DescribeConfigurationRecorders(ctx, in, o...)
}
func (a *awsLoggingAPI) DescribeConfigurationRecorderStatus(ctx context.Context, in *configservice.DescribeConfigurationRecorderStatusInput, o ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	return a.cf.DescribeConfigurationRecorderStatus(ctx, in, o...)
}
func (a *awsLoggingAPI) DescribeDeliveryChannels(ctx context.Context, in *configservice.DescribeDeliveryChannelsInput, o ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error) {
	return a.cf.DescribeDeliveryChannels(ctx, in, o...)
}

// LoggingCollector reads the account's audit-logging posture in each declared
// region (ADR-0019 §1): CloudTrail trails (with their logging status and event
// scope) and AWS Config configuration recorders and delivery channels. It is a
// detective-control collector: it records whether logging is configured and running
// as provider facts, and never judges whether a gap is a finding (that is the rule
// engine's job).
//
// Per ADR-0019 §3 it emits nodes and attributes only, no edges. A trail is keyed by
// its ARN and records its kms_key_id and s3_bucket_name as id facts, which resolve
// directly onto the KMS and S3 nodes, so an encrypted trail delivering to a specific
// bucket is one connected, traceable fact. A multi-region trail is recorded once in
// its home region (DescribeTrails is called with IncludeShadowTrails=false) rather
// than duplicated across every region.
type LoggingCollector struct {
	account string
	api     loggingAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewLoggingCollector builds the collector with read-only CloudTrail and Config
// clients from the adapter's resolved config (ADR-0018 §3), over the region set.
func NewLoggingCollector(account string, cfg awssdk.Config, budget *collect.Budget) *LoggingCollector {
	return &LoggingCollector{
		account: account,
		api:     &awsLoggingAPI{ct: cloudtrail.NewFromConfig(cfg), cf: configservice.NewFromConfig(cfg)},
		budget:  budget,
		regions: defaultRegions,
	}
}

// newLoggingCollector is the injectable constructor tests use with a stub API and an
// explicit region list. It has no budget (unlimited).
func newLoggingCollector(account string, api loggingAPI, regions []string) *LoggingCollector {
	return &LoggingCollector{account: account, api: api, regions: regions}
}

func (c *LoggingCollector) ID() string               { return loggingCollectorID }
func (c *LoggingCollector) Provider() model.Provider { return model.AWS }

// loggingRequirements are the read-only permissions this collector needs. Each maps
// to an action of the same name (CloudTrail and Config service authorization
// references, verified 2026-09-20). Registered at init so the templates reconcile
// against real code (ADR-0016).
func loggingRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: loggingCollectorID}
	}
	return []permissions.Requirement{
		req("cloudtrail:DescribeTrails"),
		req("cloudtrail:GetTrailStatus"),
		req("cloudtrail:GetEventSelectors"),
		req("config:DescribeConfigurationRecorders"),
		req("config:DescribeConfigurationRecorderStatus"),
		req("config:DescribeDeliveryChannels"),
	}
}

func init() {
	for _, r := range loggingRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *LoggingCollector) Requirements() []permissions.Requirement { return loggingRequirements() }

// loggingServices lists every completeness service, in order, for marking the
// resources not reached once the shared budget is exhausted.
func loggingServices() []string {
	return []string{svcTrails, svcTrailDetails, svcConfigRecorders, svcDeliveryChannels}
}

// Collect reads CloudTrail and Config posture in every declared region,
// sequentially (ADR-0019 §1), recording one completeness record per (service,
// region). A denied, throttled, not-enabled, or unreachable read is a represented
// gap and the other services and regions still run; budget exhaustion marks every
// (service, region) not yet reached Partial "budget exhausted". An unexpected error
// is Errored, the rest still run, and the errors surface.
func (c *LoggingCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			for _, s := range loggingServices() {
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

func (c *LoggingCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var errs []error

	bo, err := c.collectTrails(ctx, sink, region)
	errs = appendErr(errs, err)
	if bo {
		c.markBudget(sink, region, svcConfigRecorders, svcDeliveryChannels)
		return true, errors.Join(errs...)
	}

	bo, err = c.collectConfig(ctx, sink, region)
	errs = appendErr(errs, err)
	return bo, errors.Join(errs...)
}

// collectTrails lists the trails created in this region (IncludeShadowTrails=false,
// so a multi-region trail is recorded once in its home region), then details each
// with its logging status and event scope. Records svcTrails and svcTrailDetails.
func (c *LoggingCollector) collectTrails(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcTrails, region))
		_ = sink.Complete(c.budgetGap(svcTrailDetails, region))
		return true, nil
	}
	out, err := c.api.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: awssdk.Bool(false)}, ctInRegion(region))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			_ = sink.Complete(c.cancelledGap(svcTrails, region, 0))
			_ = sink.Complete(c.cancelledGap(svcTrailDetails, region, 0))
			return false, cerr
		}
		listErr := c.listError(sink, svcTrails, region, 0, err)
		_ = sink.Complete(c.completeCount(svcTrailDetails, region, 0))
		return false, listErr
	}
	_ = sink.Evidence(c.evidenceCT("DescribeTrails", region, out))
	_ = sink.Complete(c.completeCount(svcTrails, region, len(out.TrailList)))

	detailed := 0
	reason := ""
	for _, t := range out.TrailList {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcTrailDetails, region, detailed))
			return false, err
		}
		gap := c.detailTrail(ctx, sink, region, t)
		if gap == "budget exhausted" {
			_ = sink.Complete(c.budgetGap(svcTrailDetails, region))
			return true, nil
		}
		if gap != "" {
			reason = gap
			continue
		}
		detailed++
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: svcTrailDetails, Region: region, Scope: c.scope(), Status: status, Collected: detailed, Reason: reason})
	return false, nil
}

// detailTrail gathers one trail's status and event scope and emits the node (keyed
// by ARN). Returns "" on success, "budget exhausted", or a gap reason. The node is
// emitted even on a partial gather.
func (c *LoggingCollector) detailTrail(ctx context.Context, sink collect.Sink, region string, t cttypes.Trail) string {
	arn := deref(t.TrailARN)
	if arn == "" {
		return ""
	}
	a := map[string]string{
		"cloudtrail_type":               "trail",
		"home_region":                   deref(t.HomeRegion),
		"s3_bucket_name":                deref(t.S3BucketName),
		"kms_key_id":                    deref(t.KmsKeyId),
		"cloudwatch_logs_group":         deref(t.CloudWatchLogsLogGroupArn),
		"is_multi_region":               boolAttr(t.IsMultiRegionTrail),
		"is_organization_trail":         boolAttr(t.IsOrganizationTrail),
		"log_file_validation_enabled":   boolAttr(t.LogFileValidationEnabled),
		"include_global_service_events": boolAttr(t.IncludeGlobalServiceEvents),
		"region":                        region,
	}
	gap := ""

	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if st, err := c.api.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}, ctInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidenceCT("GetTrailStatus", region, st))
		a["is_logging"] = boolAttr(st.IsLogging)
	} else {
		gap = c.callGap(err)
	}

	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if es, err := c.api.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: t.TrailARN}, ctInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidenceCT("GetEventSelectors", region, es))
		mapEventSelectors(a, es)
	} else {
		gap = c.callGap(err)
	}

	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: arn, Name: deref(t.Name), Attributes: pruneEmpty(a)})
	return gap
}

// mapEventSelectors records the trail's event scope as facts: the management-event
// read/write type, and whether data events and advanced selectors are configured.
func mapEventSelectors(a map[string]string, es *cloudtrail.GetEventSelectorsOutput) {
	dataEvents := false
	for _, s := range es.EventSelectors {
		if a["management_read_write_type"] == "" && string(s.ReadWriteType) != "" {
			a["management_read_write_type"] = string(s.ReadWriteType)
		}
		if len(s.DataResources) > 0 {
			dataEvents = true
		}
	}
	if len(es.EventSelectors) > 0 {
		a["data_events"] = strconv.FormatBool(dataEvents)
	}
	if n := len(es.AdvancedEventSelectors); n > 0 {
		a["advanced_event_selectors"] = strconv.Itoa(n)
	}
}

// collectConfig reads the region's Config recorders (with recording status) and
// delivery channels, emitting a control node per recorder with the delivery-channel
// facts folded in. Records svcConfigRecorders and svcDeliveryChannels.
func (c *LoggingCollector) collectConfig(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	// Recorders.
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcConfigRecorders, region))
		_ = sink.Complete(c.budgetGap(svcDeliveryChannels, region))
		return true, nil
	}
	recOut, err := c.api.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{}, cfInRegion(region))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			_ = sink.Complete(c.cancelledGap(svcConfigRecorders, region, 0))
			_ = sink.Complete(c.cancelledGap(svcDeliveryChannels, region, 0))
			return false, cerr
		}
		recErr := c.listError(sink, svcConfigRecorders, region, 0, err)
		// Delivery channels are independent; still attempt them below.
		bo, dcErr := c.collectDeliveryChannels(ctx, sink, region, nil)
		return bo, errors.Join(recErr, dcErr)
	}
	_ = sink.Evidence(c.evidenceCF("DescribeConfigurationRecorders", region, recOut))

	// Recording status, merged by recorder name.
	recording := map[string]cfgtypes.ConfigurationRecorderStatus{}
	reason := ""
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcConfigRecorders, region))
		_ = sink.Complete(c.budgetGap(svcDeliveryChannels, region))
		return true, nil
	}
	if stOut, err := c.api.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{}, cfInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidenceCF("DescribeConfigurationRecorderStatus", region, stOut))
		for _, s := range stOut.ConfigurationRecordersStatus {
			recording[deref(s.Name)] = s
		}
	} else {
		reason = c.callGap(err)
	}

	// Delivery channels, folded onto the recorder nodes.
	channels, bo, dcErr := c.deliveryChannels(ctx, sink, region)
	if bo {
		// Budget ran out before delivery channels: recorders still emit without
		// delivery facts.
		c.emitRecorders(sink, region, recOut.ConfigurationRecorders, recording, nil)
		status := collect.Complete
		if reason != "" {
			status = collect.Partial
		}
		_ = sink.Complete(collect.Completeness{Service: svcConfigRecorders, Region: region, Scope: c.scope(), Status: status, Collected: len(recOut.ConfigurationRecorders), Reason: reason})
		return true, dcErr
	}

	c.emitRecorders(sink, region, recOut.ConfigurationRecorders, recording, channels)
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: svcConfigRecorders, Region: region, Scope: c.scope(), Status: status, Collected: len(recOut.ConfigurationRecorders), Reason: reason})
	return false, dcErr
}

// deliveryChannels reads the region's delivery channels, records the
// svcDeliveryChannels completeness, and returns them for folding onto recorders. It
// reports whether the budget ran out.
func (c *LoggingCollector) deliveryChannels(ctx context.Context, sink collect.Sink, region string) ([]cfgtypes.DeliveryChannel, bool, error) {
	if !c.budget.Spend() {
		_ = sink.Complete(c.budgetGap(svcDeliveryChannels, region))
		return nil, true, nil
	}
	out, err := c.api.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{}, cfInRegion(region))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			_ = sink.Complete(c.cancelledGap(svcDeliveryChannels, region, 0))
			return nil, false, cerr
		}
		return nil, false, c.listError(sink, svcDeliveryChannels, region, 0, err)
	}
	_ = sink.Evidence(c.evidenceCF("DescribeDeliveryChannels", region, out))
	_ = sink.Complete(c.completeCount(svcDeliveryChannels, region, len(out.DeliveryChannels)))
	return out.DeliveryChannels, false, nil
}

// collectDeliveryChannels is the standalone delivery-channel pass used when the
// recorder list itself failed (recorders are then not emitted, but the delivery
// channel is still worth recording).
func (c *LoggingCollector) collectDeliveryChannels(ctx context.Context, sink collect.Sink, region string, _ []cfgtypes.DeliveryChannel) (bool, error) {
	_, bo, err := c.deliveryChannels(ctx, sink, region)
	return bo, err
}

// emitRecorders emits one control node per Config recorder, folding in its recording
// status and the (1:1 in practice) delivery-channel facts.
func (c *LoggingCollector) emitRecorders(sink collect.Sink, region string, recorders []cfgtypes.ConfigurationRecorder, status map[string]cfgtypes.ConfigurationRecorderStatus, channels []cfgtypes.DeliveryChannel) {
	for _, r := range recorders {
		name := deref(r.Name)
		a := map[string]string{
			"config_type": "configuration_recorder",
			"role_arn":    deref(r.RoleARN),
			"region":      region,
		}
		if g := r.RecordingGroup; g != nil {
			a["all_supported"] = strconv.FormatBool(g.AllSupported)
			a["include_global_resource_types"] = strconv.FormatBool(g.IncludeGlobalResourceTypes)
		}
		if s, ok := status[name]; ok {
			a["recording"] = strconv.FormatBool(s.Recording)
			a["last_status"] = string(s.LastStatus)
		}
		// A Config account has one delivery channel per region in practice; fold its
		// destination facts onto the recorder as the delivery posture.
		if len(channels) > 0 {
			a["delivery_channel_name"] = deref(channels[0].Name)
			a["delivery_s3_bucket"] = deref(channels[0].S3BucketName)
			a["delivery_sns_topic"] = deref(channels[0].SnsTopicARN)
		}
		// Config recorders have no ARN, so key by a stable synthesized id.
		id := "config-recorder:" + c.account + ":" + region + ":" + name
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: id, Name: name, Attributes: pruneEmpty(a)})
	}
}

// ctInRegion targets one CloudTrail call at a declared region.
func ctInRegion(region string) func(*cloudtrail.Options) {
	return func(o *cloudtrail.Options) { o.Region = region }
}

// cfInRegion targets one Config call at a declared region.
func cfInRegion(region string) func(*configservice.Options) {
	return func(o *configservice.Options) { o.Region = region }
}

func (c *LoggingCollector) listError(sink collect.Sink, service, region string, collected int, err error) error {
	comp := c.completeness(service, region, collected, err)
	_ = sink.Complete(comp)
	if comp.Status == collect.Errored {
		return err
	}
	return nil
}

func (c *LoggingCollector) completeness(service, region string, collected int, err error) collect.Completeness {
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

func (c *LoggingCollector) completeCount(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: collected}
}

func (c *LoggingCollector) budgetGap(service, region string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"}
}

func (c *LoggingCollector) cancelledGap(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: collected, Reason: "cancelled"}
}

func (c *LoggingCollector) markBudget(sink collect.Sink, region string, services ...string) {
	for _, s := range services {
		_ = sink.Complete(c.budgetGap(s, region))
	}
}

func (c *LoggingCollector) callGap(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	return redact.String(err.Error())
}

func (c *LoggingCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *LoggingCollector) evidenceCT(operation, region string, response any) collect.Envelope {
	return c.evidence("cloudtrail", operation, region, cloudTrailAPIVersion, response)
}

func (c *LoggingCollector) evidenceCF(operation, region string, response any) collect.Envelope {
	return c.evidence("config", operation, region, configAPIVersion, response)
}

func (c *LoggingCollector) evidence(service, operation, region, apiVersion string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: service, Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: loggingCollectorID},
	}
}
