package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubLogging is an offline loggingAPI: the same estate in every region, recording
// each call's region, with per-"op@region" error injection.
type stubLogging struct {
	trails    []cttypes.Trail
	status    map[string]bool // trail ARN -> IsLogging
	selectors map[string]*cloudtrail.GetEventSelectorsOutput
	recorders []cfgtypes.ConfigurationRecorder
	recStatus []cfgtypes.ConfigurationRecorderStatus
	channels  []cfgtypes.DeliveryChannel
	errs      map[string]error
	calls     int
	regions   []string
}

func (s *stubLogging) hitCT(op string, o []func(*cloudtrail.Options)) (string, error) {
	s.calls++
	var opt cloudtrail.Options
	for _, f := range o {
		f(&opt)
	}
	s.regions = append(s.regions, opt.Region)
	return opt.Region, s.errs[op+"@"+opt.Region]
}

func (s *stubLogging) hitCF(op string, o []func(*configservice.Options)) (string, error) {
	s.calls++
	var opt configservice.Options
	for _, f := range o {
		f(&opt)
	}
	s.regions = append(s.regions, opt.Region)
	return opt.Region, s.errs[op+"@"+opt.Region]
}

func (s *stubLogging) DescribeTrails(_ context.Context, _ *cloudtrail.DescribeTrailsInput, o ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	region, err := s.hitCT("DescribeTrails", o)
	if err != nil {
		return nil, err
	}
	// The collector calls with IncludeShadowTrails=false, so the API returns a trail
	// only in its home region. Model that: a trail surfaces only when its HomeRegion
	// matches the call's region (a trail with no HomeRegion set surfaces everywhere).
	var out []cttypes.Trail
	for _, t := range s.trails {
		if deref(t.HomeRegion) == "" || deref(t.HomeRegion) == region {
			out = append(out, t)
		}
	}
	return &cloudtrail.DescribeTrailsOutput{TrailList: out}, nil
}

func (s *stubLogging) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, o ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	if _, err := s.hitCT("GetTrailStatus", o); err != nil {
		return nil, err
	}
	v := s.status[deref(in.Name)]
	return &cloudtrail.GetTrailStatusOutput{IsLogging: &v}, nil
}

func (s *stubLogging) GetEventSelectors(_ context.Context, in *cloudtrail.GetEventSelectorsInput, o ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	if _, err := s.hitCT("GetEventSelectors", o); err != nil {
		return nil, err
	}
	if es, ok := s.selectors[deref(in.TrailName)]; ok {
		return es, nil
	}
	return &cloudtrail.GetEventSelectorsOutput{}, nil
}

func (s *stubLogging) DescribeConfigurationRecorders(_ context.Context, _ *configservice.DescribeConfigurationRecordersInput, o ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	if _, err := s.hitCF("DescribeConfigurationRecorders", o); err != nil {
		return nil, err
	}
	return &configservice.DescribeConfigurationRecordersOutput{ConfigurationRecorders: s.recorders}, nil
}

func (s *stubLogging) DescribeConfigurationRecorderStatus(_ context.Context, _ *configservice.DescribeConfigurationRecorderStatusInput, o ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	if _, err := s.hitCF("DescribeConfigurationRecorderStatus", o); err != nil {
		return nil, err
	}
	return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: s.recStatus}, nil
}

func (s *stubLogging) DescribeDeliveryChannels(_ context.Context, _ *configservice.DescribeDeliveryChannelsInput, o ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error) {
	if _, err := s.hitCF("DescribeDeliveryChannels", o); err != nil {
		return nil, err
	}
	return &configservice.DescribeDeliveryChannelsOutput{DeliveryChannels: s.channels}, nil
}

func runLogging(t *testing.T, regions []string, api loggingAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newLoggingCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func ctrlNode(s collect.Scan, id string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

const trailArn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail"

func loggingStub() *stubLogging {
	return &stubLogging{
		trails: []cttypes.Trail{{
			Name:                       ptr("org-trail"),
			TrailARN:                   ptr(trailArn),
			HomeRegion:                 ptr("us-east-1"),
			S3BucketName:               ptr("audit-logs-bucket"),
			KmsKeyId:                   ptr("arn:aws:kms:us-east-1:123456789012:key/abcd"),
			CloudWatchLogsLogGroupArn:  ptr("arn:aws:logs:us-east-1:123456789012:log-group:ct"),
			IsMultiRegionTrail:         bptr(true),
			IsOrganizationTrail:        bptr(true),
			LogFileValidationEnabled:   bptr(true),
			IncludeGlobalServiceEvents: bptr(true),
		}},
		status: map[string]bool{trailArn: true},
		selectors: map[string]*cloudtrail.GetEventSelectorsOutput{
			trailArn: {EventSelectors: []cttypes.EventSelector{{
				ReadWriteType: cttypes.ReadWriteTypeAll,
				DataResources: []cttypes.DataResource{{Type: ptr("AWS::S3::Object")}},
			}}},
		},
		recorders: []cfgtypes.ConfigurationRecorder{{
			Name:           ptr("default"),
			RoleARN:        ptr("arn:aws:iam::123456789012:role/config-role"),
			RecordingGroup: &cfgtypes.RecordingGroup{AllSupported: true, IncludeGlobalResourceTypes: true},
		}},
		recStatus: []cfgtypes.ConfigurationRecorderStatus{{
			Name: ptr("default"), Recording: true, LastStatus: cfgtypes.RecorderStatusSuccess,
		}},
		channels: []cfgtypes.DeliveryChannel{{
			Name: ptr("default"), S3BucketName: ptr("config-logs-bucket"), SnsTopicARN: ptr("arn:aws:sns:us-east-1:123456789012:config"),
		}},
	}
}

// TestLoggingMapsTrail proves a CloudTrail trail becomes a control node keyed by
// ARN, with its logging status, event scope, and the s3_bucket_name and kms_key_id
// cross-references (which resolve onto the S3 and KMS nodes) recorded as facts.
func TestLoggingMapsTrail(t *testing.T) {
	s := runLogging(t, oneRegion, loggingStub())
	n, ok := ctrlNode(s, trailArn)
	if !ok {
		t.Fatal("trail not emitted as a control node keyed by ARN")
	}
	for k, v := range map[string]string{
		"cloudtrail_type": "trail", "home_region": "us-east-1",
		"s3_bucket_name": "audit-logs-bucket", "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd",
		"is_multi_region": "true", "is_organization_trail": "true", "log_file_validation_enabled": "true",
		"is_logging": "true", "management_read_write_type": "All", "data_events": "true",
	} {
		if n.Attributes[k] != v {
			t.Errorf("trail %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if statusOf(s, svcTrails) != collect.Complete || statusOf(s, svcTrailDetails) != collect.Complete {
		t.Errorf("trail completeness not both complete: %s / %s", statusOf(s, svcTrails), statusOf(s, svcTrailDetails))
	}
}

// TestLoggingMapsConfigRecorder proves a Config recorder becomes a control node
// (keyed by a synthesized id, since recorders have no ARN) with recording status and
// the delivery-channel facts folded in.
func TestLoggingMapsConfigRecorder(t *testing.T) {
	s := runLogging(t, oneRegion, loggingStub())
	id := "config-recorder:" + acctID + ":us-east-1:default"
	n, ok := ctrlNode(s, id)
	if !ok {
		t.Fatal("config recorder not emitted with the synthesized id")
	}
	for k, v := range map[string]string{
		"config_type": "configuration_recorder", "recording": "true", "last_status": "Success",
		"all_supported": "true", "include_global_resource_types": "true",
		"delivery_s3_bucket": "config-logs-bucket", "delivery_channel_name": "default",
	} {
		if n.Attributes[k] != v {
			t.Errorf("recorder %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if statusOf(s, svcConfigRecorders) != collect.Complete || statusOf(s, svcDeliveryChannels) != collect.Complete {
		t.Errorf("config completeness not both complete")
	}
}

// TestLoggingMultiRegionTrailNotDuplicated proves that scanning many regions records
// a multi-region trail once. The collector calls DescribeTrails with
// IncludeShadowTrails=false, so the API returns a trail only in its home region; the
// stub models that flag, so the multi-region trail (home us-east-1) surfaces only
// when us-east-1 is scanned, and the graph holds it once rather than N times.
func TestLoggingMultiRegionTrailNotDuplicated(t *testing.T) {
	api := loggingStub()
	s := runLogging(t, []string{"us-east-1", "eu-west-1"}, api)
	count := 0
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.NativeID == trailArn {
			count++
		}
	}
	if count != 1 {
		t.Errorf("multi-region trail recorded %d times, want 1", count)
	}
}

// TestLoggingNoTrailsIsComplete proves an account with no trails is an honest
// Complete/0, not a gap.
func TestLoggingNoTrailsIsComplete(t *testing.T) {
	api := &stubLogging{}
	s := runLogging(t, oneRegion, api)
	for _, svc := range loggingServices() {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}

// TestLoggingTrailStatusDeniedIsGap proves a denied GetTrailStatus is a gap; the
// trail node is still emitted.
func TestLoggingTrailStatusDeniedIsGap(t *testing.T) {
	api := loggingStub()
	api.errs = map[string]error{"GetTrailStatus@us-east-1": apiErr("AccessDenied")}
	s := runLogging(t, oneRegion, api)
	if _, ok := ctrlNode(s, trailArn); !ok {
		t.Error("trail node must still be emitted when GetTrailStatus is denied")
	}
	if c := completenessOf(s, svcTrailDetails); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("%s = %+v, want partial denied", svcTrailDetails, c)
	}
}

// TestLoggingTrailsDeniedStillCollectsConfig proves a denied DescribeTrails is a gap
// that does not stop the Config pass.
func TestLoggingTrailsDeniedStillCollectsConfig(t *testing.T) {
	api := loggingStub()
	api.errs = map[string]error{"DescribeTrails@us-east-1": apiErr("AccessDenied")}
	s := runLogging(t, oneRegion, api)
	if statusOf(s, svcTrails) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcTrails, statusOf(s, svcTrails))
	}
	if statusOf(s, svcConfigRecorders) != collect.Complete {
		t.Error("config should still collect when trails is denied")
	}
}

// TestLoggingRecorderStatusDeniedIsPartial proves a denied recorder-status read makes
// config.recorders Partial while the recorder node is still emitted (without status).
func TestLoggingRecorderStatusDeniedIsPartial(t *testing.T) {
	api := loggingStub()
	api.errs = map[string]error{"DescribeConfigurationRecorderStatus@us-east-1": apiErr("AccessDenied")}
	s := runLogging(t, oneRegion, api)
	id := "config-recorder:" + acctID + ":us-east-1:default"
	n, ok := ctrlNode(s, id)
	if !ok {
		t.Fatal("recorder node must still be emitted when status read is denied")
	}
	if _, has := n.Attributes["recording"]; has {
		t.Error("recording status must be absent when the status read was denied")
	}
	if c := completenessOf(s, svcConfigRecorders); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("%s = %+v, want partial denied", svcConfigRecorders, c)
	}
}

// TestLoggingRegionNotEnabled proves an opt-in region the account has not enabled is
// Unsupported "region not enabled".
func TestLoggingRegionNotEnabled(t *testing.T) {
	api := &stubLogging{errs: map[string]error{"DescribeTrails@us-east-1": apiErr("UnrecognizedClientException")}}
	s := runLogging(t, oneRegion, api)
	if c := completenessOf(s, svcTrails); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("%s = %+v, want unsupported region-not-enabled", svcTrails, c)
	}
}

// TestLoggingFanOutAllRegions proves every declared region is visited and records
// four completeness services per region.
func TestLoggingFanOutAllRegions(t *testing.T) {
	regions := []string{"us-east-1", "eu-west-1"}
	s := runLogging(t, regions, &stubLogging{})
	if len(s.Completeness) != 8 { // 4 services x 2 regions
		t.Errorf("completeness records = %d, want 8", len(s.Completeness))
	}
}

// TestLoggingBudgetExhaustion proves the shared budget bounds the sweep and marks the
// services not reached Partial "budget exhausted".
func TestLoggingBudgetExhaustion(t *testing.T) {
	api := loggingStub()
	c := newLoggingCollector(acctID, api, oneRegion)
	c.budget = collect.NewBudget(1) // DescribeTrails only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, svc := range []string{svcConfigRecorders, svcDeliveryChannels} {
		if got := completenessOf(s, svc); got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial budget-exhausted", svc, got)
		}
	}
}

// TestLoggingEvidenceRedactsToken proves the evidence body is scrubbed.
func TestLoggingEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Z", 16)
	api := loggingStub()
	api.trails[0].S3BucketName = ptr(token)
	s := runLogging(t, oneRegion, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
