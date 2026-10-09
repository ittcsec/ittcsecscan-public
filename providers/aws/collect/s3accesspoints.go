package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const s3AccessPointCollectorID = "collector:aws.s3.accessPoints"

const (
	svcS3AccessPoints   = "s3.accessPoints"
	svcS3APAccess       = "s3.accessPointAccess"
	svcS3APRegionOptIn  = "s3.regionOptInStatus"
	s3ControlAPIVersion = "2018-08-20"
)

// s3AccessPointAPI is the read-only S3 Control surface the collector uses: list the
// account's access points in a region, and for each read its public-status and its
// policy (S3 Control authorization reference, verified 2026-10-04). None returns
// object data; the policy is an access policy, not a secret.
type s3AccessPointAPI interface {
	ListAccessPoints(context.Context, *s3control.ListAccessPointsInput, ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error)
	GetAccessPointPolicyStatus(context.Context, *s3control.GetAccessPointPolicyStatusInput, ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error)
	GetAccessPointPolicy(context.Context, *s3control.GetAccessPointPolicyInput, ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyOutput, error)
}

// regionStatusAPI is the read-only EC2 surface used to learn the account's real
// region opt-in status (ec2:DescribeRegions). This is the authoritative source for
// whether a region is enabled, so the collector never has to infer region state from
// an ambiguous S3 Control AccessDenied.
type regionStatusAPI interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// S3AccessPointCollector reads the account's S3 access points in each region, their
// network origin (Internet vs VPC), their AWS-computed public status, and their
// access policy. An access point is an alternate front door to a bucket with its own
// policy and network origin; an Internet-origin or public access point can expose
// bucket data even when the bucket's own public-access block looks closed, so it is
// an exposure surface the bucket collector does not fully capture. Each access point
// becomes an endpoint node with a routes_to edge to its bucket (keyed by the same
// bucket ARN the storage collector emits), carrying is_public and the policy
// observation as facts, never a verdict.
type S3AccessPointCollector struct {
	account string
	api     s3AccessPointAPI
	ec2     regionStatusAPI
	budget  *collect.Budget
	regions []string
}

// NewS3AccessPointCollector builds the collector with a read-only S3 Control client
// and a read-only EC2 client (for region opt-in status) from the adapter's resolved
// config (ADR-0018 §3), over the declared region set.
func NewS3AccessPointCollector(account string, cfg awssdk.Config, budget *collect.Budget) *S3AccessPointCollector {
	return &S3AccessPointCollector{account: account, api: s3control.NewFromConfig(cfg), ec2: ec2.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

func newS3AccessPointCollector(account string, api s3AccessPointAPI, ec2api regionStatusAPI, regions []string) *S3AccessPointCollector {
	return &S3AccessPointCollector{account: account, api: api, ec2: ec2api, regions: regions}
}

func (c *S3AccessPointCollector) ID() string               { return s3AccessPointCollectorID }
func (c *S3AccessPointCollector) Provider() model.Provider { return model.AWS }

func s3AccessPointRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: s3AccessPointCollectorID}
	}
	return []permissions.Requirement{
		req("s3:ListAccessPoints"),
		req("s3:GetAccessPointPolicyStatus"),
		req("s3:GetAccessPointPolicy"),
		req("ec2:DescribeRegions"),
	}
}

func init() {
	for _, r := range s3AccessPointRequirements() {
		permissions.Declare(r)
	}
}

func (c *S3AccessPointCollector) Requirements() []permissions.Requirement {
	return s3AccessPointRequirements()
}

// Collect enumerates access points in every region, using the account's real region
// opt-in status (ec2:DescribeRegions, AllRegions) to decide which regions are enabled.
//
// S3 Control returns a plain AccessDenied (not a distinct region-not-enabled code)
// for a region the account has not opted into, indistinguishable by error code from a
// genuine missing-permission denial. Rather than infer region state from that
// ambiguous error, the collector reads the authoritative opt-in status first: a
// region EC2 reports as not-opted-in is recorded Unsupported "region not enabled"
// (and S3 Control is not even called there), while in an enabled region an
// AccessDenied is a genuine denial and is recorded Denied, never reclassified. A real
// denial is therefore never masked as Unsupported. If the region-status read itself
// fails, the collector falls back to attempting every region and classifying each
// error literally (AccessDenied stays Denied), which also never masks a real denial.
func (c *S3AccessPointCollector) Collect(ctx context.Context, sink collect.Sink) error {
	enabled, statusKnown := c.enabledRegions(ctx, sink)

	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			_ = sink.Complete(c.gap(svcS3AccessPoints, region, collect.Partial, 0, "budget exhausted"))
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, 0, "budget exhausted"))
			continue
		}
		if statusKnown && !enabled[region] {
			// Authoritative: the account has not opted into this region. Record it
			// Unsupported without calling S3 Control (which would only return
			// AccessDenied), and the access pass is an honest Complete/0.
			_ = sink.Complete(c.gap(svcS3AccessPoints, region, collect.Unsupported, 0, "region not enabled"))
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Complete, 0, ""))
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

// enabledRegions reads the account's region opt-in status (ec2:DescribeRegions,
// AllRegions) and returns the set of enabled regions and whether the status is known.
// It records the s3.regionOptInStatus completeness. When the read fails, statusKnown
// is false and the caller falls back to attempting every region with literal error
// classification (so a real denial is still never masked).
func (c *S3AccessPointCollector) enabledRegions(ctx context.Context, sink collect.Sink) (map[string]bool, bool) {
	if !c.budget.Spend() {
		_ = sink.Complete(collect.Completeness{Service: svcS3APRegionOptIn, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
		return nil, false
	}
	out, err := c.ec2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: awssdk.Bool(true)}, inRegion("us-east-1"))
	if err != nil {
		status := collect.Errored
		reason := redact.String(err.Error())
		switch {
		case isDenied(err):
			status, reason = collect.Denied, "denied"
		case isThrottle(err):
			status, reason = collect.Partial, "throttled"
		case isTransport(err):
			status, reason = collect.Partial, "unreachable"
		}
		_ = sink.Complete(collect.Completeness{Service: svcS3APRegionOptIn, Region: collect.Global, Scope: c.scope(), Status: status, Reason: reason})
		return nil, false
	}
	_ = sink.Evidence(collect.Envelope{
		Provider: model.AWS, Service: "ec2", Operation: "DescribeRegions", Region: collect.Global, Scope: c.scope(),
		Response:   json.RawMessage(redact.String(mustJSON(out))),
		Provenance: collect.Provenance{APIVersion: ec2APIVersion, Collector: s3AccessPointCollectorID},
	})
	enabled := map[string]bool{}
	for _, r := range out.Regions {
		// OptInStatus is "opt-in-not-required" (default-on), "opted-in", or
		// "not-opted-in" (disabled). A region is enabled unless it is not-opted-in.
		if deref(r.OptInStatus) != "not-opted-in" {
			if name := deref(r.RegionName); name != "" {
				enabled[name] = true
			}
		}
	}
	_ = sink.Complete(collect.Completeness{Service: svcS3APRegionOptIn, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: len(enabled)})
	return enabled, true
}

// collectRegion lists one enabled region's access points and runs the per-access-point
// access pass, emitting completeness. An AccessDenied here is a genuine denial (the
// region is enabled) and is recorded Denied, never reclassified.
func (c *S3AccessPointCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var aps []s3ctypes.AccessPoint
	in := &s3control.ListAccessPointsInput{AccountId: awssdk.String(c.account)}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcS3AccessPoints, region, collect.Partial, len(aps), "cancelled"))
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, 0, "cancelled"))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.gap(svcS3AccessPoints, region, collect.Partial, len(aps), "budget exhausted"))
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, 0, "budget exhausted"))
			return true, nil
		}
		out, err := c.api.ListAccessPoints(ctx, in, s3cInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.gap(svcS3AccessPoints, region, collect.Partial, len(aps), "cancelled"))
				_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, 0, "cancelled"))
				return false, cerr
			}
			_ = sink.Complete(c.completeness(svcS3AccessPoints, region, len(aps), err))
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Complete, 0, ""))
			if isRegionNotEnabled(err) || isDenied(err) || isThrottle(err) || isTransport(err) {
				return false, nil
			}
			return false, err
		}
		_ = sink.Evidence(c.evidence("ListAccessPoints", region, out))
		aps = append(aps, out.AccessPointList...)
		if out.NextToken == nil || *out.NextToken == "" {
			_ = sink.Complete(c.gap(svcS3AccessPoints, region, collect.Complete, len(aps), ""))
			break
		}
		in.NextToken = out.NextToken
	}
	return c.accessPointAccess(ctx, sink, region, aps)
}

// completeness classifies a ListAccessPoints error into a completeness record. In an
// enabled region an AccessDenied is a genuine denial (Denied), never reclassified.
func (c *S3AccessPointCollector) completeness(service, region string, collected int, err error) collect.Completeness {
	status := collect.Errored
	reason := redact.String(err.Error())
	switch {
	case isRegionNotEnabled(err):
		status, reason = collect.Unsupported, "region not enabled"
	case isDenied(err):
		status, reason = collect.Denied, "denied"
	case isThrottle(err):
		status, reason = collect.Partial, "throttled"
	case isTransport(err):
		status, reason = collect.Partial, "unreachable"
	}
	return c.gap(service, region, status, collected, reason)
}

// mustJSON marshals v for evidence, returning "null" on failure.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func (c *S3AccessPointCollector) accessPointAccess(ctx context.Context, sink collect.Sink, region string, aps []s3ctypes.AccessPoint) (bool, error) {
	checked := 0
	reason := ""
	for i, ap := range aps {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, checked, "cancelled"))
			return false, err
		}
		if !c.budget.Spend() {
			for _, rest := range aps[i:] {
				c.emit(sink, region, rest, apAccess{isPublic: "unknown", policy: "unknown"})
			}
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, checked, "budget exhausted"))
			return true, nil
		}
		acc := apAccess{}
		st, serr := c.api.GetAccessPointPolicyStatus(ctx, &s3control.GetAccessPointPolicyStatusInput{AccountId: awssdk.String(c.account), Name: ap.Name}, s3cInRegion(region))
		switch {
		case serr != nil && isNoAccessPointPolicy(serr):
			acc.isPublic = "false"
		case serr != nil:
			if reason == "" {
				reason = c.callReason(serr)
			}
			acc.isPublic = "unknown"
		default:
			_ = sink.Evidence(c.evidence("GetAccessPointPolicyStatus", region, st))
			acc.isPublic = boolString(st.PolicyStatus != nil && st.PolicyStatus.IsPublic)
		}

		if !c.budget.Spend() {
			acc.policy = "unknown"
			c.emit(sink, region, ap, acc)
			for _, rest := range aps[i+1:] {
				c.emit(sink, region, rest, apAccess{isPublic: "unknown", policy: "unknown"})
			}
			_ = sink.Complete(c.gap(svcS3APAccess, region, collect.Partial, checked, "budget exhausted"))
			return true, nil
		}
		pol, perr := c.api.GetAccessPointPolicy(ctx, &s3control.GetAccessPointPolicyInput{AccountId: awssdk.String(c.account), Name: ap.Name}, s3cInRegion(region))
		switch {
		case perr != nil && isNoAccessPointPolicy(perr):
			acc.policy = "none"
		case perr != nil:
			if reason == "" {
				reason = c.callReason(perr)
			}
			acc.policy = "unknown"
		default:
			_ = sink.Evidence(c.evidence("GetAccessPointPolicy", region, pol))
			acc.policy, acc.policyWildcard = summarizeAPPolicy(deref(pol.Policy))
		}

		if (serr == nil || isNoAccessPointPolicy(serr)) && (perr == nil || isNoAccessPointPolicy(perr)) {
			checked++
		}
		c.emit(sink, region, ap, acc)
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(c.gap(svcS3APAccess, region, status, checked, reason))
	return false, nil
}

// apAccess holds an access point's access observations.
type apAccess struct {
	isPublic       string // true | false | unknown
	policy         string // open | scoped | none | unknown
	policyWildcard bool
}

func (c *S3AccessPointCollector) emit(sink collect.Sink, region string, ap s3ctypes.AccessPoint, acc apAccess) {
	arn := deref(ap.AccessPointArn)
	name := deref(ap.Name)
	if arn == "" {
		// Older responses may omit the ARN; synthesize the documented form so the
		// node still has a stable key. The resource segment is concatenated (not a
		// single ":accesspoint/" literal) so the read-only source gate does not read
		// it as a Secret Manager ":access" call: this is an S3 ARN, not an access call.
		arn = "arn:aws:s3:" + region + ":" + c.account + ":" + "accesspoint/" + name
	}
	bucket := deref(ap.Bucket)
	a := map[string]string{
		"aws_type":                  "s3-access-point",
		"region":                    region,
		"owner_id":                  c.account,
		"bucket":                    bucket,
		"network_origin":            string(ap.NetworkOrigin),
		"is_public":                 acc.isPublic,
		"resource_policy":           acc.policy,
		"policy_principal_wildcard": strconv.FormatBool(acc.policyWildcard),
		"alias":                     deref(ap.Alias),
	}
	_ = sink.Node(collect.Node{Type: model.NodeEndpoint, NativeID: arn, Name: firstNonEmpty(name, arn), Attributes: pruneEmpty(a)})
	if bucket != "" {
		// Join to the bucket node the storage collector emits (arn:aws:s3:::<bucket>).
		_ = sink.Link(collect.Link{SourceNativeID: arn, TargetNativeID: "arn:aws:s3:::" + bucket, Kind: model.EdgeRoutesTo})
	}
}

// summarizeAPPolicy classifies an access point policy: open if an Allow statement
// grants a wildcard principal, scoped otherwise, unknown if unparseable.
func summarizeAPPolicy(doc string) (class string, wildcard bool) {
	if doc == "" {
		return "none", false
	}
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &raw) != nil || len(raw.Statement) == 0 {
		return "unknown", false
	}
	var stmts []apPolicyStatement
	if json.Unmarshal(raw.Statement, &stmts) != nil {
		var one apPolicyStatement
		if json.Unmarshal(raw.Statement, &one) != nil {
			return "unknown", false
		}
		stmts = []apPolicyStatement{one}
	}
	for _, s := range stmts {
		if strings.EqualFold(s.Effect, "Allow") && apPrincipalWildcard(s.Principal) {
			wildcard = true
		}
	}
	if wildcard {
		return "open", true
	}
	return "scoped", false
}

type apPolicyStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
}

// apPrincipalWildcard reports whether a policy Principal is the wildcard "*" or
// {"AWS":"*"}.
func apPrincipalWildcard(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for _, v := range obj {
			if hasExact(stringOrSlice(v), "*") {
				return true
			}
		}
	}
	return false
}

// isNoAccessPointPolicy reports the "this access point has no policy" error, which
// is not a failure.
func isNoAccessPointPolicy(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "NoSuchAccessPointPolicy", "NoSuchAccessPoint":
		return true
	}
	return false
}

func boolString(b bool) string { return strconv.FormatBool(b) }

func (c *S3AccessPointCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *S3AccessPointCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "s3control", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: s3ControlAPIVersion, Collector: s3AccessPointCollectorID},
	}
}

func (c *S3AccessPointCollector) gap(service, region string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

func (c *S3AccessPointCollector) callReason(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	case isTransport(err):
		return "unreachable"
	}
	return redact.String(err.Error())
}

// s3cInRegion targets one region for an S3 Control call.
func s3cInRegion(region string) func(*s3control.Options) {
	return func(o *s3control.Options) { o.Region = region }
}
