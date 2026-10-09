package collect

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// instanceCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const instanceCollectorID = "collector:aws.ec2.instances"

// ec2APIVersion is the EC2 API version, recorded as evidence provenance.
const ec2APIVersion = "2016-11-15"

// instancesEC2API is the read-only EC2 surface the collector uses: DescribeInstances,
// a List-level read verified against the EC2 service authorization reference
// (2026-09-19). It returns instance metadata only, never user data, console
// output, or a password (those getters are refused by the read-only gate). The
// optFns target one declared region per call.
type instancesEC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// instanceProfileAPI is the read-only IAM surface used to resolve an instance's
// instance profile to the role it runs as (iam:GetInstanceProfile, verified
// 2026-09-19). IAM is global, so these calls are not region-targeted.
type instanceProfileAPI interface {
	GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error)
}

// InstanceCollector reads the account's EC2 instances in each declared region
// (ADR-0019 §1) and emits each as a compute node keyed by its ARN, with the
// run-as edge to the IAM role its instance profile grants (ADR-0019 §3). It reads
// instance metadata only; user data, console output, and passwords are never read
// (and their getters are gate-forbidden). Network and reachability edges are the
// the reachability engine's job and are not emitted here.
type InstanceCollector struct {
	account string
	ec2     instancesEC2API
	iam     instanceProfileAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string

	// pending records each instance that carries an instance profile, so roles are
	// resolved once after enumeration (a profile is shared across instances).
	pending []instanceProfileRef
}

// instanceProfileRef pairs an instance's ARN with its instance-profile ARN, to
// resolve the run-as role after enumeration.
type instanceProfileRef struct {
	instanceARN string
	profileARN  string
}

// NewInstanceCollector builds the collector with read-only EC2 and IAM clients
// from the adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewInstanceCollector(account string, cfg awssdk.Config, budget *collect.Budget) *InstanceCollector {
	return &InstanceCollector{account: account, ec2: ec2.NewFromConfig(cfg), iam: iam.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

// newInstanceCollector is the injectable constructor tests use with stub APIs and
// an explicit region list. It has no budget (unlimited).
func newInstanceCollector(account string, ec2api instancesEC2API, iamapi instanceProfileAPI, regions []string) *InstanceCollector {
	return &InstanceCollector{account: account, ec2: ec2api, iam: iamapi, regions: regions}
}

func (c *InstanceCollector) ID() string               { return instanceCollectorID }
func (c *InstanceCollector) Provider() model.Provider { return model.AWS }

// instanceRequirements are the read-only permissions this collector needs.
// ec2:DescribeInstances (List) enumerates instances; iam:GetInstanceProfile
// resolves the run-as role. Both action names were verified against the service
// authorization references (2026-09-19) and are registered at init so the
// templates reconcile against real code (ADR-0016).
func instanceRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: instanceCollectorID}
	}
	return []permissions.Requirement{
		req("ec2:DescribeInstances"),
		req("iam:GetInstanceProfile"),
	}
}

func init() {
	for _, r := range instanceRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *InstanceCollector) Requirements() []permissions.Requirement { return instanceRequirements() }

// Collect enumerates instances in every declared region (sequentially, ADR-0019
// §1), then resolves the run-as roles. One completeness record per region
// (ec2.instances) plus one aggregate for role resolution (ec2.instanceRoles). A
// denied or throttled region is a recorded gap and collection continues; a
// not-enabled opt-in region is Unsupported; budget exhaustion marks every
// enumeration not yet reached Partial "budget exhausted", none skipped. An
// unexpected error is Errored, the rest still run, and the errors surface.
func (c *InstanceCollector) Collect(ctx context.Context, sink collect.Sink) error {
	c.pending = nil
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			_ = sink.Complete(collect.Completeness{Service: "ec2.instances", Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
			continue
		}
		out, err := c.instancesInRegion(ctx, sink, region)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, err)
		}
		exhausted = out
	}
	c.resolveRoles(ctx, sink, exhausted)
	return errors.Join(errs...)
}

// instancesInRegion paginates DescribeInstances in one region and records its
// completeness. It reports whether the budget ran out.
func (c *InstanceCollector) instancesInRegion(ctx context.Context, sink collect.Sink, region string) (budgetOut bool, err error) {
	const service = "ec2.instances"
	count := 0
	var token *string
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return true, nil
		}
		out, err := c.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: token}, inRegion(region))
		if err != nil {
			// Separate genuine cancellation of the scan's own context from a
			// per-request failure (a dial timeout wraps context.DeadlineExceeded but
			// leaves the scan context live), so the former is "cancelled" and the
			// latter is classified below.
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
				return false, cerr
			}
			_ = sink.Complete(c.instancesCompleteness(region, count, err))
			// A not-enabled region, a denial, a throttle, or a transport failure
			// (one region unreachable) is a represented per-region gap that does not
			// stop the others (ADR-0018 §4); only an unclassified error surfaces.
			if isRegionNotEnabled(err) || isDenied(err) || isThrottle(err) || isTransport(err) {
				return false, nil
			}
			return false, err
		}
		_ = sink.Evidence(c.evidence("DescribeInstances", region, out))
		count += c.mapInstances(sink, region, out)
		if out.NextToken == nil || *out.NextToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return false, nil
		}
		token = out.NextToken
	}
}

// mapInstances emits a compute node per instance and records instances that carry
// an instance profile for role resolution. Returns the number of instances mapped.
func (c *InstanceCollector) mapInstances(sink collect.Sink, region string, out *ec2.DescribeInstancesOutput) int {
	n := 0
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			id := deref(inst.InstanceId)
			if id == "" {
				continue
			}
			arn := c.instanceARN(region, id)
			a := map[string]string{
				"instance_id":   id,
				"region":        region,
				"instance_type": string(inst.InstanceType),
				"image_id":      deref(inst.ImageId),
				"vpc_id":        deref(inst.VpcId),
				"subnet_id":     deref(inst.SubnetId),
				"private_ip":    deref(inst.PrivateIpAddress),
				"public_ip":     deref(inst.PublicIpAddress),
				"public_dns":    deref(inst.PublicDnsName),
			}
			if inst.State != nil {
				a["state"] = string(inst.State.Name)
			}
			if inst.Placement != nil {
				a["availability_zone"] = deref(inst.Placement.AvailabilityZone)
			}
			var sgs []string
			for _, g := range inst.SecurityGroups {
				if gid := deref(g.GroupId); gid != "" {
					sgs = append(sgs, gid)
				}
			}
			a["security_group_ids"] = joinSorted(sgs)
			if inst.IamInstanceProfile != nil {
				pa := deref(inst.IamInstanceProfile.Arn)
				a["iam_instance_profile_arn"] = pa
				if pa != "" {
					c.pending = append(c.pending, instanceProfileRef{instanceARN: arn, profileARN: pa})
				}
			}
			name := ""
			for _, t := range inst.Tags {
				if k := deref(t.Key); k != "" {
					a["tag:"+k] = deref(t.Value)
					if k == "Name" {
						name = deref(t.Value)
					}
				}
			}
			_ = sink.Node(collect.Node{Type: model.NodeCompute, NativeID: arn, Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
			n++
		}
	}
	return n
}

// resolveRoles resolves each distinct instance profile to the role it grants
// (iam:GetInstanceProfile) and emits the instance to role run-as edge, keyed to
// the role ARN so it joins the IAM identity collector's role nodes. A minimal role
// node is emitted so the edge does not dangle when the IAM collector is not in the
// scan. One profile is resolved once (shared across instances). A per-profile
// denial or error is a recorded gap that does not stop the others; budget
// exhaustion stops resolution. It records the ec2.instanceRoles completeness.
// alreadyExhausted is true when the region enumeration already drained the budget.
func (c *InstanceCollector) resolveRoles(ctx context.Context, sink collect.Sink, alreadyExhausted bool) {
	const service = "ec2.instanceRoles"
	roleOf := map[string]roleRef{}
	reason := ""
	if alreadyExhausted {
		reason = "budget exhausted"
	}
	for _, p := range c.pending {
		name := lastSegment(p.profileARN)
		if name == "" {
			continue
		}
		if _, done := roleOf[name]; done {
			continue
		}
		if reason == "budget exhausted" {
			break
		}
		if err := ctx.Err(); err != nil {
			reason = "cancelled"
			break
		}
		if !c.budget.Spend() {
			reason = "budget exhausted"
			break
		}
		out, err := c.iam.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: &name})
		if err != nil {
			reason = c.callGap(err)
			roleOf[name] = roleRef{} // attempted; no edge
			continue
		}
		_ = sink.Evidence(c.iamEvidence("GetInstanceProfile", out))
		ref := roleRef{}
		if out.InstanceProfile != nil && len(out.InstanceProfile.Roles) > 0 {
			ref = roleRef{arn: deref(out.InstanceProfile.Roles[0].Arn), name: deref(out.InstanceProfile.Roles[0].RoleName)}
		}
		roleOf[name] = ref
	}

	edges := 0
	for _, p := range c.pending {
		ref, ok := roleOf[lastSegment(p.profileARN)]
		if !ok || ref.arn == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeRole, NativeID: ref.arn, Name: ref.name})
		_ = sink.Link(collect.Link{SourceNativeID: p.instanceARN, TargetNativeID: ref.arn, Kind: model.EdgeAssumes})
		edges++
	}

	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: edges, Reason: reason})
}

// roleRef is a resolved instance-profile role.
type roleRef struct{ arn, name string }

// instanceARN builds the documented EC2 instance ARN. DescribeInstances returns
// no ARN, so it is synthesized from the region, the scanned account, and the
// instance id (EC2 service authorization reference, verified 2026-09-19). Only the
// aws partition is collected (see regions.go).
func (c *InstanceCollector) instanceARN(region, id string) string {
	return "arn:aws:ec2:" + region + ":" + c.account + ":instance/" + id
}

// inRegion targets one EC2 call at a declared region.
func inRegion(region string) func(*ec2.Options) {
	return func(o *ec2.Options) { o.Region = region }
}

// isRegionNotEnabled reports an AWS error meaning the Region is not enabled for
// the account (an opt-in Region the account has not opted into): the credential is
// valid (other Regions succeed) but this Region rejects it. Recorded Unsupported
// ("region not enabled"), the remediation being to enable the Region, not to grant
// a permission, mirroring how a disabled GCP API is Unsupported.
//
// Services signal a disabled opt-in Region with different codes, each confirmed
// live against the same real disabled Regions: EC2 returns OptInRequired or
// AuthFailure, RDS rejects the global credential with InvalidClientTokenId, and KMS
// with UnrecognizedClientException. All mean the same thing, a Region the account
// has not enabled, so all classify as region-not-enabled. This is per-Region: a
// genuinely invalid credential fails identity resolution and every Region including
// the always-on ones, so it never reaches a collector.
func isRegionNotEnabled(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "OptInRequired", "AuthFailure", "UnauthorizedOperation.RegionDisabled",
		"InvalidClientTokenId", "UnrecognizedClientException":
		return true
	}
	return false
}

// isTransport reports a transient failure that should be a per-region gap rather
// than a reason to fail the whole scan (ADR-0018 §4: exhausting retries yields
// partial, never a crash), the same way one provider's denial never blocks the
// others. Three shapes qualify:
//
//   - Retry exhaustion (retry.MaxAttemptsError): the SDK only retries transient
//     failures (5xx, throttling, timeouts), so giving up after the bounded attempts
//     is transient by definition. This is how a real 503 surfaces: a modeled API
//     error (for example UnknownError) wrapped in a MaxAttemptsError, which the plain
//     smithy.APIError check below would otherwise misclassify as fatal (caught live
//     against CloudTrail).
//   - A 5xx server response (ServiceUnavailable, InternalError): server-side and
//     transient even when it carries an API error code.
//   - No modeled API error at all: a transport or connection failure (a dial
//     timeout, a reset).
//
// A dial timeout wraps context.DeadlineExceeded (the dialer's own per-connection
// deadline), so the no-API-error branch must NOT exclude context errors, or a
// fast-fail dial timeout would be misclassified as fatal. Genuine cancellation of
// the scan's own context is instead separated by the caller, which checks ctx.Err()
// before classifying, so a transient error only reaches here when the scan is live.
func isTransport(err error) bool {
	if err == nil {
		return false
	}
	var maxAtt *retry.MaxAttemptsError
	if errors.As(err, &maxAtt) {
		return true
	}
	var httpErr interface{ HTTPStatusCode() int }
	if errors.As(err, &httpErr) && httpErr.HTTPStatusCode() >= 500 {
		return true
	}
	var api smithy.APIError
	return !errors.As(err, &api)
}

// callGap classifies a per-profile IAM error into a gap reason (never empty).
func (c *InstanceCollector) callGap(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	return redact.String(err.Error())
}

func (c *InstanceCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one EC2 read.
func (c *InstanceCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "ec2", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: ec2APIVersion, Collector: instanceCollectorID},
	}
}

// iamEvidence builds a redacted envelope for one IAM GetInstanceProfile read
// (global, so no region).
func (c *InstanceCollector) iamEvidence(operation string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "iam", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: instanceCollectorID},
	}
}

// instancesCompleteness classifies a DescribeInstances error into a completeness
// record. A not-enabled Region is Unsupported, a denial Denied, a throttle
// Partial, anything else Errored.
func (c *InstanceCollector) instancesCompleteness(region string, collected int, err error) collect.Completeness {
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
	return collect.Completeness{Service: "ec2.instances", Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

// lastSegment returns the substring after the final "/", used to get an instance
// profile's name from its ARN (arn:aws:iam::acct:instance-profile/<path>/<name>).
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// joinSorted renders a set of ids as a sorted, comma-separated list.
func joinSorted(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	s := append([]string(nil), xs...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
