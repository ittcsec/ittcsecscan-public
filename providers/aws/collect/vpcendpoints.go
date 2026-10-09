package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// vpcEndpointCollectorID is the stable id this collector is credited with.
const vpcEndpointCollectorID = "collector:aws.ec2.vpcEndpoints"

// vpcEndpointAPI is the read-only EC2 surface for VPC endpoints: one Describe at
// the List access level (EC2 service authorization reference, verified 2026-10-04).
// It returns configuration only, including the endpoint's resource policy document;
// no secret value.
type vpcEndpointAPI interface {
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
}

// VPCEndpointCollector reads each region's VPC endpoints and their resource
// policies. A VPC endpoint's policy governs which principals and actions may reach
// an AWS service privately through the endpoint; a permissive endpoint policy is a
// data-exfiltration and cross-account-access surface the network and IAM collectors
// do not see. It records the policy as a fact plus structural observations
// (wildcard principal, wildcard action, whether any condition narrows it, and
// whether the policy is the AWS full-access default), never a verdict: whether a
// given policy is too permissive is the rule engine's call.
type VPCEndpointCollector struct {
	account string
	api     vpcEndpointAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewVPCEndpointCollector builds the collector with a read-only EC2 client from the
// adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewVPCEndpointCollector(account string, cfg awssdk.Config, budget *collect.Budget) *VPCEndpointCollector {
	return &VPCEndpointCollector{account: account, api: ec2.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

// newVPCEndpointCollector is the injectable constructor tests use with a stub API
// and an explicit region list. It has no budget (unlimited).
func newVPCEndpointCollector(account string, api vpcEndpointAPI, regions []string) *VPCEndpointCollector {
	return &VPCEndpointCollector{account: account, api: api, regions: regions}
}

func (c *VPCEndpointCollector) ID() string               { return vpcEndpointCollectorID }
func (c *VPCEndpointCollector) Provider() model.Provider { return model.AWS }

func vpcEndpointRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.AWS, Profile: permissions.Discovery,
		Permission: "ec2:DescribeVpcEndpoints", By: vpcEndpointCollectorID,
	}}
}

func init() {
	for _, r := range vpcEndpointRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permission the collector needs.
func (c *VPCEndpointCollector) Requirements() []permissions.Requirement {
	return vpcEndpointRequirements()
}

// Collect enumerates VPC endpoints in every declared region sequentially, one
// completeness record per region. A denied, throttled, not-enabled, or unreachable
// read is a represented gap and the rest continue; budget exhaustion marks every
// region not yet reached Partial.
func (c *VPCEndpointCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "ec2.vpcEndpoints"
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
			continue
		}
		budgetOut, err := c.enumerate(ctx, sink, service, region)
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

func (c *VPCEndpointCollector) enumerate(ctx context.Context, sink collect.Sink, service, region string) (budgetOut bool, err error) {
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
		out, err := c.api.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{NextToken: token}, inRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
				return false, cerr
			}
			_ = sink.Complete(c.completeness(service, region, count, err))
			if isRegionNotEnabled(err) || isDenied(err) || isThrottle(err) || isTransport(err) {
				return false, nil
			}
			return false, err
		}
		_ = sink.Evidence(c.evidence("DescribeVpcEndpoints", region, out))
		for i := range out.VpcEndpoints {
			c.emit(sink, region, &out.VpcEndpoints[i])
			count++
		}
		if out.NextToken == nil || *out.NextToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return false, nil
		}
		token = out.NextToken
	}
}

func (c *VPCEndpointCollector) emit(sink collect.Sink, region string, e *ec2types.VpcEndpoint) {
	id, owner := deref(e.VpcEndpointId), deref(e.OwnerId)
	if id == "" {
		return
	}
	a := base("vpc-endpoint", id, region, owner)
	a["endpoint_type"] = string(e.VpcEndpointType)
	a["service_name"] = deref(e.ServiceName)
	a["vpc_id"] = deref(e.VpcId)
	a["state"] = string(e.State)
	a["private_dns_enabled"] = boolAttr(e.PrivateDnsEnabled)
	name := tagAttrs(a, e.Tags)

	if pol := deref(e.PolicyDocument); pol != "" {
		a["has_policy"] = "true"
		f := assessEndpointPolicy(pol)
		a["policy_default"] = strconv.FormatBool(f.isDefault)
		a["policy_principal_wildcard"] = strconv.FormatBool(f.principalWildcard)
		a["policy_action_wildcard"] = strconv.FormatBool(f.actionWildcard)
		a["policy_has_condition"] = strconv.FormatBool(f.hasCondition)
		if f.canonical != "" {
			a["policy_document"] = f.canonical
		}
	} else {
		a["has_policy"] = "false"
	}

	_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: c.ec2ARN(region, owner, "vpc-endpoint", id),
		Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
}

// endpointPolicyFacts are the structural observations drawn from a VPC endpoint
// resource policy, for a rule to judge. None is a verdict.
type endpointPolicyFacts struct {
	isDefault         bool // the AWS full-access default (single Allow, Action *, Principal *, Resource *)
	principalWildcard bool // some Allow statement has Principal "*" or {"AWS":"*"}
	actionWildcard    bool // some Allow statement has Action "*"
	hasCondition      bool // some statement carries a Condition
	canonical         string
}

// endpointStatement is a VPC endpoint policy statement. Unlike the IAM policy
// parser it carries Principal, which the endpoint policy uses and the IAM identity
// policy does not.
type endpointStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition"`
}

// assessEndpointPolicy parses a VPC endpoint resource policy (plain JSON, not
// URL-encoded) and records structural facts. A document that cannot be parsed
// yields canonical="" and all-false, so a malformed policy is an honest non-result,
// never a false "wide open" or a false "locked down".
func assessEndpointPolicy(doc string) endpointPolicyFacts {
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &raw) != nil || len(raw.Statement) == 0 {
		return endpointPolicyFacts{}
	}
	var stmts []endpointStatement
	if json.Unmarshal(raw.Statement, &stmts) != nil {
		var one endpointStatement
		if json.Unmarshal(raw.Statement, &one) != nil {
			return endpointPolicyFacts{}
		}
		stmts = []endpointStatement{one}
	}

	f := endpointPolicyFacts{canonical: canonicalizeJSON(doc)}
	allowCount := 0
	for _, s := range stmts {
		if len(s.Condition) > 0 && string(s.Condition) != "null" {
			f.hasCondition = true
		}
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		allowCount++
		actions := stringOrSlice(s.Action)
		pw := principalIsWildcard(s.Principal)
		aw := hasExact(actions, "*")
		if pw {
			f.principalWildcard = true
		}
		if aw {
			f.actionWildcard = true
		}
		if pw && aw && hasExact(stringOrSlice(s.Resource), "*") && len(s.Condition) == 0 && len(stmts) == 1 && allowCount == 1 {
			f.isDefault = true
		}
	}
	return f
}

// principalIsWildcard reports whether a policy Principal element is the wildcard "*"
// or {"AWS":"*"} (optionally a list containing "*").
func principalIsWildcard(raw json.RawMessage) bool {
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

// canonicalizeJSON re-marshals a JSON document so equal policies render identically
// in evidence (encoding/json sorts object keys on marshal); an unparseable document
// is returned redacted as-is.
func canonicalizeJSON(doc string) string {
	var v any
	if json.Unmarshal([]byte(doc), &v) != nil {
		return redact.String(doc)
	}
	return canonicalJSON(v)
}

func (c *VPCEndpointCollector) ec2ARN(region, owner, resourceType, id string) string {
	if owner == "" {
		owner = c.account
	}
	return "arn:aws:ec2:" + region + ":" + owner + ":" + resourceType + "/" + id
}

func (c *VPCEndpointCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *VPCEndpointCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "ec2", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: ec2APIVersion, Collector: vpcEndpointCollectorID},
	}
}

func (c *VPCEndpointCollector) completeness(service, region string, collected int, err error) collect.Completeness {
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
