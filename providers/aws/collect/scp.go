package collect

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// scpDenyLevel classifies what privilege a service control policy removes from the
// accounts and OUs it is attached to, from its Deny statements (the restrictive
// pattern): admin when it denies all actions ("*"), privileged when it denies a
// documented escalation action. An allow-list SCP (Allow only a subset, implicitly
// denying the rest) is a noted follow-up; this reads explicit Deny statements. A
// cap at a level removes an effective grant at or below it (ADR-0022 EP-6).
func scpDenyLevel(doc string) string {
	stmts, ok := parseStatements(doc)
	if !ok {
		return ""
	}
	admin := false
	esc := false
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Deny") {
			continue
		}
		actions := lowerAll(stringOrSlice(s.Action))
		if hasExact(actions, "*") {
			admin = true
		}
		for _, ea := range escalationActions {
			if actionAllowed(actions, ea) {
				esc = true
			}
		}
	}
	switch {
	case admin:
		return "admin"
	case esc:
		return "privileged"
	default:
		return ""
	}
}

// collectSCPs reads the organization's service control policies and stamps a
// deny_privilege_level fact on each account or OU an SCP is attached to (the
// privilege the SCP removes). An SCP is an account-wide guardrail, so the Step 4
// engine applies an account's cap to every principal in it (ADR-0022 EP-6). Only
// SCPs that actually remove privilege are stamped; the default FullAWSAccess SCP
// (Allow "*", no Deny) is not a cap. OU-to-account inheritance (an SCP on a parent
// OU capping child accounts) is a noted follow-up; this stamps directly-targeted
// accounts and OUs. Reads are DescribePolicy / ListTargetsForPolicy (read-only).
func (c *OrganizationsCollector) collectSCPs(ctx context.Context, sink collect.Sink) {
	const service = "organizations.scps"
	var summaries []orgtypes.PolicySummary
	var token *string
	for {
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
			return
		}
		out, err := c.api.ListPolicies(ctx, &organizations.ListPoliciesInput{Filter: orgtypes.PolicyTypeServiceControlPolicy, NextToken: token})
		if err != nil {
			_ = sink.Complete(c.completeness(service, 0, err))
			return
		}
		summaries = append(summaries, out.Policies...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}

	stamped := 0
	for _, p := range summaries {
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: stamped, Reason: "budget exhausted"})
			return
		}
		desc, err := c.api.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: p.Id})
		if err != nil {
			_ = sink.Complete(c.completeness(service, stamped, err))
			return
		}
		if desc.Policy == nil {
			continue
		}
		level := scpDenyLevel(deref(desc.Policy.Content))
		if level == "" {
			continue // not a restrictive SCP; no cap
		}
		stamped += c.stampSCPTargets(ctx, sink, p.Id, level)
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: stamped})
}

// stampSCPTargets reads a policy's targets and stamps each with the deny level,
// keyed to match the hierarchy nodes: an account by its id, an OU or root by its
// ARN. Returns how many targets were stamped.
func (c *OrganizationsCollector) stampSCPTargets(ctx context.Context, sink collect.Sink, policyID *string, level string) int {
	n := 0
	var token *string
	for {
		if !c.budget.Spend() {
			return n
		}
		out, err := c.api.ListTargetsForPolicy(ctx, &organizations.ListTargetsForPolicyInput{PolicyId: policyID, NextToken: token})
		if err != nil {
			return n
		}
		for _, t := range out.Targets {
			key, typ := scpTargetKey(t)
			if key == "" {
				continue
			}
			_ = sink.Node(collect.Node{Type: typ, NativeID: key, Attributes: attrs("deny_privilege_level", level)})
			n++
		}
		if out.NextToken == nil {
			return n
		}
		token = out.NextToken
	}
}

// scpTargetKey returns the node key and type for an SCP target: an account is keyed
// by its id (matching the member-account node), an OU or root by its ARN (matching
// the hierarchy node).
func scpTargetKey(t orgtypes.PolicyTargetSummary) (string, model.NodeType) {
	switch t.Type {
	case orgtypes.TargetTypeAccount:
		return deref(t.TargetId), model.NodeAccount
	case orgtypes.TargetTypeOrganizationalUnit, orgtypes.TargetTypeRoot:
		return deref(t.Arn), model.NodeOrganization
	default:
		return "", ""
	}
}
