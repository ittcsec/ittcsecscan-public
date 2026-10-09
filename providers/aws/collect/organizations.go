package collect

import (
	"context"
	"errors"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// organizationsCollectorID is the stable id this collector is credited with.
const organizationsCollectorID = "collector:aws.organizations"

// organizationsAPIVersion is the AWS Organizations API version, recorded as evidence
// provenance.
const organizationsAPIVersion = "2016-11-28"

// maxOrgPages bounds pagination and the OU recursion so a malformed response cannot
// loop forever (AWS OUs nest at most five deep).
const maxOrgPages = 1000

// orgAPI is the read-only AWS Organizations surface the collector uses. Every call is
// a read (Describe/List) verified against the Organizations API reference (2026-09-22);
// the collector never calls a mutating operation (CreateAccount, MoveAccount,
// AttachPolicy, and the rest are refused by the read-only method-name gate).
type orgAPI interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(context.Context, *organizations.ListAccountsForParentInput, ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	ListPolicies(context.Context, *organizations.ListPoliciesInput, ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

// OrganizationsCollector reads the account's AWS Organizations hierarchy, the AWS half
// of the account-hierarchy domain (ADR-0018 §5), alongside Azure management
// groups and GCP org/folders. Service control policies attach at the organization,
// organizational-unit, and account levels and constrain every principal beneath, so
// the tree is the join the identity engine needs. Organizations is a global service
// (like IAM), so there is no region fan-out. Starting from DescribeOrganization it
// lists the roots, then walks organizational units and accounts down the tree with
// read-only Describe/List calls only; it never creates, moves, closes, or invites an
// account, and never attaches or modifies a policy.
//
// The organization, its roots, and each organizational unit become organization nodes
// keyed by their ARNs (ADR-0019 §2) with a hierarchy_type; each member account becomes
// an account node keyed by its 12-digit account id (so it merges with the node the IAM
// and authorization collectors emit). Every node records its parent as a parent_id
// forward-key fact, so the containment chain joins without a synthesized edge, the same
// discipline the Azure and GCP hierarchy collectors follow. Per ADR-0019 §3 no verdict
// is synthesized, and no account email (PII) is recorded.
//
// An account that is not a member of any organization (AWSOrganizationsNotInUseException)
// is recorded as an explicit represented fact (Complete with a stated reason), the same
// treatment as a GCP standalone project, never a Denied or Errored gap.
type OrganizationsCollector struct {
	account string
	api     orgAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewOrganizationsCollector builds the collector with a read-only Organizations client
// from the adapter's resolved config (ADR-0018 §3).
func NewOrganizationsCollector(account string, cfg awssdk.Config, budget *collect.Budget) *OrganizationsCollector {
	return &OrganizationsCollector{account: account, api: organizations.NewFromConfig(cfg), budget: budget}
}

// newOrganizationsCollector is the injectable constructor tests use with a stub API.
func newOrganizationsCollector(account string, api orgAPI) *OrganizationsCollector {
	return &OrganizationsCollector{account: account, api: api}
}

func (c *OrganizationsCollector) ID() string               { return organizationsCollectorID }
func (c *OrganizationsCollector) Provider() model.Provider { return model.AWS }

func organizationsRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: organizationsCollectorID}
	}
	return []permissions.Requirement{
		req("organizations:DescribeOrganization"),
		req("organizations:ListRoots"),
		req("organizations:ListOrganizationalUnitsForParent"),
		req("organizations:ListAccountsForParent"),
		req("organizations:ListPolicies"),
		req("organizations:DescribePolicy"),
		req("organizations:ListTargetsForPolicy"),
	}
}

func init() {
	for _, r := range organizationsRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *OrganizationsCollector) Requirements() []permissions.Requirement {
	return organizationsRequirements()
}

// walkState carries the running node count and whether any sub-read was a represented
// gap (so the aggregate completeness is Partial), plus a budget-exhausted flag that
// stops the walk.
type walkState struct {
	count     int
	degraded  bool
	reason    string
	exhausted bool
}

// Collect reads the organization and walks its roots, organizational units, and
// accounts, emitting one node per level with its parent as a forward-key fact. One
// completeness record is produced (organizations.hierarchy): Complete when the whole
// tree was read (or the account is standalone), Partial when a sub-read was denied,
// throttled, or the budget ran out, Denied or Errored when DescribeOrganization itself
// failed.
func (c *OrganizationsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "organizations.hierarchy"
	if !c.budget.Spend() {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
	}
	out, err := c.api.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		if isNotInOrg(err) {
			// The account belongs to no organization: an explicit, checked fact, not a
			// gap. No org node exists to emit.
			return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Reason: "account is not a member of an organization"})
		}
		return sink.Complete(c.completeness(service, 0, err))
	}
	org := out.Organization
	if org == nil || org.Arn == nil {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Reason: "organization response had no arn"})
	}
	_ = sink.Evidence(c.evidence("DescribeOrganization"))
	orgArn := aws(org.Arn)
	a := map[string]string{
		"hierarchy_type":    "organization",
		"organization_id":   aws(org.Id),
		"master_account_id": aws(org.MasterAccountId),
		"feature_set":       string(org.FeatureSet),
	}
	_ = sink.Node(collect.Node{Type: model.NodeOrganization, NativeID: orgArn, Name: aws(org.Id), Attributes: pruneEmptyOrg(a)})

	st := &walkState{count: 1}
	c.walkRoots(ctx, sink, orgArn, st)

	status := collect.Complete
	if st.exhausted {
		st.degraded, st.reason = true, "budget exhausted"
	}
	if st.degraded {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: st.count, Reason: st.reason})

	// Service control policies cap the privilege of every principal in the accounts
	// and OUs they attach to (ADR-0022 EP-6). Read them after the tree so the account
	// and OU nodes they stamp merge with the hierarchy nodes.
	c.collectSCPs(ctx, sink)
	return nil
}

func (c *OrganizationsCollector) walkRoots(ctx context.Context, sink collect.Sink, orgArn string, st *walkState) {
	token := ""
	for page := 0; page < maxOrgPages; page++ {
		if st.exhausted || ctx.Err() != nil {
			return
		}
		if !c.budget.Spend() {
			st.exhausted = true
			return
		}
		in := &organizations.ListRootsInput{}
		if token != "" {
			in.NextToken = &token
		}
		out, err := c.api.ListRoots(ctx, in)
		if err != nil {
			c.note(st, err)
			return
		}
		_ = sink.Evidence(c.evidence("ListRoots"))
		for _, r := range out.Roots {
			if r.Arn == nil {
				continue
			}
			rootArn := aws(r.Arn)
			_ = sink.Node(collect.Node{Type: model.NodeOrganization, NativeID: rootArn, Name: aws(r.Name),
				Attributes: pruneEmptyOrg(map[string]string{"hierarchy_type": "organizational_root", "parent_id": orgArn})})
			st.count++
			c.walkParent(ctx, sink, aws(r.Id), rootArn, st, 0)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return
		}
		token = *out.NextToken
	}
}

// walkParent lists the organizational units and accounts directly under parentId and
// recurses into each organizational unit. parentArn is the parent's canonical id, used
// as the children's parent_id fact.
func (c *OrganizationsCollector) walkParent(ctx context.Context, sink collect.Sink, parentID, parentArn string, st *walkState, depth int) {
	if depth >= maxOrgPages {
		st.degraded, st.reason = true, "hierarchy depth limit reached"
		return
	}
	c.listOUs(ctx, sink, parentID, parentArn, st, depth)
	c.listAccounts(ctx, sink, parentID, parentArn, st)
}

func (c *OrganizationsCollector) listOUs(ctx context.Context, sink collect.Sink, parentID, parentArn string, st *walkState, depth int) {
	token := ""
	for page := 0; page < maxOrgPages; page++ {
		if st.exhausted || ctx.Err() != nil {
			return
		}
		if !c.budget.Spend() {
			st.exhausted = true
			return
		}
		in := &organizations.ListOrganizationalUnitsForParentInput{ParentId: &parentID}
		if token != "" {
			in.NextToken = &token
		}
		out, err := c.api.ListOrganizationalUnitsForParent(ctx, in)
		if err != nil {
			c.note(st, err)
			return
		}
		_ = sink.Evidence(c.evidence("ListOrganizationalUnitsForParent"))
		for _, ou := range out.OrganizationalUnits {
			if ou.Arn == nil {
				continue
			}
			ouArn := aws(ou.Arn)
			_ = sink.Node(collect.Node{Type: model.NodeOrganization, NativeID: ouArn, Name: aws(ou.Name),
				Attributes: pruneEmptyOrg(map[string]string{"hierarchy_type": "organizational_unit", "parent_id": parentArn})})
			st.count++
			c.walkParent(ctx, sink, aws(ou.Id), ouArn, st, depth+1)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return
		}
		token = *out.NextToken
	}
}

func (c *OrganizationsCollector) listAccounts(ctx context.Context, sink collect.Sink, parentID, parentArn string, st *walkState) {
	token := ""
	for page := 0; page < maxOrgPages; page++ {
		if st.exhausted || ctx.Err() != nil {
			return
		}
		if !c.budget.Spend() {
			st.exhausted = true
			return
		}
		in := &organizations.ListAccountsForParentInput{ParentId: &parentID}
		if token != "" {
			in.NextToken = &token
		}
		out, err := c.api.ListAccountsForParent(ctx, in)
		if err != nil {
			c.note(st, err)
			return
		}
		_ = sink.Evidence(c.evidence("ListAccountsForParent"))
		for _, acct := range out.Accounts {
			if acct.Id == nil {
				continue
			}
			// Keyed by the 12-digit account id so it merges with the account node the
			// IAM and authorization collectors emit. No email (PII) is recorded.
			_ = sink.Node(collect.Node{Type: model.NodeAccount, NativeID: aws(acct.Id), Name: aws(acct.Name),
				Attributes: pruneEmptyOrg(map[string]string{"parent_id": parentArn, "status": string(acct.Status)})})
			st.count++
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return
		}
		token = *out.NextToken
	}
}

// note records a sub-read failure as a represented gap: a denied or throttled read
// degrades the aggregate to Partial and stops that branch, never sinking the run.
func (c *OrganizationsCollector) note(st *walkState, err error) {
	st.degraded = true
	switch {
	case isDenied(err):
		st.reason = "denied"
	case isThrottle(err):
		st.reason = "throttled"
	default:
		st.reason = redact.String(err.Error())
	}
}

// isNotInOrg reports the AWSOrganizationsNotInUseException: the account is not a member
// of an organization. It is the standalone-account fact, not an access denial.
func isNotInOrg(err error) bool {
	var notInUse *orgtypes.AWSOrganizationsNotInUseException
	if errors.As(err, &notInUse) {
		return true
	}
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == "AWSOrganizationsNotInUseException"
}

// aws dereferences an AWS SDK *string, returning "" for nil.
func aws(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func pruneEmptyOrg(a map[string]string) map[string]string {
	for k, v := range a {
		if v == "" {
			delete(a, k)
		}
	}
	return a
}

func (c *OrganizationsCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *OrganizationsCollector) evidence(operation string) collect.Envelope {
	return collect.Envelope{
		Provider: model.AWS, Service: "organizations", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Provenance: collect.Provenance{APIVersion: organizationsAPIVersion, Collector: organizationsCollectorID},
	}
}

func (c *OrganizationsCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: redact.String(err.Error())}
}
