package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// identityCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const identityCollectorID = "collector:aws.iam.identities"

// iamAPIVersion is the IAM API version, recorded as evidence provenance.
const iamAPIVersion = "2010-05-08"

// identityAPI is the read-only IAM surface the collector uses. Both calls were
// verified against the AWS API reference (2026-09-18): read-only, paginated, and
// they return no secret value (policy documents are permission JSON, not
// secrets).
type identityAPI interface {
	GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput, optFns ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	ListAccountAliases(ctx context.Context, in *iam.ListAccountAliasesInput, optFns ...func(*iam.Options)) (*iam.ListAccountAliasesOutput, error)
}

// IdentityCollector reads the AWS IAM identity and authorization graph from a
// single GetAccountAuthorizationDetails read: the account, its users, groups,
// roles, and policies, their group memberships, the managed policies attached to
// each principal, and each role's trust policy (who may assume it). The
// authorization edges come from the same response, so no extra call is made.
type IdentityCollector struct {
	account string // the account id (from the identity adapter)
	api     identityAPI
	budget  *collect.Budget  // the scan's shared call cap; nil is unlimited
	now     func() time.Time // injectable clock; nil uses time.Now
}

func (c *IdentityCollector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

// NewIdentityCollector builds the collector with a read-only IAM client from the
// adapter's resolved config (ADR-0018 §3). The config comes from the same
// credential resolution the identity adapter uses. budget is the scan's shared
// call cap (nil is unlimited).
func NewIdentityCollector(account string, cfg awssdk.Config, budget *collect.Budget) *IdentityCollector {
	return &IdentityCollector{account: account, api: iam.NewFromConfig(cfg), budget: budget}
}

// newIdentityCollector is the injectable constructor tests use with a stub API.
// It has no budget (unlimited); a test that needs one sets the field.
func newIdentityCollector(account string, api identityAPI) *IdentityCollector {
	return &IdentityCollector{account: account, api: api}
}

func (c *IdentityCollector) ID() string               { return identityCollectorID }
func (c *IdentityCollector) Provider() model.Provider { return model.AWS }

// identityRequirements are the read-only permissions this collector needs,
// credited to it. They are registered at init so the templates reconcile
// against real code (ADR-0016), and returned by Requirements for the run.
func identityRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: identityCollectorID}
	}
	return []permissions.Requirement{
		req("iam:GetAccountAuthorizationDetails"),
		req("iam:ListAccountAliases"),
	}
}

func init() {
	for _, r := range identityRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *IdentityCollector) Requirements() []permissions.Requirement { return identityRequirements() }

// Collect reads the account and its IAM identity graph, emitting nodes, links,
// evidence, and completeness. IAM is global, so there is one region: "global".
func (c *IdentityCollector) Collect(ctx context.Context, sink collect.Sink) error {
	alias := c.accountAlias(ctx, sink)
	if err := sink.Node(collect.Node{Type: model.NodeAccount, NativeID: c.account, Name: alias}); err != nil {
		return err
	}
	return c.identities(ctx, sink)
}

// accountAlias reads the account's alias, best-effort: a failure is recorded as
// completeness and leaves the account unnamed, never stopping the collection.
func (c *IdentityCollector) accountAlias(ctx context.Context, sink collect.Sink) string {
	if !c.budget.Spend() {
		_ = sink.Complete(collect.Completeness{Service: "iam.aliases", Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
		return ""
	}
	out, err := c.api.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		_ = sink.Complete(c.completeness("iam.aliases", 0, err))
		return ""
	}
	_ = sink.Evidence(c.evidence("ListAccountAliases", out))
	_ = sink.Complete(collect.Completeness{Service: "iam.aliases", Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: len(out.AccountAliases)})
	if len(out.AccountAliases) > 0 {
		return out.AccountAliases[0]
	}
	return ""
}

// identities reads the IAM identity graph, paginating fully or recording
// Partial. A denied or errored read is a completeness gap, not a silent empty.
func (c *IdentityCollector) identities(ctx context.Context, sink collect.Sink) error {
	in := &iam.GetAccountAuthorizationDetailsInput{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: "iam.identities", Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: "iam.identities", Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return nil
		}
		out, err := c.api.GetAccountAuthorizationDetails(ctx, in)
		if err != nil {
			_ = sink.Complete(c.completeness("iam.identities", count, err))
			// A denied or throttled read is an expected, represented gap
			// (Denied or Partial); an unexpected error is surfaced so the run
			// reports it. Retry-with-backoff on throttling is a noted follow-up.
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence("GetAccountAuthorizationDetails", out))
		count += c.mapPage(sink, out)
		if !out.IsTruncated {
			_ = sink.Complete(collect.Completeness{Service: "iam.identities", Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return nil
		}
		in.Marker = out.Marker
	}
}

// mapPage turns one page of authorization details into nodes and links, and
// returns the number of identities it added.
func (c *IdentityCollector) mapPage(sink collect.Sink, out *iam.GetAccountAuthorizationDetailsOutput) int {
	n := 0
	for _, u := range out.UserDetailList {
		ua := []string{"user_id", deref(u.UserId), "path", deref(u.Path)}
		ua = append(ua, principalAuthzAttrs(inlinePrivilege(u.UserPolicyList), u.PermissionsBoundary)...)
		_ = sink.Node(collect.Node{Type: model.NodeIdentity, NativeID: deref(u.Arn), Name: deref(u.UserName),
			Attributes: attrs(ua...)})
		for _, g := range u.GroupList {
			// GetAccountAuthorizationDetails gives group names, not ARNs; the
			// group node is keyed by ARN, so synthesise the ARN to join them.
			// This assumes the root path, which is the common case; pathed-group
			// linking is a noted follow-up.
			_ = sink.Link(collect.Link{SourceNativeID: deref(u.Arn), TargetNativeID: groupARN(c.account, g), Kind: model.EdgeMemberOf})
		}
		c.attachmentEdges(sink, deref(u.Arn), u.AttachedManagedPolicies)
		n++
	}
	for _, r := range out.RoleDetailList {
		path := deref(r.Path)
		ra := []string{"role_id", deref(r.RoleId), "path", path}
		// Service-linked roles live under the /aws-service-role/ path and are managed by
		// an AWS service, not an operator, so a dormancy rule should exclude them. Flag it
		// by that documented path prefix rather than guessing from the name.
		if strings.HasPrefix(path, "/aws-service-role/") {
			ra = append(ra, "service_linked", "true")
		} else {
			ra = append(ra, "service_linked", "false")
		}
		ra = append(ra, principalAuthzAttrs(inlinePrivilege(r.RolePolicyList), r.PermissionsBoundary)...)
		// RoleLastUsed is returned by GetAccountAuthorizationDetails and was previously
		// discarded; it is the dormant-role signal. AWS only tracks role activity for the
		// trailing 400 days (per Region), and omits LastUsedDate when the role has not been
		// used within that window (it may have been used earlier, or never). So an absent
		// value is recorded role_last_used "never" meaning "no activity in the trailing-400-day
		// tracking window", and role_last_used_age_days is emitted only when a real date is
		// returned (age is unknown, never zero, outside the window).
		if lu := r.RoleLastUsed; lu != nil && lu.LastUsedDate != nil {
			ra = append(ra, "role_last_used", lu.LastUsedDate.UTC().Format(time.RFC3339), "role_last_used_region", deref(lu.Region),
				"role_last_used_age_days", strconv.Itoa(ageDays(c.clock(), lu.LastUsedDate.UTC())))
		} else {
			ra = append(ra, "role_last_used", "never")
		}
		_ = sink.Node(collect.Node{Type: model.NodeRole, NativeID: deref(r.Arn), Name: deref(r.RoleName),
			Attributes: attrs(ra...)})
		c.attachmentEdges(sink, deref(r.Arn), r.AttachedManagedPolicies)
		// The trust policy names who may assume the role: the classic AWS
		// privilege-escalation and cross-account edge.
		c.trustEdges(sink, deref(r.Arn), deref(r.AssumeRolePolicyDocument))
		n++
	}
	for _, g := range out.GroupDetailList {
		ga := []string{"group_id", deref(g.GroupId), "path", deref(g.Path)}
		if lvl := inlinePrivilege(g.GroupPolicyList); lvl != "" {
			ga = append(ga, "inline_privilege", lvl)
		}
		_ = sink.Node(collect.Node{Type: model.NodeGroup, NativeID: deref(g.Arn), Name: deref(g.GroupName),
			Attributes: attrs(ga...)})
		c.attachmentEdges(sink, deref(g.Arn), g.AttachedManagedPolicies)
		n++
	}
	for _, p := range out.Policies {
		pa := []string{"policy_id", deref(p.PolicyId), "path", deref(p.Path)}
		if cls, ok := classifyPolicy(defaultPolicyDocument(p)); ok {
			pa = append(pa, "document_read", "true")
			if lvl := cls.level(); lvl != "" {
				pa = append(pa, "privilege_level", lvl)
			}
			if len(cls.escalation) > 0 {
				pa = append(pa, "escalation_actions", strings.Join(cls.escalation, ","))
			}
		}
		_ = sink.Node(collect.Node{Type: model.NodePolicy, NativeID: deref(p.Arn), Name: deref(p.PolicyName),
			Attributes: attrs(pa...)})
		n++
	}
	return n
}

func (c *IdentityCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one IAM read.
func (c *IdentityCollector) evidence(operation string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	// Defence in depth: the response carries no secret value, but it still passes
	// through redaction before it is recorded.
	redacted := json.RawMessage(redact.String(string(raw)))
	return collect.Envelope{
		Provider: model.AWS, Service: "iam", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   redacted,
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: identityCollectorID},
	}
}

// completeness classifies an IAM error into a completeness record with a
// redacted reason.
func (c *IdentityCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{
		Service: service, Region: collect.Global, Scope: c.scope(),
		Status: status, Collected: collected, Reason: redact.String(err.Error()),
	}
}

func isDenied(err error) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return true
		}
	}
	return false
}

func isThrottle(err error) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException":
			return true
		}
	}
	return false
}

func attrs(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// groupARN synthesises a root-path IAM group ARN from its name, to join a user's
// group membership (which gives names) to the group node (keyed by ARN).
func groupARN(account, name string) string {
	return "arn:aws:iam::" + account + ":group/" + name
}
