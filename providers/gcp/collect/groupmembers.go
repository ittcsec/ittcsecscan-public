package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// membershipCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const membershipCollectorID = "collector:gcp.cloudidentity.groupMembers"

const (
	// ciBaseURL is the Cloud Identity v1 REST endpoint. The collector only ever
	// issues GETs against the two read-only resources below (groups:lookup and
	// groups.memberships.list).
	ciBaseURL = "https://cloudidentity.googleapis.com/v1"
	// ciAPIVersion is recorded as evidence provenance.
	ciAPIVersion = "v1"
	// membershipPageSize is the memberships page size the collector requests. The
	// BASIC view allows up to 1000; 500 keeps a page bounded while cutting round
	// trips (Cloud Identity groups.memberships.list reference, verified 2026-09-19).
	membershipPageSize = 500
)

// cloudIdentityAPI is the read-only Cloud Identity surface the collector uses:
// fetch a lookup or memberships URL and return the raw JSON body. It is an
// interface so tests inject a stub and never touch the network, a real token, or
// the client libraries.
type cloudIdentityAPI interface {
	get(ctx context.Context, url string) ([]byte, error)
}

// GroupMembershipCollector expands the direct membership of the Google Groups
// that hold a role binding on the project, so a principal's roles through group
// membership are visible in the attack graph (the same gap the Azure Entra
// collector closes for tenants).
//
// It first reads the project IAM allow policy to learn which groups hold bindings
// (the groups that matter for the graph), then for each group resolves its
// resource name (groups:lookup) and lists its direct members
// (groups.memberships.list), emitting each member as a node keyed by its email
// (so it dedups with the IAM-policy and service-account nodes) and a member-of
// edge to the group.
//
// The reads were verified against the Cloud Identity API reference (v1,
// 2026-09-19): groups:lookup and groups.memberships.list are read-only GETs,
// memberships paginated by pageToken/nextPageToken, returning no secret value.
//
// Authorization note: Cloud Identity is organization- and domain-scoped, not
// project-scoped. Listing a group's memberships requires the caller to hold "View
// Membership" on that group (the Cloud Identity Groups Reader IAM role at the
// organization, a Workspace groups-admin role, or membership of the group
// itself). A project service account granted only project-level IAM roles will
// typically be denied here; that is recorded as a Denied gap, never a silent
// empty. The OAuth cloud-platform scope the scan already requests is an accepted
// scope for these endpoints, so no new scope is needed, only the org-scoped
// permission.
type GroupMembershipCollector struct {
	projectID string
	policy    policyAPI        // to discover which groups hold project role bindings
	ci        cloudIdentityAPI // to resolve and expand each group's membership
	budget    *collect.Budget  // the scan's shared call cap; nil is unlimited
}

// NewGroupMembershipCollector builds the collector with REST clients that
// authenticate with a token from the adapter's resolved credential (ADR-0018 §3).
// budget is the scan's shared call cap (nil is unlimited).
func NewGroupMembershipCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *GroupMembershipCollector {
	return &GroupMembershipCollector{
		projectID: projectID,
		policy:    &gcpPolicyClient{tokens: tokens, http: sharedHTTPClient},
		ci:        &cloudIdentityClient{tokens: tokens, http: sharedHTTPClient},
		budget:    budget,
	}
}

// newGroupMembershipCollector is the injectable constructor tests use with stub
// APIs. It has no budget (unlimited); a test that needs one sets the field.
func newGroupMembershipCollector(projectID string, policy policyAPI, ci cloudIdentityAPI) *GroupMembershipCollector {
	return &GroupMembershipCollector{projectID: projectID, policy: policy, ci: ci}
}

func (c *GroupMembershipCollector) ID() string               { return membershipCollectorID }
func (c *GroupMembershipCollector) Provider() model.Provider { return model.GCP }

// membershipRequirements are the read-only permissions this collector needs,
// credited to it. getIamPolicy discovers the groups that hold bindings; the two
// Cloud Identity permissions resolve and list each group's members. They are the
// least-privileged permission for each call (Cloud Identity Groups Reader role,
// verified 2026-09-19), registered at init so the templates reconcile against
// real code (ADR-0016).
func membershipRequirements() []permissions.Requirement {
	r := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: membershipCollectorID}
	}
	return []permissions.Requirement{
		r("resourcemanager.projects.getIamPolicy"),
		r("cloudidentity.groups.get"),
		r("cloudidentity.groups.memberships.list"),
	}
}

func init() {
	for _, r := range membershipRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *GroupMembershipCollector) Requirements() []permissions.Requirement {
	return membershipRequirements()
}

// Collect reads the project IAM policy to find the groups that hold bindings,
// then expands each group's direct membership. Cloud Identity is a global read,
// so there is one region: "global". The whole expansion is one completeness
// record: an unreadable IAM policy, a disabled Cloud Identity API, or a
// membership denial each become a represented gap rather than a silent hole.
func (c *GroupMembershipCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "cloudidentity.groupMembers"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{
			Service: service, Region: collect.Global, Scope: c.scope(),
			Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to",
		})
	}
	if !c.budget.Spend() {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"})
	}
	body, err := c.policy.getIamPolicy(ctx, c.projectID)
	if err != nil {
		_ = sink.Complete(c.completeness(service, 0, err))
		if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
			return nil
		}
		return err
	}
	_ = sink.Evidence(c.evidence("resourcemanager", "getIamPolicy", crmAPIVersion, body))
	var policy iamPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Reason: redact.String(err.Error())})
		return fmt.Errorf("%s: decoding policy: %w", service, err)
	}
	return c.expand(ctx, sink, service, groupEmails(policy))
}

// expand resolves and lists each group's direct membership, emitting member nodes
// and member-of edges, and records one completeness for the whole pass. This is
// the scan's most call-heavy step (a lookup plus a members page per group), so
// the shared budget bounds it: when it is exhausted the remaining groups are a
// Partial "budget exhausted" gap, never silently skipped. A single group's
// denied, not-found, or errored read is a recorded gap that does not stop the
// others; a disabled Cloud Identity API is a global condition, so it stops the
// pass and is recorded Unsupported. A batched or transitive read
// (searchTransitiveMemberships) to cut round-trips and follow nested groups that
// hold no binding is a noted follow-up.
func (c *GroupMembershipCollector) expand(ctx context.Context, sink collect.Sink, service string, groups []string) error {
	total := 0
	reason := ""
	disabled := false
	for _, email := range groups {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: total, Reason: "cancelled"})
			return err
		}
		n, gap := c.groupMembers(ctx, sink, email)
		total += n
		if gap != "" {
			reason = gap
			if gap == "budget exhausted" {
				break
			}
			if gap == "api disabled" {
				disabled = true
				break
			}
		}
	}
	status := collect.Complete
	switch {
	case disabled:
		status = collect.Unsupported
	case reason != "":
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: total, Reason: reason})
}

// groupMembers resolves one group's resource name from its email, then lists its
// direct members, emitting each as a node (typed from its membership type) and a
// member-of edge to the group (keyed by the group's email, matching the group
// node the IAM-policy collector emits). It returns how many members it emitted
// and, if the read did not fully complete, the reason. One group's failure is
// never fatal to the rest.
func (c *GroupMembershipCollector) groupMembers(ctx context.Context, sink collect.Sink, email string) (int, string) {
	if !c.budget.Spend() {
		return 0, "budget exhausted"
	}
	lookupURL := ciBaseURL + "/groups:lookup?groupKey.id=" + url.QueryEscape(email)
	body, err := c.ci.get(ctx, lookupURL)
	if err != nil {
		return 0, membershipGap(err)
	}
	_ = sink.Evidence(c.evidence("cloudidentity", "groups.lookup", ciAPIVersion, body))
	var lk struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &lk); err != nil {
		return 0, redact.String(err.Error())
	}
	if lk.Name == "" {
		// Not a Cloud Identity group we can enumerate (for example an external or
		// consumer group named in the policy): a represented gap, not an empty pass.
		return 0, "not found"
	}

	base := fmt.Sprintf("%s/%s/memberships?view=BASIC&pageSize=%d", ciBaseURL, lk.Name, membershipPageSize)
	pageToken := ""
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return count, "page limit reached"
		}
		if !c.budget.Spend() {
			// The lookup above spent one call; every members page is its own call
			// and is charged too. Exhaustion here (after a successful lookup) is an
			// honest partial: the group resolved but its members could not be listed.
			return count, "budget exhausted"
		}
		u := base
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.ci.get(ctx, u)
		if err != nil {
			return count, membershipGap(err)
		}
		_ = sink.Evidence(c.evidence("cloudidentity", "memberships.list", ciAPIVersion, body))
		var mp membershipPage
		if err := json.Unmarshal(body, &mp); err != nil {
			return count, redact.String(err.Error())
		}
		for _, m := range mp.Memberships {
			id := m.PreferredMemberKey.ID
			if id == "" {
				continue
			}
			_ = sink.Node(membershipMemberNode(m.Type, id))
			_ = sink.Link(collect.Link{SourceNativeID: id, TargetNativeID: email, Kind: model.EdgeMemberOf})
			count++
		}
		if mp.NextPageToken == "" {
			return count, ""
		}
		pageToken = mp.NextPageToken
	}
}

// membershipPage is the subset of the groups.memberships.list response the
// collector reads. preferredMemberKey.id is the member's email (for a user,
// service account, or nested group), which is the native id the IAM-policy and
// service-account collectors also key on, so the views merge at ingest.
type membershipPage struct {
	Memberships []struct {
		Name               string `json:"name"`
		PreferredMemberKey struct {
			ID        string `json:"id"`
			Namespace string `json:"namespace"`
		} `json:"preferredMemberKey"`
		Type string `json:"type"`
	} `json:"memberships"`
	NextPageToken string `json:"nextPageToken"`
}

// membershipMemberNode maps a membership to a node, keyed by its email so it
// dedups with the identity and IAM-policy passes, typed from the membership type.
// An unrecognized type is never dropped: it becomes an identity with its raw type
// recorded.
func membershipMemberNode(memberType, id string) collect.Node {
	switch memberType {
	case "SERVICE_ACCOUNT":
		return collect.Node{Type: model.NodeWorkload, NativeID: id}
	case "GROUP":
		// A nested group; keyed by email so it merges with the group node the
		// IAM-policy collector emits. It is expanded further only if it also holds
		// a binding (transitive expansion is a noted follow-up).
		return collect.Node{Type: model.NodeGroup, NativeID: id}
	case "CHROME_OS_DEVICE":
		return collect.Node{Type: model.NodeEndpointDevice, NativeID: id}
	case "USER":
		return collect.Node{Type: model.NodeIdentity, NativeID: id}
	default: // SHARED_DRIVE, CBCM_BROWSER, OTHER, or unspecified
		return collect.Node{Type: model.NodeIdentity, NativeID: id, Attributes: attrs("member_type", memberType)}
	}
}

// groupEmails returns the deduplicated emails of the Google Groups that hold a
// role binding on the project, the set worth expanding. Only "group:" members are
// Cloud Identity groups resolvable by email; domain, principalSet, and other
// member forms are not directly listable and are left to compose in the graph
// from their own bindings.
func groupEmails(policy iamPolicy) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			rest, ok := strings.CutPrefix(m, "group:")
			if !ok || rest == "" || seen[rest] {
				continue
			}
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out
}

// membershipGap classifies a Cloud Identity error into a per-group gap reason. A
// disabled API is a global condition the caller stops on; a denial, throttle, or
// not-found is a per-group gap that does not stop the other groups.
func membershipGap(err error) string {
	switch {
	case isServiceDisabled(err):
		return "api disabled"
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	var ge *gcpError
	if errors.As(err, &ge) && ge.status == http.StatusNotFound {
		return "not found"
	}
	return redact.String(err.Error())
}

func (c *GroupMembershipCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

// evidence builds a redacted, secret-free envelope for one read. The service and
// api version differ across this collector's two APIs (Cloud Resource Manager for
// the policy read, Cloud Identity for the membership reads), so both are passed.
func (c *GroupMembershipCollector) evidence(service, operation, apiVersion string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: service, Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: membershipCollectorID},
	}
}

// completeness classifies a GCP error into a completeness record with a redacted
// reason (used for the initial policy read).
func (c *GroupMembershipCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
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

// cloudIdentityClient is the production cloudIdentityAPI: it authenticates with a
// bearer token from the shared token source and issues read-only GETs.
type cloudIdentityClient struct {
	tokens oauth2.TokenSource
	http   *http.Client
}

func (g *cloudIdentityClient) get(ctx context.Context, url string) ([]byte, error) {
	return gcpDo(ctx, g.http, g.tokens, http.MethodGet, url, nil)
}
