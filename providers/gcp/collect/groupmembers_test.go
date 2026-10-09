package collect

import (
	"context"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/ingest"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// oneGroupBinding is a project IAM policy whose only group member is eng@; the
// membership collector expands exactly that group.
const oneGroupBinding = `{"bindings":[
	{"role":"roles/viewer","members":["user:alice@example.com","group:eng@example.com"]}]}`

// engMembers is a groups.memberships.list page: a user, a service account, and a
// nested group, each keyed by email in preferredMemberKey.id.
const engMembers = `{"memberships":[
	{"name":"groups/1/memberships/a","preferredMemberKey":{"id":"bob@example.com"},"type":"USER"},
	{"name":"groups/1/memberships/b","preferredMemberKey":{"id":"ci@p.iam.gserviceaccount.com"},"type":"SERVICE_ACCOUNT"},
	{"name":"groups/1/memberships/c","preferredMemberKey":{"id":"leads@example.com"},"type":"GROUP"}]}`

func runMembers(t *testing.T, project string, policy policyAPI, ci cloudIdentityAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newGroupMembershipCollector(project, policy, ci).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func completenessOf(s collect.Scan, service string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service {
			return c
		}
	}
	return collect.Completeness{}
}

func hasNode(s collect.Scan, tp model.NodeType, native string) bool {
	for _, n := range s.Nodes {
		if n.Type == tp && n.NativeID == native {
			return true
		}
	}
	return false
}

// TestGroupMembershipExpands proves the expansion: the group that holds a binding
// is resolved and its direct members become member-of edges to the group (keyed
// by the group's email), each typed from its membership type, with the pass
// Complete.
func TestGroupMembershipExpands(t *testing.T) {
	s := runMembers(t, "proj",
		&stubPolicy{body: oneGroupBinding},
		&stubGCP{bodies: map[string]string{
			"lookup":      `{"name":"groups/1"}`,
			"memberships": engMembers,
		}})

	edges := map[string]collect.Link{}
	for _, l := range s.Links {
		edges[l.SourceNativeID+"|"+l.TargetNativeID] = l
	}
	for _, member := range []string{"bob@example.com", "ci@p.iam.gserviceaccount.com", "leads@example.com"} {
		if e := edges[member+"|eng@example.com"]; e.Kind != model.EdgeMemberOf {
			t.Errorf("missing member-of edge %s -> eng@example.com: %+v", member, e)
		}
	}
	if !hasNode(s, model.NodeIdentity, "bob@example.com") {
		t.Error("user member not an identity node")
	}
	if !hasNode(s, model.NodeWorkload, "ci@p.iam.gserviceaccount.com") {
		t.Error("service-account member not a workload node")
	}
	if !hasNode(s, model.NodeGroup, "leads@example.com") {
		t.Error("nested-group member not a group node")
	}
	if c := completenessOf(s, "cloudidentity.groupMembers"); c.Status != collect.Complete || c.Collected != 3 {
		t.Errorf("completeness = %+v, want complete with 3", c)
	}
}

// TestGroupMembershipPaginates proves nextPageToken is followed across membership
// pages to completion.
func TestGroupMembershipPaginates(t *testing.T) {
	s := runMembers(t, "proj",
		&stubPolicy{body: oneGroupBinding},
		&stubGCP{bodies: map[string]string{
			"lookup":      `{"name":"groups/1"}`,
			"memberships": `{"memberships":[{"preferredMemberKey":{"id":"bob@example.com"},"type":"USER"}],"nextPageToken":"pg2"}`,
			"pg2":         `{"memberships":[{"preferredMemberKey":{"id":"carol@example.com"},"type":"USER"}]}`,
		}})
	if !hasNode(s, model.NodeIdentity, "bob@example.com") || !hasNode(s, model.NodeIdentity, "carol@example.com") {
		t.Error("members across pages not all collected")
	}
	if c := completenessOf(s, "cloudidentity.groupMembers"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("completeness = %+v, want complete with 2", c)
	}
}

// TestGroupMembershipDeniedIsGapNotFatal proves one group's denied membership is a
// recorded Partial gap, not a run error: the group resolved but its members could
// not be listed.
func TestGroupMembershipDeniedIsGapNotFatal(t *testing.T) {
	var s collect.Scan
	err := newGroupMembershipCollector("proj",
		&stubPolicy{body: oneGroupBinding},
		&stubGCP{
			bodies:   map[string]string{"lookup": `{"name":"groups/1"}`},
			failSub:  "memberships",
			failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"},
		}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("a denied membership must not fail the run: %v", err)
	}
	if c := completenessOf(s, "cloudidentity.groupMembers"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("completeness = %+v, want partial denied", c)
	}
}

// TestGroupMembershipApiDisabledIsUnsupported proves a disabled Cloud Identity API
// is a global condition: the pass stops and is recorded Unsupported (enable the
// API), not Partial and not a run error.
func TestGroupMembershipApiDisabledIsUnsupported(t *testing.T) {
	var s collect.Scan
	err := newGroupMembershipCollector("proj",
		&stubPolicy{body: oneGroupBinding},
		&stubGCP{
			failSub:  "lookup",
			failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud Identity API is not enabled"},
		}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("service-disabled must not surface as a run error: %v", err)
	}
	if statusOf(s, "cloudidentity.groupMembers") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "cloudidentity.groupMembers"))
	}
}

// TestGroupMembershipBudgetExhaustion proves the shared budget bounds the N+1
// expansion: with budget only for the policy read, the expansion is a Partial
// "budget exhausted" gap and no Cloud Identity call is made.
func TestGroupMembershipBudgetExhaustion(t *testing.T) {
	ci := &stubGCP{bodies: map[string]string{"lookup": `{"name":"groups/1"}`, "memberships": engMembers}}
	c := newGroupMembershipCollector("proj", &stubPolicy{body: oneGroupBinding}, ci)
	c.budget = collect.NewBudget(1) // enough for the policy read, nothing for membership
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ci.calls != 0 {
		t.Errorf("made %d Cloud Identity calls under an exhausted budget; want 0", ci.calls)
	}
	if got := completenessOf(s, "cloudidentity.groupMembers"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("completeness = %+v, want partial budget-exhausted", got)
	}
}

// TestGroupMembershipNoGroupsIsComplete proves a policy with no group members
// makes no Cloud Identity call and records a clean Complete with nothing to
// expand.
func TestGroupMembershipNoGroupsIsComplete(t *testing.T) {
	ci := &stubGCP{}
	s := runMembers(t, "proj",
		&stubPolicy{body: `{"bindings":[{"role":"roles/viewer","members":["user:alice@example.com"]}]}`},
		ci)
	if ci.calls != 0 {
		t.Errorf("made %d Cloud Identity calls with no group members; want 0", ci.calls)
	}
	if c := completenessOf(s, "cloudidentity.groupMembers"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("completeness = %+v, want complete with 0", c)
	}
}

// TestGroupMembershipPolicyDeniedIsGap proves the whole domain is a recorded gap
// when the IAM policy that seeds it cannot be read, not a silent empty.
func TestGroupMembershipPolicyDeniedIsGap(t *testing.T) {
	var s collect.Scan
	err := newGroupMembershipCollector("proj",
		&stubPolicy{err: &gcpError{status: 403, body: "PERMISSION_DENIED"}},
		&stubGCP{}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("denied policy read must not fail the run: %v", err)
	}
	if statusOf(s, "cloudidentity.groupMembers") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "cloudidentity.groupMembers"))
	}
}

func TestGroupMembershipEmptyProjectIsUnsupported(t *testing.T) {
	policy := &stubPolicy{}
	ci := &stubGCP{}
	var s collect.Scan
	if err := newGroupMembershipCollector("", policy, ci).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if policy.calls != 0 || ci.calls != 0 {
		t.Errorf("made calls with no project (policy=%d ci=%d); want 0", policy.calls, ci.calls)
	}
	if statusOf(s, "cloudidentity.groupMembers") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "cloudidentity.groupMembers"))
	}
}

func TestMembershipMemberNode(t *testing.T) {
	cases := []struct {
		memberType string
		typ        model.NodeType
	}{
		{"USER", model.NodeIdentity},
		{"SERVICE_ACCOUNT", model.NodeWorkload},
		{"GROUP", model.NodeGroup},
		{"CHROME_OS_DEVICE", model.NodeEndpointDevice},
		{"SHARED_DRIVE", model.NodeIdentity},
		{"OTHER", model.NodeIdentity},
		{"", model.NodeIdentity},
	}
	for _, tc := range cases {
		if n := membershipMemberNode(tc.memberType, "id-1"); n.Type != tc.typ || n.NativeID != "id-1" {
			t.Errorf("membershipMemberNode(%q) = (%s), want %s", tc.memberType, n.Type, tc.typ)
		}
	}
	// An unrecognized type keeps its raw form as an attribute so it is not silently
	// mislabeled.
	if n := membershipMemberNode("SHARED_DRIVE", "id-1"); n.Attributes["member_type"] != "SHARED_DRIVE" {
		t.Errorf("unrecognized member type not recorded: %v", n.Attributes)
	}
}

// TestGroupEmails proves only group: members are selected for expansion and that
// they are deduplicated across bindings.
func TestGroupEmails(t *testing.T) {
	policy := iamPolicy{}
	policy.Bindings = []struct {
		Role      string   `json:"role"`
		Members   []string `json:"members"`
		Condition *struct {
			Title      string `json:"title"`
			Expression string `json:"expression"`
		} `json:"condition"`
	}{
		{Role: "roles/viewer", Members: []string{"group:eng@example.com", "user:a@example.com", "domain:example.com"}},
		{Role: "roles/editor", Members: []string{"group:eng@example.com", "group:ops@example.com", "principalSet://x"}},
	}
	got := groupEmails(policy)
	if len(got) != 2 {
		t.Fatalf("groupEmails = %v, want the two distinct group emails", got)
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	if !seen["eng@example.com"] || !seen["ops@example.com"] {
		t.Errorf("groupEmails = %v, want eng@ and ops@ only", got)
	}
}

// TestGroupMembershipClosesUserToRolePath proves the gap this collector exists to
// close, end to end through the real collectors, ingest, and store: a user who
// holds a role only through group membership. The IAM policy grants a role to a
// group; the membership collector expands the group to the user. After ingest,
// both the user -> group member-of edge and the group -> role assumes edge resolve
// (no dropped edges), so the path user -> group -> role exists in the graph.
func TestGroupMembershipClosesUserToRolePath(t *testing.T) {
	const binding = `{"bindings":[{"role":"roles/editor","members":["group:eng@example.com"]}]}`

	var scan collect.Scan
	cols := []collect.Collector{
		newPolicyCollector("proj", &stubPolicy{body: binding}),
		newGroupMembershipCollector("proj",
			&stubPolicy{body: binding},
			&stubGCP{bodies: map[string]string{
				"lookup":      `{"name":"groups/1"}`,
				"memberships": `{"memberships":[{"preferredMemberKey":{"id":"alice@example.com"},"type":"USER"}]}`,
			}}),
	}
	if err := collect.Run(context.Background(), cols, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	now := time.Now().UTC()
	in := ingest.ToStore(scan, ingest.Meta{ToolVersion: "v", Provider: model.GCP, Started: now, Completed: now})
	res, err := newTenant(t).Ingest(context.Background(), in)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.DroppedEdges != 0 {
		t.Errorf("dropped edges = %d, want 0 (user -> group -> role path resolves end to end)", res.DroppedEdges)
	}
}
