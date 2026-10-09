package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubGraph is an offline graphAPI. It matches a request URL to a canned body by
// substring, so a test drives pagination and per-resource behaviour with no
// network, no token, and no SDK. A failure can be scoped to one resource.
type stubGraph struct {
	bodies    map[string]string // url substring -> JSON body
	failSub   string            // return failWith for a URL containing this
	failWith  error
	callCount int
}

func (s *stubGraph) get(_ context.Context, url string) ([]byte, error) {
	s.callCount++
	if s.failWith != nil && s.failSub != "" && strings.Contains(url, s.failSub) {
		return nil, s.failWith
	}
	for sub, body := range s.bodies {
		if strings.Contains(url, sub) {
			return []byte(body), nil
		}
	}
	return []byte(`{"value":[]}`), nil
}

const (
	usersOnePage = `{"value":[
		{"id":"u1","displayName":"Alice","userPrincipalName":"alice@contoso.com","accountEnabled":true},
		{"id":"u2","displayName":"Bob","userPrincipalName":"bob@contoso.com","accountEnabled":false}]}`
	groupsOnePage = `{"value":[{"id":"g1","displayName":"Admins","securityEnabled":true}]}`
	spsOnePage    = `{"value":[{"id":"sp1","appId":"app-1","displayName":"CI Runner","servicePrincipalType":"Application"}]}`
)

func run(t *testing.T, api graphAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	err := newIdentityCollector("tenant-1", api).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func nodesByType(s collect.Scan) map[model.NodeType]int {
	m := map[model.NodeType]int{}
	for _, n := range s.Nodes {
		m[n.Type]++
	}
	return m
}

// TestCollectMapsEntraGraph proves the three Entra reads become the tenant node
// plus users (identity), groups, and service principals, with service principals
// mapped to workload (machine identity) nodes, and every enumeration Complete.
func TestCollectMapsEntraGraph(t *testing.T) {
	s := run(t, &stubGraph{bodies: map[string]string{
		"/users?":             usersOnePage,
		"/groups?":            groupsOnePage,
		"/servicePrincipals?": spsOnePage,
	}})

	byType := nodesByType(s)
	if byType[model.NodeTenant] != 1 {
		t.Errorf("tenant nodes = %d, want 1", byType[model.NodeTenant])
	}
	if byType[model.NodeIdentity] != 2 {
		t.Errorf("identity (user) nodes = %d, want 2", byType[model.NodeIdentity])
	}
	if byType[model.NodeGroup] != 1 {
		t.Errorf("group nodes = %d, want 1", byType[model.NodeGroup])
	}
	// The approved mapping: a service principal is machine identity, a workload,
	// not a human identity.
	if byType[model.NodeWorkload] != 1 {
		t.Errorf("workload (service principal) nodes = %d, want 1", byType[model.NodeWorkload])
	}
	if byType[model.NodeIdentity] != 2 || byType[model.NodeWorkload] != 1 {
		t.Error("service principals must not be counted as human identities")
	}
	// Users, groups, service principals, and the group-member expansion.
	if len(s.Completeness) != 4 {
		t.Fatalf("completeness records = %d, want 4", len(s.Completeness))
	}
	for _, c := range s.Completeness {
		if !c.Done() {
			t.Errorf("%s not Complete: %s", c.Service, c.Status)
		}
		if c.Scope.Account != "tenant-1" {
			t.Errorf("%s scope account = %q, want tenant-1", c.Service, c.Scope.Account)
		}
	}
	if statusOf(s, "entra.groupMembers") != collect.Complete {
		t.Errorf("group-member expansion status = %s, want complete", statusOf(s, "entra.groupMembers"))
	}
	// One evidence envelope per read: the three lists plus the one group's members.
	if len(s.Envelopes) != 4 {
		t.Errorf("evidence envelopes = %d, want 4", len(s.Envelopes))
	}
}

// TestExpandGroupMembers proves group-member expansion: each group's direct
// members become member-of edges, typed from @odata.type and keyed by object id
// so they dedup with the identity pass.
func TestExpandGroupMembers(t *testing.T) {
	s := run(t, &stubGraph{bodies: map[string]string{
		"/groups?":   `{"value":[{"id":"g1","displayName":"Admins"}]}`,
		"g1/members": `{"value":[{"id":"u1","@odata.type":"#microsoft.graph.user"},{"id":"nested","@odata.type":"#microsoft.graph.group"}]}`,
	}})

	edges := map[string]collect.Link{}
	for _, l := range s.Links {
		edges[l.SourceNativeID+"|"+l.TargetNativeID] = l
	}
	if e := edges["u1|g1"]; e.Kind != model.EdgeMemberOf {
		t.Errorf("missing user member-of edge: %+v", e)
	}
	if e := edges["nested|g1"]; e.Kind != model.EdgeMemberOf {
		t.Errorf("missing nested-group member-of edge: %+v", e)
	}
	if _, ok := nodeNamed(s, model.NodeIdentity, "u1"); !ok {
		t.Error("user member not an identity node")
	}
	if _, ok := nodeNamed(s, model.NodeGroup, "nested"); !ok {
		t.Error("nested-group member not a group node")
	}
	if c := completenessOf(s, "entra.groupMembers"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("group-member completeness = %+v, want complete with 2", c)
	}
}

// TestGroupMembersDeniedIsGapNotFatal proves one group's denied membership is a
// recorded Partial gap, not a run error, and does not stop the identity reads.
func TestGroupMembersDeniedIsGapNotFatal(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("tenant-1", &stubGraph{
		bodies:   map[string]string{"/groups?": `{"value":[{"id":"g1"}]}`},
		failSub:  "g1/members",
		failWith: &azureError{status: 403, body: "denied"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("a denied group membership must not fail the run: %v", err)
	}
	if c := completenessOf(s, "entra.groupMembers"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("group-member completeness = %+v, want partial denied", c)
	}
	if statusOf(s, "entra.groups") != collect.Complete {
		t.Errorf("groups status = %s, want complete", statusOf(s, "entra.groups"))
	}
}

// TestGroupMembersBudgetExhaustion proves the N+1 expansion respects the shared
// budget: with budget only for the three lists, the membership expansion is a
// Partial "budget exhausted" gap.
func TestGroupMembersBudgetExhaustion(t *testing.T) {
	c := newIdentityCollector("tenant-1", &stubGraph{bodies: map[string]string{"/groups?": `{"value":[{"id":"g1"}]}`}})
	c.budget = collect.NewBudget(3) // users + groups + servicePrincipals, nothing left for members
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "entra.groupMembers"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("group-member completeness = %+v, want partial budget-exhausted", got)
	}
}

func TestMemberNode(t *testing.T) {
	cases := []struct {
		odata string
		typ   model.NodeType
	}{
		{"#microsoft.graph.user", model.NodeIdentity},
		{"#microsoft.graph.group", model.NodeGroup},
		{"#microsoft.graph.servicePrincipal", model.NodeWorkload},
		{"#microsoft.graph.device", model.NodeEndpointDevice},
		{"#microsoft.graph.orgContact", model.NodeIdentity},
		{"", model.NodeIdentity},
	}
	for _, tc := range cases {
		if n := memberNode(tc.odata, "id-1"); n.Type != tc.typ || n.NativeID != "id-1" {
			t.Errorf("memberNode(%q) = (%s), want %s", tc.odata, n.Type, tc.typ)
		}
	}
}

// TestCollectFollowsNextLink proves pagination: a users page with an
// @odata.nextLink is followed to completion.
func TestCollectFollowsNextLink(t *testing.T) {
	s := run(t, &stubGraph{bodies: map[string]string{
		"/users?":     `{"value":[{"id":"u1","displayName":"Alice"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/users-next"}`,
		"users-next":  `{"value":[{"id":"u2","displayName":"Bob"}]}`,
		"/groups?":    groupsOnePage,
		"servicePrin": spsOnePage,
	}})
	if got := nodesByType(s)[model.NodeIdentity]; got != 2 {
		t.Errorf("identity nodes across pages = %d, want 2", got)
	}
	for _, c := range s.Completeness {
		if c.Service == "entra.users" && !c.Done() {
			t.Errorf("paginated users not Complete: %s", c.Status)
		}
	}
}

// TestCollectPageLimitStopsRunawayPagination proves the collector bounds
// pagination: a resource that returns an @odata.nextLink forever is stopped at
// the page limit and recorded as Partial, never followed into a hang.
func TestCollectPageLimitStopsRunawayPagination(t *testing.T) {
	loop := `{"value":[{"id":"u1"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/users-loop"}`
	api := &stubGraph{bodies: map[string]string{
		"/users?":    loop,
		"users-loop": loop,
	}}
	var s collect.Scan
	if err := newIdentityCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "entra.users") != collect.Partial {
		t.Errorf("users status = %s, want partial (page limit reached)", statusOf(s, "entra.users"))
	}
	if api.callCount > maxPages+3 { // users hits the cap, then groups and servicePrincipals
		t.Errorf("made %d API calls; must stop at the page limit (%d)", api.callCount, maxPages)
	}
}

// TestCollectBudgetExhaustionAcrossResources proves the shared budget bites
// first-come-first-served across a provider's resources: with budget for one
// resource, users completes and the later resources are recorded Partial "budget
// exhausted", never silently skipped.
func TestCollectBudgetExhaustionAcrossResources(t *testing.T) {
	api := &stubGraph{bodies: map[string]string{
		"/users?":             usersOnePage,
		"/groups?":            groupsOnePage,
		"/servicePrincipals?": spsOnePage,
	}}
	c := newIdentityCollector("tenant-1", api)
	c.budget = collect.NewBudget(1)

	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.callCount != 1 {
		t.Errorf("made %d calls under a 1-call budget; want 1", api.callCount)
	}
	if statusOf(s, "entra.users") != collect.Complete {
		t.Errorf("users status = %s, want complete (it got the one call)", statusOf(s, "entra.users"))
	}
	for _, service := range []string{"entra.groups", "entra.servicePrincipals"} {
		var got collect.Completeness
		for _, comp := range s.Completeness {
			if comp.Service == service {
				got = comp
			}
		}
		if got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial with reason budget exhausted", service, got)
		}
	}
}

// TestCollectDeniedIsGapNotError proves a 403 on one resource is a recorded
// Denied gap, not a run error, and does not stop the other resources.
func TestCollectDeniedIsGapNotError(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("tenant-1", &stubGraph{
		bodies:   map[string]string{"/groups?": groupsOnePage, "servicePrin": spsOnePage},
		failSub:  "/users?",
		failWith: &azureError{status: 403, body: "Authorization_RequestDenied"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("denied read must not surface as a run error: %v", err)
	}
	if statusOf(s, "entra.users") != collect.Denied {
		t.Errorf("users status = %s, want denied", statusOf(s, "entra.users"))
	}
	if statusOf(s, "entra.groups") != collect.Complete {
		t.Errorf("groups status = %s, want complete (a peer's denial must not block it)", statusOf(s, "entra.groups"))
	}
}

// TestCollectThrottleIsPartial proves a 429 is a represented Partial gap, not an
// error, and does not stop the other resources.
func TestCollectThrottleIsPartial(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("tenant-1", &stubGraph{
		bodies:   map[string]string{"/groups?": groupsOnePage},
		failSub:  "/users?",
		failWith: &azureError{status: 429, body: "throttled"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("throttle must not surface as a run error: %v", err)
	}
	if statusOf(s, "entra.users") != collect.Partial {
		t.Errorf("users status = %s, want partial", statusOf(s, "entra.users"))
	}
}

// TestCollectUnexpectedErrorSurfaces proves an unexpected failure (500) is
// recorded as Errored and surfaced as a run error, never swallowed into a pass.
func TestCollectUnexpectedErrorSurfaces(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("tenant-1", &stubGraph{
		failSub:  "/users?",
		failWith: &azureError{status: 500, body: "server error"},
	}).Collect(context.Background(), &s)
	if err == nil {
		t.Fatal("unexpected error must surface")
	}
	if statusOf(s, "entra.users") != collect.Errored {
		t.Errorf("users status = %s, want error", statusOf(s, "entra.users"))
	}
}

// TestEvidenceRedactsToken proves the evidence body is scrubbed: a JWT that
// somehow appears in a response is redacted before it is recorded.
func TestEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + "0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" + ".eyJ" + "hdWQiOiJncmFwaCJ9" + ".sig"
	body := `{"value":[{"id":"u1","displayName":"` + token + `"}]}`
	s := run(t, &stubGraph{bodies: map[string]string{"/users?": body}})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}

func statusOf(s collect.Scan, service string) collect.Status {
	for _, c := range s.Completeness {
		if c.Service == service {
			return c.Status
		}
	}
	return ""
}

func completenessOf(s collect.Scan, service string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service {
			return c
		}
	}
	return collect.Completeness{}
}
