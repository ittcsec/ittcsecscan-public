package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubARM is an offline armAPI matching a request URL to a canned body by
// substring, with an optional per-resource failure.
type stubARM struct {
	bodies   map[string]string
	failSub  string
	failWith error
	calls    int
}

func (s *stubARM) get(_ context.Context, url string) ([]byte, error) {
	s.calls++
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
	ownerGUID       = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	contributorGUID = "b24988ac-6180-42a0-ab88-20f7382dd24c"

	subsOne = `{"value":[{"subscriptionId":"sub-1","displayName":"Test Sub","state":"Enabled","tenantId":"tenant-1"}]}`

	roleDefsTwo = `{"value":[
		{"name":"` + ownerGUID + `","properties":{"roleName":"Owner","type":"BuiltInRole"}},
		{"name":"` + contributorGUID + `","properties":{"roleName":"Contributor","type":"BuiltInRole"}}]}`

	assignmentsTwo = `{"value":[
		{"properties":{"principalId":"u-guid","principalType":"User","roleDefinitionId":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/` + ownerGUID + `","scope":"/subscriptions/sub-1"}},
		{"properties":{"principalId":"sp-guid","principalType":"ServicePrincipal","roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/` + contributorGUID + `","scope":"/subscriptions/sub-1/resourceGroups/rg1","condition":"@Resource[x] StringEquals 'y'"}}]}`
)

func runRBAC(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newRBACCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func nodeNamed(s collect.Scan, tp model.NodeType, native string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == tp && n.NativeID == native {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestRBACMapsAssignments proves the authorization graph: subscription, role, and
// principal nodes plus member-to-role grant edges, with role names resolved, the
// principal typed from the assignment, the role keyed by its guid (so a
// subscription-scoped and a tenant-level role id resolve to one node), and the
// assignment scope and condition carried on the edge.
func TestRBACMapsAssignments(t *testing.T) {
	s := runRBAC(t, &stubARM{bodies: map[string]string{
		"/subscriptions?":   subsOne,
		"/roleDefinitions?": roleDefsTwo,
		"/roleAssignments?": assignmentsTwo,
	}})

	if _, ok := nodeNamed(s, model.NodeSubscription, "sub-1"); !ok {
		t.Error("missing subscription node")
	}
	// Roles keyed by guid, names resolved.
	if n, ok := nodeNamed(s, model.NodeRole, ownerGUID); !ok || n.Name != "Owner" {
		t.Errorf("owner role node = %+v (ok=%v), want name Owner", n, ok)
	}
	if n, ok := nodeNamed(s, model.NodeRole, contributorGUID); !ok || n.Name != "Contributor" {
		t.Errorf("contributor role node = %+v (ok=%v), want name Contributor", n, ok)
	}
	// Principals typed from the assignment, keyed by object id (dedups with Entra).
	if _, ok := nodeNamed(s, model.NodeIdentity, "u-guid"); !ok {
		t.Error("user principal not an identity node")
	}
	if _, ok := nodeNamed(s, model.NodeWorkload, "sp-guid"); !ok {
		t.Error("service-principal principal not a workload node")
	}

	links := map[string]collect.Link{}
	for _, l := range s.Links {
		links[l.SourceNativeID+"|"+l.TargetNativeID] = l
	}
	owner := links["u-guid|"+ownerGUID]
	if owner.Kind != model.EdgeAssumes || owner.Conditions["scope"] != "/subscriptions/sub-1" {
		t.Errorf("user->owner edge = %+v, want assumes with subscription scope", owner)
	}
	contrib := links["sp-guid|"+contributorGUID]
	if contrib.Kind != model.EdgeAssumes || contrib.Conditions["scope"] != "/subscriptions/sub-1/resourceGroups/rg1" || contrib.Conditions["condition"] == "" {
		t.Errorf("sp->contributor edge = %+v, want assumes with RG scope and a condition", contrib)
	}

	for _, svc := range []string{"rbac.subscriptions", "rbac.roleDefinitions", "rbac.roleAssignments"} {
		if statusOf(s, svc) != collect.Complete {
			t.Errorf("%s status = %s, want complete", svc, statusOf(s, svc))
		}
	}
}

func TestRBACPrincipalNode(t *testing.T) {
	cases := []struct {
		ptype string
		typ   model.NodeType
	}{
		{"User", model.NodeIdentity},
		{"Group", model.NodeGroup},
		{"ForeignGroup", model.NodeGroup},
		{"ServicePrincipal", model.NodeWorkload},
		{"AgentServicePrincipal", model.NodeWorkload},
		{"Device", model.NodeEndpointDevice},
		{"Something", model.NodeIdentity},
	}
	for _, tc := range cases {
		n, ok := rbacPrincipalNode("id-1", tc.ptype)
		if !ok || n.Type != tc.typ || n.NativeID != "id-1" {
			t.Errorf("rbacPrincipalNode(%q) = (%s, %v), want %s", tc.ptype, n.Type, ok, tc.typ)
		}
	}
	if _, ok := rbacPrincipalNode("", "User"); ok {
		t.Error("an empty principal id must not produce a node")
	}
}

// TestRBACRoleDefinitionsDeniedStillCollectsAssignments proves role-name
// resolution is best-effort: if role definitions are denied, assignments still
// collect (with unresolved role names) and the denial is its own recorded gap.
func TestRBACRoleDefinitionsDeniedStillCollectsAssignments(t *testing.T) {
	var s collect.Scan
	err := newRBACCollector("tenant-1", &stubARM{
		bodies:   map[string]string{"/subscriptions?": subsOne, "/roleAssignments?": assignmentsTwo},
		failSub:  "/roleDefinitions?",
		failWith: &azureError{status: 403, body: "denied"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "rbac.roleDefinitions") != collect.Denied {
		t.Errorf("roleDefinitions status = %s, want denied", statusOf(s, "rbac.roleDefinitions"))
	}
	if statusOf(s, "rbac.roleAssignments") != collect.Complete {
		t.Errorf("roleAssignments status = %s, want complete (names unresolved but assignments collected)", statusOf(s, "rbac.roleAssignments"))
	}
	// The role node exists but unnamed, since its name could not be resolved.
	if n, ok := nodeNamed(s, model.NodeRole, ownerGUID); !ok || n.Name != "" {
		t.Errorf("owner role node = %+v (ok=%v), want present with an empty name", n, ok)
	}
}

// TestRBACSubscriptionsDeniedIsGap proves a denied subscription enumeration is a
// recorded gap with no assignments collected, not a run error.
func TestRBACSubscriptionsDeniedIsGap(t *testing.T) {
	var s collect.Scan
	err := newRBACCollector("tenant-1", &stubARM{
		failSub:  "/subscriptions?",
		failWith: &azureError{status: 403, body: "denied"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "rbac.subscriptions") != collect.Denied {
		t.Errorf("subscriptions status = %s, want denied", statusOf(s, "rbac.subscriptions"))
	}
	if len(s.Links) != 0 {
		t.Errorf("edges = %d, want 0 (no subscriptions enumerated)", len(s.Links))
	}
}

// TestRBACBudgetExhaustion proves the shared budget bites: with no budget the
// subscription enumeration is a Partial gap and no call is made.
func TestRBACBudgetExhaustion(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne}}
	c := newRBACCollector("tenant-1", api)
	c.budget = collect.NewBudget(0)
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 0 {
		t.Errorf("made %d calls under an exhausted budget; want 0", api.calls)
	}
	if statusOf(s, "rbac.subscriptions") != collect.Partial {
		t.Errorf("status = %s, want partial", statusOf(s, "rbac.subscriptions"))
	}
}

func TestRBACEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + "0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" + ".eyJ" + "hdWQiOiJhcm0ifQ" + ".sig"
	body := `{"value":[{"subscriptionId":"sub-1","displayName":"` + token + `"}]}`
	s := runRBAC(t, &stubARM{bodies: map[string]string{"/subscriptions?": body}})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
