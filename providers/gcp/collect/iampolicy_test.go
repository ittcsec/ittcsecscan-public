package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubPolicy is an offline policyAPI returning a canned body or error. roles maps
// a role name to its roles.get body; a role not in the map returns an empty
// definition (no permissions), so tests that do not exercise privilege get roles
// with no privilege_level fact. roleErr, when set, fails every roles.get.
type stubPolicy struct {
	body     string
	err      error
	calls    int
	roles    map[string]string
	roleErr  error
	roleGets int
	deny     string
	denyErr  error
}

func (s *stubPolicy) getIamPolicy(context.Context, string) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.body), nil
}

func (s *stubPolicy) getRole(_ context.Context, roleName string) ([]byte, error) {
	s.roleGets++
	if s.roleErr != nil {
		return nil, s.roleErr
	}
	if b, ok := s.roles[roleName]; ok {
		return []byte(b), nil
	}
	return []byte(`{"includedPermissions":[]}`), nil
}

func (s *stubPolicy) getDenyPolicies(context.Context, string) ([]byte, error) {
	if s.denyErr != nil {
		return nil, s.denyErr
	}
	if s.deny != "" {
		return []byte(s.deny), nil
	}
	return []byte(`{}`), nil
}

const twoBindings = `{"bindings":[
	{"role":"roles/owner","members":["user:alice@example.com","serviceAccount:sa@p.iam.gserviceaccount.com"]},
	{"role":"roles/viewer","members":["group:eng@example.com","allUsers","domain:example.com"],
	 "condition":{"title":"biz-hours","expression":"request.time.getHours() < 18"}}]}`

func runPolicy(t *testing.T, project string, api policyAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newPolicyCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func linkTo(s collect.Scan, role string) []collect.Link {
	var out []collect.Link
	for _, l := range s.Links {
		if l.TargetNativeID == role {
			out = append(out, l)
		}
	}
	return out
}

// TestPolicyMapsBindings proves the authorization graph: roles become role nodes,
// members become the right node type, and each grant is a member-to-role assumes
// edge, with a binding condition carried on its edges.
func TestPolicyMapsBindings(t *testing.T) {
	s := runPolicy(t, "proj", &stubPolicy{body: twoBindings})

	byType := nodesByType(s)
	if byType[model.NodeRole] != 2 {
		t.Errorf("role nodes = %d, want 2", byType[model.NodeRole])
	}
	if byType[model.NodeProject] != 1 {
		t.Errorf("project nodes = %d, want 1", byType[model.NodeProject])
	}
	// user -> identity, allUsers -> identity; serviceAccount -> workload; group and
	// domain -> group.
	if byType[model.NodeIdentity] != 2 {
		t.Errorf("identity nodes = %d, want 2 (alice + allUsers)", byType[model.NodeIdentity])
	}
	if byType[model.NodeWorkload] != 1 {
		t.Errorf("workload nodes = %d, want 1 (the service account)", byType[model.NodeWorkload])
	}
	if byType[model.NodeGroup] != 2 {
		t.Errorf("group nodes = %d, want 2 (group + domain)", byType[model.NodeGroup])
	}

	if len(s.Links) != 5 {
		t.Fatalf("grant edges = %d, want 5", len(s.Links))
	}
	for _, l := range s.Links {
		if l.Kind != model.EdgeAssumes {
			t.Errorf("edge kind = %s, want assumes", l.Kind)
		}
	}
	// The service-account member is keyed by its bare email, so it merges with the
	// service-account collector's node.
	var sawSA bool
	for _, l := range linkTo(s, "roles/owner") {
		if l.SourceNativeID == "sa@p.iam.gserviceaccount.com" {
			sawSA = true
		}
	}
	if !sawSA {
		t.Error("service-account member is not keyed by its bare email")
	}
	// The conditional binding's edges carry the condition.
	for _, l := range linkTo(s, "roles/viewer") {
		if l.Conditions["condition_title"] != "biz-hours" {
			t.Errorf("viewer edge missing the binding condition: %v", l.Conditions)
		}
	}
	// The unconditional binding's edges carry no condition.
	for _, l := range linkTo(s, "roles/owner") {
		if l.Conditions != nil {
			t.Errorf("owner edge should have no condition, got %v", l.Conditions)
		}
	}
	if statusOf(s, "iam.projectPolicy") != collect.Complete {
		t.Errorf("status = %s, want complete", statusOf(s, "iam.projectPolicy"))
	}
	// getIamPolicy + one roles.get per distinct role (owner, viewer) + denypolicies.list.
	if len(s.Envelopes) != 4 {
		t.Errorf("evidence envelopes = %d, want 4 (policy + 2 role reads + deny read)", len(s.Envelopes))
	}
}

// TestMemberNode covers the principal-identifier mapping, including the public
// and federated forms, and proves an unknown member is kept, never dropped.
func TestMemberNode(t *testing.T) {
	cases := []struct {
		member string
		typ    model.NodeType
		native string
		public bool
	}{
		{"user:a@x.com", model.NodeIdentity, "a@x.com", false},
		{"serviceAccount:sa@p.iam.gserviceaccount.com", model.NodeWorkload, "sa@p.iam.gserviceaccount.com", false},
		{"group:g@x.com", model.NodeGroup, "g@x.com", false},
		{"domain:x.com", model.NodeGroup, "domain:x.com", false},
		{"allUsers", model.NodeIdentity, "allUsers", true},
		{"allAuthenticatedUsers", model.NodeIdentity, "allAuthenticatedUsers", true},
		{"principal://iam.googleapis.com/locations/global/workforcePools/p/subject/s", model.NodeIdentity, "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/s", false},
		{"principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*", model.NodeGroup, "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*", false},
		{"deleted:serviceAccount:sa@p.iam.gserviceaccount.com?uid=1", model.NodeWorkload, "deleted:serviceAccount:sa@p.iam.gserviceaccount.com?uid=1", false},
		{"somethingNew:xyz", model.NodeIdentity, "somethingNew:xyz", false},
	}
	for _, tc := range cases {
		n := memberNode(tc.member)
		if n.Type != tc.typ || n.NativeID != tc.native {
			t.Errorf("memberNode(%q) = (%s, %q), want (%s, %q)", tc.member, n.Type, n.NativeID, tc.typ, tc.native)
		}
		if tc.public && n.Attributes["public"] != "true" {
			t.Errorf("memberNode(%q) not marked public", tc.member)
		}
	}
}

func TestPolicyEmptyProjectIsUnsupported(t *testing.T) {
	api := &stubPolicy{}
	var s collect.Scan
	if err := newPolicyCollector("", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 0 {
		t.Errorf("made %d calls with no project; want 0", api.calls)
	}
	if statusOf(s, "iam.projectPolicy") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "iam.projectPolicy"))
	}
}

func TestPolicyDeniedIsGapNotError(t *testing.T) {
	var s collect.Scan
	err := newPolicyCollector("proj", &stubPolicy{err: &gcpError{status: 403, body: "PERMISSION_DENIED"}}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("denied read must not surface as a run error: %v", err)
	}
	if statusOf(s, "iam.projectPolicy") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "iam.projectPolicy"))
	}
}

// TestPolicyServiceDisabledIsUnsupported proves a disabled-API 403 on the policy
// read is a recorded Unsupported gap, not Denied, and not a run error.
func TestPolicyServiceDisabledIsUnsupported(t *testing.T) {
	var s collect.Scan
	err := newPolicyCollector("proj", &stubPolicy{err: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud Resource Manager API is not enabled"}}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("service-disabled must not surface as a run error: %v", err)
	}
	if statusOf(s, "iam.projectPolicy") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "iam.projectPolicy"))
	}
}

func TestPolicyUnexpectedErrorSurfaces(t *testing.T) {
	var s collect.Scan
	err := newPolicyCollector("proj", &stubPolicy{err: &gcpError{status: 500, body: "INTERNAL"}}).Collect(context.Background(), &s)
	if err == nil {
		t.Fatal("unexpected error must surface")
	}
	if statusOf(s, "iam.projectPolicy") != collect.Errored {
		t.Errorf("status = %s, want error", statusOf(s, "iam.projectPolicy"))
	}
}

// TestPolicyBudgetExhaustion proves the single getIamPolicy call spends from the
// budget: with no budget it is a recorded Partial gap and no call is made.
func TestPolicyBudgetExhaustion(t *testing.T) {
	api := &stubPolicy{body: twoBindings}
	c := newPolicyCollector("proj", api)
	c.budget = collect.NewBudget(0)

	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 0 {
		t.Errorf("made %d calls under an exhausted budget; want 0", api.calls)
	}
	c0 := s.Completeness[0]
	if c0.Status != collect.Partial || c0.Reason != "budget exhausted" {
		t.Fatalf("status = %+v, want partial with reason budget exhausted", c0)
	}
}

func TestPolicyEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("Q", 60)
	body := `{"bindings":[{"role":"roles/viewer","members":["user:` + token + `@x.com"]}]}`
	s := runPolicy(t, "proj", &stubPolicy{body: body})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
