package rules

import (
	"reflect"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// publicStorageRule is a representative detection: a data store with an all-users IAM
// grant is a fail. It reads one completeness input, storage.bucketIam.
func publicStorageRule() Rule {
	return Rule{
		ID: "TEST-STORAGE-PUBLIC", Version: "1", PackID: "test",
		Title:     "public object storage",
		Severity:  model.SeverityHigh,
		Selector:  Selector{NodeType: model.NodeDataStore},
		Predicate: Predicate{Op: OpFactPresent, Fact: "iam_all_users_roles"},
		Requires:  Requirements{Nodes: []model.NodeType{model.NodeDataStore}, Completeness: []string{"storage.bucketIam"}},
		Confidence: ConfidenceModel{Base: 90, Factors: []ConfidenceFactor{
			{Name: "direct_iam_binding", When: Predicate{Op: OpFactPresent, Fact: "iam_all_users_roles"}, Delta: 5},
		}},
	}
}

func store(id string, attrs map[string]string) collect.Node {
	return collect.Node{Type: model.NodeDataStore, NativeID: id, Attributes: attrs}
}

func complete(service string, st collect.Status) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Status: st}
}

func stateOf(rs []Result, entity string) model.Outcome {
	for _, r := range rs {
		if r.EntityID == entity {
			return r.State
		}
	}
	return ""
}

// TestEvalPassFail proves a complete-evidence scan yields fail for the public store and
// pass for the private one, with the deterministic confidence and the grounding facts.
func TestEvalPassFail(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			store("//s/pub", map[string]string{"iam_all_users_roles": "READER"}),
			store("//s/priv", map[string]string{"uniform_bucket_level_access": "true"}),
		},
		Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Complete)},
	}
	rs, err := Evaluate(norm(scan), []Rule{publicStorageRule()})
	if err != nil {
		t.Fatal(err)
	}
	if stateOf(rs, "//s/pub") != model.Fail {
		t.Errorf("public store state = %s, want fail", stateOf(rs, "//s/pub"))
	}
	if stateOf(rs, "//s/priv") != model.Pass {
		t.Errorf("private store state = %s, want pass", stateOf(rs, "//s/priv"))
	}
	for _, r := range rs {
		if r.EntityID == "//s/pub" {
			if r.Confidence != 95 {
				t.Errorf("confidence = %d, want 95 (base 90 + direct 5)", r.Confidence)
			}
			if len(r.Grounding.Facts) == 0 {
				t.Error("fail finding carries no grounding facts")
			}
		}
	}
}

// TestHonestUnknownFromDenied is the honest-state guarantee, mutation-strength: when the
// required completeness input is Denied, the public store must be UNKNOWN, never a fail
// and never a pass. A mutation that treats Denied as complete (or drops the coverage
// check) turns this into fail/pass and the test fails.
func TestHonestUnknownFromDenied(t *testing.T) {
	for _, st := range []collect.Status{collect.Denied, collect.Partial, collect.Errored} {
		scan := &collect.Scan{
			Nodes:        []collect.Node{store("//s/pub", map[string]string{"iam_all_users_roles": "READER"})},
			Completeness: []collect.Completeness{complete("storage.bucketIam", st)},
		}
		rs, err := Evaluate(norm(scan), []Rule{publicStorageRule()})
		if err != nil {
			t.Fatal(err)
		}
		got := stateOf(rs, "//s/pub")
		if got != model.OutcomeUnknown {
			t.Errorf("with %s evidence, state = %s, want unknown (never a false pass or fail)", st, got)
		}
		if got == model.Pass {
			t.Errorf("CRITICAL: gap-marked evidence produced a PASS with %s", st)
		}
	}
}

// TestNotApplicableFromUnsupported proves an Unsupported input (the service is not in
// use) yields not-applicable, distinct from the unknown of a Denied read.
func TestNotApplicableFromUnsupported(t *testing.T) {
	scan := &collect.Scan{
		Nodes:        []collect.Node{store("//s/pub", map[string]string{"iam_all_users_roles": "READER"})},
		Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Unsupported)},
	}
	rs, _ := Evaluate(norm(scan), []Rule{publicStorageRule()})
	if got := stateOf(rs, "//s/pub"); got != model.NotApplicable {
		t.Errorf("with Unsupported evidence, state = %s, want not_applicable", got)
	}
}

// TestCoverageGapNeverSilent proves that when a gap means no entities could be listed,
// the engine still emits one rule-level unknown result rather than silently nothing (a
// gap must never be a false pass by omission).
func TestCoverageGapNeverSilent(t *testing.T) {
	scan := &collect.Scan{
		Nodes:        nil, // the list read was denied, so no nodes exist
		Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Denied)},
	}
	rs, _ := Evaluate(norm(scan), []Rule{publicStorageRule()})
	if len(rs) != 1 {
		t.Fatalf("expected one rule-level gap result, got %d", len(rs))
	}
	if rs[0].State != model.OutcomeUnknown || rs[0].EntityID != "" {
		t.Errorf("gap result = %+v, want rule-level unknown", rs[0])
	}
}

// TestMissingInputIsNotApplicable proves a required service with no completeness record
// at all (the provider/domain was not scanned) is not-applicable, not a pass.
func TestMissingInputIsNotApplicable(t *testing.T) {
	scan := &collect.Scan{
		Nodes:        []collect.Node{store("//s/pub", map[string]string{"iam_all_users_roles": "READER"})},
		Completeness: []collect.Completeness{complete("compute.instances", collect.Complete)}, // unrelated
	}
	rs, _ := Evaluate(norm(scan), []Rule{publicStorageRule()})
	if got := stateOf(rs, "//s/pub"); got != model.NotApplicable {
		t.Errorf("with the required input absent, state = %s, want not_applicable", got)
	}
}

// TestDeterministicOrderAndValues is the determinism guarantee: the same scan evaluated
// with its nodes and rules in different input orders yields identical results in
// identical order. A mutation that leaked map iteration order into output fails this.
func TestDeterministicOrderAndValues(t *testing.T) {
	mk := func(order []collect.Node) *collect.Scan {
		return &collect.Scan{Nodes: order, Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Complete)}}
	}
	a := mk([]collect.Node{
		store("//s/a", map[string]string{"iam_all_users_roles": "READER"}),
		store("//s/b", nil),
		store("//s/c", map[string]string{"iam_all_users_roles": "OWNER"}),
	})
	b := mk([]collect.Node{
		store("//s/c", map[string]string{"iam_all_users_roles": "OWNER"}),
		store("//s/a", map[string]string{"iam_all_users_roles": "READER"}),
		store("//s/b", nil),
	})
	rulesIn := []Rule{publicStorageRule(), rotationRule()}
	ra, _ := Evaluate(norm(a), rulesIn)
	rb, _ := Evaluate(norm(b), []Rule{rotationRule(), publicStorageRule()}) // rules in different order too
	if !reflect.DeepEqual(ra, rb) {
		t.Fatalf("evaluation is not deterministic across input orderings:\n a=%+v\n b=%+v", ra, rb)
	}
	// And a second run of the identical input is byte-identical.
	ra2, _ := Evaluate(norm(a), rulesIn)
	if !reflect.DeepEqual(ra, ra2) {
		t.Fatal("re-evaluating the same scan gave different results")
	}
}

// TestSelectNodesDeterministicOrder proves the view returns entities in canonical id
// order regardless of the order they were collected in, so no map or input ordering can
// leak into the finding stream. Removing the canonical sort makes this fail.
func TestSelectNodesDeterministicOrder(t *testing.T) {
	scan := &collect.Scan{Nodes: []collect.Node{
		store("//s/z", nil), store("//s/a", nil), store("//s/m", nil),
	}}
	got := newView(norm(scan)).selectNodes(Selector{NodeType: model.NodeDataStore})
	want := []string{"//s/a", "//s/m", "//s/z"}
	if len(got) != len(want) {
		t.Fatalf("got %d nodes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].NativeID != want[i] {
			t.Errorf("selection not in canonical order: got[%d]=%s, want %s", i, got[i].NativeID, want[i])
		}
	}
}

func rotationRule() Rule {
	return Rule{
		ID: "TEST-KEY-ROTATION", Version: "1", PackID: "test",
		Severity:   model.SeverityMedium,
		Selector:   Selector{NodeType: model.NodeControl},
		Predicate:  Predicate{Op: OpFactEquals, Fact: "rotation_configured", Value: "false"},
		Requires:   Requirements{Completeness: []string{"cloudkms.cryptoKeys"}},
		Confidence: ConfidenceModel{Base: 80},
	}
}

// TestHasEdgeJoin proves the one bounded graph join: a principal that assumes a
// high-privilege role is a fail, with the edge recorded in the grounding.
func TestHasEdgeJoin(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeIdentity, NativeID: "user:alice"},
			{Type: model.NodeRole, NativeID: "role:Owner", Attributes: map[string]string{"privilege": "owner"}},
			{Type: model.NodeRole, NativeID: "role:Reader", Attributes: map[string]string{"privilege": "reader"}},
			{Type: model.NodeIdentity, NativeID: "user:bob"},
		},
		Links: []collect.Link{
			{SourceNativeID: "user:alice", TargetNativeID: "role:Owner", Kind: model.EdgeAssumes},
			{SourceNativeID: "user:bob", TargetNativeID: "role:Reader", Kind: model.EdgeAssumes},
		},
		Completeness: []collect.Completeness{complete("rbac.roleAssignments", collect.Complete)},
	}
	rule := Rule{
		ID: "TEST-STANDING-ADMIN", Version: "1", PackID: "test",
		Severity: model.SeverityHigh,
		Selector: Selector{NodeType: model.NodeIdentity},
		Predicate: Predicate{Op: OpHasEdge, Edge: model.EdgeAssumes, Target: &Selector{
			NodeType:  model.NodeRole,
			Predicate: &Predicate{Op: OpFactEquals, Fact: "privilege", Value: "owner"},
		}},
		Requires:   Requirements{Edges: []model.EdgeKind{model.EdgeAssumes}, Completeness: []string{"rbac.roleAssignments"}},
		Confidence: ConfidenceModel{Base: 85},
	}
	rs, err := Evaluate(norm(scan), []Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if stateOf(rs, "user:alice") != model.Fail {
		t.Errorf("alice (assumes Owner) state = %s, want fail", stateOf(rs, "user:alice"))
	}
	if stateOf(rs, "user:bob") != model.Pass {
		t.Errorf("bob (assumes Reader) state = %s, want pass", stateOf(rs, "user:bob"))
	}
	for _, r := range rs {
		if r.EntityID == "user:alice" && len(r.Grounding.Edges) == 0 {
			t.Error("has_edge fail did not record the edge in grounding")
		}
	}
}

// TestFactOperators exercises each fact operator's truth.
func TestFactOperators(t *testing.T) {
	n := collect.Node{Type: model.NodeDataStore, NativeID: "//x", Attributes: map[string]string{
		"public": "true", "tier": "premium", "nets": "10.0.0.0/8,0.0.0.0/0", "retention_days": "7",
	}}
	v := newView(norm(&collect.Scan{Nodes: []collect.Node{n}}))
	ent := v.byID[n.NativeID]
	cases := []struct {
		name string
		p    Predicate
		want bool
	}{
		{"equals", Predicate{Op: OpFactEquals, Fact: "public", Value: "true"}, true},
		{"equals-no", Predicate{Op: OpFactEquals, Fact: "public", Value: "false"}, false},
		{"in", Predicate{Op: OpFactIn, Fact: "tier", Values: []string{"standard", "premium"}}, true},
		{"present", Predicate{Op: OpFactPresent, Fact: "tier"}, true},
		{"absent", Predicate{Op: OpFactAbsent, Fact: "missing"}, true},
		{"contains-member", Predicate{Op: OpFactContains, Fact: "nets", Value: "0.0.0.0/0"}, true},
		{"contains-no", Predicate{Op: OpFactContains, Fact: "nets", Value: "192.168.0.0/16"}, false},
		{"num-lt", Predicate{Op: OpFactNum, Fact: "retention_days", Cmp: CmpLT, Value: "90"}, true},
		{"num-ge", Predicate{Op: OpFactNum, Fact: "retention_days", Cmp: CmpGE, Value: "90"}, false},
		{"and", Predicate{Op: OpAnd, Children: []Predicate{{Op: OpFactEquals, Fact: "public", Value: "true"}, {Op: OpFactPresent, Fact: "tier"}}}, true},
		{"or-false", Predicate{Op: OpOr, Children: []Predicate{{Op: OpFactEquals, Fact: "public", Value: "false"}, {Op: OpFactAbsent, Fact: "tier"}}}, false},
		{"not", Predicate{Op: OpNot, Children: []Predicate{{Op: OpFactEquals, Fact: "public", Value: "false"}}}, true},
	}
	for _, c := range cases {
		var g Grounding
		var tr []string
		if got := evalNode(c.p, ent, v, &g, &tr); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// ageRuleWithIndeterminate is an age-threshold detection with a per-node honesty gate:
// a node whose numeric fact is missing or a non-numeric sentinel (N/A, no_information,
// not_supported) is Indeterminate -> Unknown, never pass. This is the pattern the
// identity-hygiene rules use for fact_num thresholds.
func ageRuleWithIndeterminate() Rule {
	return Rule{
		ID: "TEST-AGE", Version: "1", PackID: "test", Title: "resource too old",
		Severity: model.SeverityMedium,
		Selector: Selector{NodeType: model.NodeDataStore},
		// Fail when age_days > 90.
		Predicate: Predicate{Op: OpFactNum, Fact: "age_days", Cmp: CmpGT, Value: "90"},
		// Unknown when age_days is not a usable number (absent or a sentinel): not(age_days >= 0).
		Indeterminate: &Predicate{Op: OpNot, Children: []Predicate{{Op: OpFactNum, Fact: "age_days", Cmp: CmpGE, Value: "0"}}},
		Requires:      Requirements{Nodes: []model.NodeType{model.NodeDataStore}, Completeness: []string{"storage.bucketIam"}},
		Confidence:    ConfidenceModel{Base: 80},
	}
}

// TestIndeterminateFactIsUnknownNeverPass proves the amendment-2 guarantee: on a
// complete scan, a node whose deciding numeric fact is missing or a sentinel
// (N/A / no_information / not_supported) evaluates to Unknown, never Pass; a node with
// a real value still passes or fails normally.
func TestIndeterminateFactIsUnknownNeverPass(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			store("//old", map[string]string{"age_days": "412"}),               // fail
			store("//young", map[string]string{"age_days": "10"}),              // pass
			store("//missing", map[string]string{}),                            // unknown (absent)
			store("//na", map[string]string{"age_days": "N/A"}),                // unknown (sentinel)
			store("//noinfo", map[string]string{"age_days": "no_information"}), // unknown (sentinel)
			store("//notsup", map[string]string{"age_days": "not_supported"}),  // unknown (sentinel)
		},
		Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Complete)},
	}
	rs, err := Evaluate(norm(scan), []Rule{ageRuleWithIndeterminate()})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.Outcome{
		"//old": model.Fail, "//young": model.Pass,
		"//missing": model.OutcomeUnknown, "//na": model.OutcomeUnknown,
		"//noinfo": model.OutcomeUnknown, "//notsup": model.OutcomeUnknown,
	}
	for id, w := range want {
		if got := stateOf(rs, id); got != w {
			t.Errorf("%s state = %s, want %s", id, got, w)
		}
	}
	// Belt and braces: no node with a missing or sentinel fact is ever Pass.
	for _, id := range []string{"//missing", "//na", "//noinfo", "//notsup"} {
		if stateOf(rs, id) == model.Pass {
			t.Errorf("%s was Pass, but an undeterminable fact must be Unknown", id)
		}
	}
}
