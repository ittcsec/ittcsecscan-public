package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

type keyer struct{}

func (keyer) StableID(nativeID string) (model.StableID, error) {
	sum := sha256.Sum256([]byte(nativeID))
	return model.StableID(hex.EncodeToString(sum[:])), nil
}

func sid(nativeID string) model.StableID {
	id, _ := keyer{}.StableID(nativeID)
	return id
}

func norm(scan *collect.Scan) *normalize.NormalizedScan {
	g, err := normalize.Normalize(*scan, keyer{}, normalize.Meta{})
	if err != nil {
		panic(err)
	}
	return &g
}

func node(t model.NodeType, id string, attrs map[string]string) collect.Node {
	return collect.Node{Type: t, NativeID: id, Attributes: attrs}
}

// TestReachTransitive proves the closure emits a derived edge for a two-hop reach
// (a principal reaching a role through a group), with the terminal edge kind and a
// path trace, and does NOT re-emit the one-hop direct edges (which are collected).
func TestReachTransitive(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "user:alice", nil),
			node(model.NodeGroup, "group:admins", nil),
			node(model.NodeRole, "role:Owner", map[string]string{"privilege": "owner"}),
		},
		Links: []collect.Link{
			{SourceNativeID: "user:alice", TargetNativeID: "group:admins", Kind: model.EdgeMemberOf},
			{SourceNativeID: "group:admins", TargetNativeID: "role:Owner", Kind: model.EdgeAssumes},
		},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	res := Reach(norm(scan))
	// alice -> role:Owner is a two-hop assumes reach (member_of then assumes).
	var got *model.Edge
	for i := range res.Reaches {
		if res.Reaches[i].Source == sid("user:alice") && res.Reaches[i].Target == sid("role:Owner") {
			got = &res.Reaches[i]
		}
	}
	if got == nil {
		t.Fatalf("no transitive reach alice -> role:Owner; got %d reaches", len(res.Reaches))
	}
	if got.Kind != model.EdgeAssumes {
		t.Errorf("reach kind = %s, want assumes (terminal hop)", got.Kind)
	}
	if got.Confidence != 80 {
		t.Errorf("2-hop reach confidence = %d, want 80", got.Confidence)
	}
	if got.DenyEvaluated != model.Unknown {
		t.Errorf("reach deny_evaluated = %s, want unknown (no deny data)", got.DenyEvaluated)
	}
	if len(got.Explanation) == 0 {
		t.Error("reach has no path trace")
	}
	// The one-hop direct edges (alice->group, group->role) must NOT be re-emitted.
	for _, e := range res.Reaches {
		if e.Source == sid("user:alice") && e.Target == sid("group:admins") {
			t.Error("one-hop direct edge alice->group was re-emitted as a reach")
		}
	}
}

// TestReachDeterministic proves the closure is order-independent and reproducible.
func TestReachDeterministic(t *testing.T) {
	mk := func(order []collect.Node) *collect.Scan {
		return &collect.Scan{
			Nodes: order,
			Links: []collect.Link{
				{SourceNativeID: "u:a", TargetNativeID: "g:1", Kind: model.EdgeMemberOf},
				{SourceNativeID: "g:1", TargetNativeID: "g:2", Kind: model.EdgeMemberOf},
				{SourceNativeID: "g:2", TargetNativeID: "r:x", Kind: model.EdgeAssumes},
			},
			Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
		}
	}
	a := mk([]collect.Node{node(model.NodeIdentity, "u:a", nil), node(model.NodeGroup, "g:1", nil), node(model.NodeGroup, "g:2", nil), node(model.NodeRole, "r:x", nil)})
	b := mk([]collect.Node{node(model.NodeRole, "r:x", nil), node(model.NodeGroup, "g:2", nil), node(model.NodeGroup, "g:1", nil), node(model.NodeIdentity, "u:a", nil)})
	ra, rb := Reach(norm(a)), Reach(norm(b))
	if !reflect.DeepEqual(ra, rb) {
		t.Fatal("reachability depends on input order")
	}
	if !reflect.DeepEqual(ra, Reach(norm(a))) {
		t.Fatal("reachability is not reproducible across runs")
	}
}

// TestTrustExposure proves external/public/federated principals yield trust edges
// with the right kind, and an ordinary in-account principal yields none.
func TestTrustExposure(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "allUsers", map[string]string{"public": "true"}),
			node(model.NodeIdentity, "fed:idp", map[string]string{"federated": "true"}),
			node(model.NodeIdentity, "user:real", nil),
			node(model.NodeRole, "role:pub", nil),
			node(model.NodeRole, "role:fed", nil),
			node(model.NodeRole, "role:priv", nil),
		},
		Links: []collect.Link{
			{SourceNativeID: "allUsers", TargetNativeID: "role:pub", Kind: model.EdgeAssumes},
			{SourceNativeID: "fed:idp", TargetNativeID: "role:fed", Kind: model.EdgeAssumes},
			{SourceNativeID: "user:real", TargetNativeID: "role:priv", Kind: model.EdgeAssumes},
		},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	res := Reach(norm(scan))
	kinds := map[model.StableID]model.EdgeKind{}
	for _, e := range res.Trust {
		kinds[e.Source] = e.Kind // source is the trusting role
	}
	if kinds[sid("role:pub")] != model.EdgeTrusts {
		t.Errorf("public role trust kind = %s, want trusts", kinds[sid("role:pub")])
	}
	if kinds[sid("role:fed")] != model.EdgeFederatesWith {
		t.Errorf("federated role trust kind = %s, want federates_with", kinds[sid("role:fed")])
	}
	if _, ok := kinds[sid("role:priv")]; ok {
		t.Error("an ordinary in-account principal wrongly produced a trust edge")
	}
	if len(res.Trust) != 2 {
		t.Errorf("got %d trust edges, want 2 (public + federated only)", len(res.Trust))
	}
}

// TestHonestCoverage proves a non-complete identity read makes the reachability an
// explicit floor (Complete=false) with the gap cited, never silently exhaustive.
func TestHonestCoverage(t *testing.T) {
	scan := &collect.Scan{
		Completeness: []collect.Completeness{
			{Service: "iam.identities", Status: collect.Complete},
			{Service: "cloudidentity.groupMembers", Status: collect.Denied, Reason: "denied"},
		},
	}
	res := Reach(norm(scan))
	if res.Complete {
		t.Error("reachability reported Complete despite a denied identity read")
	}
	if len(res.Gaps) != 1 || res.Gaps[0] != "cloudidentity.groupMembers:denied" {
		t.Errorf("gaps = %v, want [cloudidentity.groupMembers:denied]", res.Gaps)
	}
}

// TestReachEmitsNoPermissionOrEffect is the Layer B boundary (ADR-0022): the engine
// never produces a model.Permission and never carries a model.Effect. It walks the
// Result type graph by reflection, so a later field that added either would fail
// here, not in review.
func TestReachEmitsNoPermissionOrEffect(t *testing.T) {
	forbidden := map[string]bool{
		reflect.TypeOf(model.Permission{}).String(): true,
		reflect.TypeOf(model.Effect("")).String():   true,
	}
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		if ty == nil || seen[ty] {
			return
		}
		seen[ty] = true
		if forbidden[ty.String()] {
			t.Errorf("Layer B Result reaches a forbidden type: %s", ty.String())
			return
		}
		switch ty.Kind() {
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				walk(ty.Field(i).Type)
			}
		case reflect.Slice, reflect.Array, reflect.Pointer, reflect.Map:
			if ty.Kind() == reflect.Map {
				walk(ty.Key())
			}
			walk(ty.Elem())
		}
	}
	walk(reflect.TypeOf(Result{}))
}
