package rules

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// goldenFS embeds the pre-re-target golden findings, so reading them needs no
// host access (the evaluation package is gated against os; ADR-0021 §4).
//
//go:embed testdata/retarget_hasedge.json testdata/retarget_fact.json testdata/retarget_denied.json
var goldenFS embed.FS

// testKeyer derives a valid StableID from a native id, deterministically, so a
// test can normalize a collect.Scan fixture without a real tenant. The keying is
// internal to the graph; findings are reported by native id, so the specific hash
// never affects a Result.
type testKeyer struct{}

func (testKeyer) StableID(nativeID string) (model.StableID, error) {
	sum := sha256.Sum256([]byte(nativeID))
	return model.StableID(hex.EncodeToString(sum[:])), nil
}

// norm normalizes a collect.Scan fixture into the model graph the engine now
// reads, so existing fixtures drive the re-targeted engine unchanged.
func norm(scan *collect.Scan) *normalize.NormalizedScan {
	if scan == nil {
		return nil
	}
	g, err := normalize.Normalize(*scan, testKeyer{}, normalize.Meta{})
	if err != nil {
		panic(err)
	}
	return &g
}

// TestReTargetReproducesGolden is the behavior-preservation proof (ADR-0022 EP-2):
// the re-targeted engine, reading the normalized model graph, produces byte-for-byte
// the same findings the pre-re-target engine produced on the same fixtures. The
// golden files were captured from the collect.Scan-based engine before the re-target
// (see the preceding commit), so a match proves the change is behavior-preserving,
// not merely that tests are green.
func TestReTargetReproducesGolden(t *testing.T) {
	for name, f := range retargetGoldenFixtures() {
		want, err := goldenFS.ReadFile("testdata/" + name + ".json")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rs, err := Evaluate(norm(f.scan), f.rules)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, _ := json.MarshalIndent(rs, "", "  ")
		got = append(got, '\n')
		if string(got) != string(want) {
			t.Errorf("%s: re-targeted findings differ from the pre-re-target golden\n--- got ---\n%s", name, got)
		}
	}
}

type retargetFixture struct {
	scan  *collect.Scan
	rules []Rule
}

func retargetGoldenFixtures() map[string]retargetFixture {
	edgeScan := &collect.Scan{
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
	edgeRule := Rule{
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
	factScan := &collect.Scan{
		Nodes: []collect.Node{
			store("//b/pub", map[string]string{"iam_all_users_roles": "roles/viewer"}),
			store("//b/priv", nil),
		},
		Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Complete)},
	}
	deniedScan := &collect.Scan{
		Nodes:        []collect.Node{store("//b/pub", map[string]string{"iam_all_users_roles": "roles/viewer"})},
		Completeness: []collect.Completeness{complete("storage.bucketIam", collect.Denied)},
	}
	return map[string]retargetFixture{
		"retarget_hasedge": {edgeScan, []Rule{edgeRule}},
		"retarget_fact":    {factScan, []Rule{publicStorageRule()}},
		"retarget_denied":  {deniedScan, []Rule{publicStorageRule()}},
	}
}
