package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestMergedDenyFactReachesStep4 proves the attribute merge (index.go) lets a fact
// set by one collector (a deny collector's deny_privilege_level) reach the engine
// alongside a principal node another collector emitted without it. The deny node is
// listed FIRST and the plain node SECOND, so a last-wins index would drop the deny
// and the admin grant would resolve as allow; the merge preserves it and the grant
// resolves as deny. This is the EP-6 integration: deny source -> Step 4.
func TestMergedDenyFactReachesStep4(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			// The deny collector's node for alice (carries the deny fact).
			node(model.NodeIdentity, "user:alice", map[string]string{"deny_privilege_level": "admin"}),
			// The identity collector's node for the same alice (no deny fact), listed after.
			node(model.NodeIdentity, "user:alice", nil),
			node(model.NodeRole, "role:Admin", map[string]string{"privilege_level": "admin"}),
		},
		Links:        []collect.Link{{SourceNativeID: "user:alice", TargetNativeID: "role:Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "user:alice")
	if g == nil || g.Effect != model.EffectDeny {
		t.Fatalf("merged deny fact did not override the admin grant: %v", g)
	}
}
