package graph

import (
	"reflect"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// grantFor returns the effective-privilege grant for a principal, or nil.
func grantFor(res EffectiveResult, principal string) *model.Permission {
	for i := range res.Grants {
		if res.Grants[i].Principal == sid(principal) {
			return &res.Grants[i]
		}
	}
	return nil
}

// TestEffectivePrivilegeGranted proves a principal reaching an admin role holds an
// allowed effective-admin grant.
func TestEffectivePrivilegeGranted(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "user:alice", nil),
			node(model.NodeRole, "role:Admin", map[string]string{"privilege_level": "admin"}),
		},
		Links:        []collect.Link{{SourceNativeID: "user:alice", TargetNativeID: "role:Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "user:alice")
	if g == nil {
		t.Fatal("no grant for a principal reaching an admin role")
	}
	if g.Effect != model.EffectAllow || g.Action != "privilege:admin" {
		t.Errorf("grant = %s %s, want allow privilege:admin", g.Effect, g.Action)
	}
}

// TestBoundaryCapIsDenyOverride is the deny-semantics proof (ADR-0022 §5): an admin
// grant capped by a read-only permission boundary must resolve as denied, not
// allowed. It is the mutation target: dropping the boundary cap makes the grant
// resolve as an allowed admin, and this test catches it.
func TestBoundaryCapIsDenyOverride(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "user:alice", map[string]string{"permission_boundary": "arn:boundary"}),
			node(model.NodeRole, "role:Admin", map[string]string{"privilege_level": "admin"}),
			// The boundary policy was read and is read-only (no privilege_level).
			node(model.NodePolicy, "arn:boundary", map[string]string{"document_read": "true"}),
		},
		Links:        []collect.Link{{SourceNativeID: "user:alice", TargetNativeID: "role:Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "user:alice")
	if g == nil {
		t.Fatal("no grant emitted")
	}
	if g.Effect != model.EffectDeny {
		t.Errorf("admin grant capped by a read-only boundary resolved %s, want deny (the allow must be overridden)", g.Effect)
	}
}

// TestExplicitDenyOverride is the second deny-semantics proof: an explicit deny (a
// deny-assignment / deny policy / SCP, surfaced as deny_privilege_level) at or
// above the granted level removes it. Mutation target: dropping the explicit-deny
// check makes the admin grant resolve as allowed.
func TestExplicitDenyOverride(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "user:alice", map[string]string{"deny_privilege_level": "admin"}),
			node(model.NodeRole, "role:Admin", map[string]string{"privilege_level": "admin"}),
		},
		Links:        []collect.Link{{SourceNativeID: "user:alice", TargetNativeID: "role:Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "user:alice")
	if g == nil || g.Effect != model.EffectDeny {
		t.Errorf("admin grant under an explicit admin-level deny = %v, want a deny grant", g)
	}
}

// TestUnknownBoundaryIsNotSilentGrant proves a boundary whose policy could not be
// classified does not leave the principal asserted as full admin: an unknown cap
// removes the assertion (deny), never a silent full grant.
func TestUnknownBoundaryIsNotSilentGrant(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "user:alice", map[string]string{"permission_boundary": "arn:unknown"}),
			node(model.NodeRole, "role:Admin", map[string]string{"privilege_level": "admin"}),
			// The boundary policy node is absent / not read (no document_read).
		},
		Links:        []collect.Link{{SourceNativeID: "user:alice", TargetNativeID: "role:Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "user:alice")
	if g == nil || g.Effect != model.EffectDeny {
		t.Errorf("admin grant with an unclassifiable boundary = %v, want deny (never a silent full grant)", g)
	}
}

// TestAccountSCPCapOverridesAdmin is the account-cap deny proof (ADR-0022 EP-6): an
// SCP over the principal's account (a deny_privilege_level on the account node,
// found via the principal's ARN) overrides an otherwise-valid in-account admin
// grant. Mutation target: dropping the account-cap check makes the grant resolve
// as allowed.
func TestAccountSCPCapOverridesAdmin(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "arn:aws:iam::123456789012:user/alice", nil),
			node(model.NodeRole, "arn:aws:iam::123456789012:role/Admin", map[string]string{"privilege_level": "admin"}),
			node(model.NodeAccount, "123456789012", map[string]string{"deny_privilege_level": "admin"}),
		},
		Links:        []collect.Link{{SourceNativeID: "arn:aws:iam::123456789012:user/alice", TargetNativeID: "arn:aws:iam::123456789012:role/Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "arn:aws:iam::123456789012:user/alice")
	if g == nil || g.Effect != model.EffectDeny {
		t.Errorf("account SCP cap did not override the in-account admin grant: %v", g)
	}
}

// TestAccountCapUnaffectedWithoutScp proves a principal in an account with no SCP
// cap keeps its admin grant (the account-cap check does not spuriously deny).
func TestAccountCapUnaffectedWithoutScp(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "arn:aws:iam::123456789012:user/bob", nil),
			node(model.NodeRole, "arn:aws:iam::123456789012:role/Admin", map[string]string{"privilege_level": "admin"}),
			node(model.NodeAccount, "123456789012", nil),
		},
		Links:        []collect.Link{{SourceNativeID: "arn:aws:iam::123456789012:user/bob", TargetNativeID: "arn:aws:iam::123456789012:role/Admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "arn:aws:iam::123456789012:user/bob")
	if g == nil || g.Effect != model.EffectAllow {
		t.Errorf("admin grant with no account SCP cap = %v, want allow", g)
	}
}

// TestNoPrivilegeNoGrant proves a principal reaching only non-privileged roles
// gets no effective-privilege grant.
func TestNoPrivilegeNoGrant(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "user:bob", nil),
			node(model.NodeRole, "role:Reader", nil),
		},
		Links:        []collect.Link{{SourceNativeID: "user:bob", TargetNativeID: "role:Reader", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	if g := grantFor(EffectivePrivilege(norm(scan)), "user:bob"); g != nil {
		t.Errorf("a non-privileged principal got a grant: %v", g)
	}
}

// TestInlinePrivilegeGrant proves a principal's own inline-policy privilege is
// resolved even with no reachable privileged role.
func TestInlinePrivilegeGrant(t *testing.T) {
	scan := &collect.Scan{
		Nodes:        []collect.Node{node(model.NodeIdentity, "user:carol", map[string]string{"inline_privilege": "admin"})},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := grantFor(EffectivePrivilege(norm(scan)), "user:carol")
	if g == nil || g.Effect != model.EffectAllow || g.Action != "privilege:admin" {
		t.Errorf("inline admin grant = %v, want allow privilege:admin", g)
	}
}

// TestEffectivePrivilegeDeterministic proves the resolution is reproducible.
func TestEffectivePrivilegeDeterministic(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeIdentity, "u:b", nil),
			node(model.NodeIdentity, "u:a", map[string]string{"inline_privilege": "privileged"}),
			node(model.NodeRole, "r:x", map[string]string{"privilege_level": "admin"}),
		},
		Links:        []collect.Link{{SourceNativeID: "u:b", TargetNativeID: "r:x", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	a := EffectivePrivilege(norm(scan))
	for i := 0; i < 5; i++ {
		if !reflect.DeepEqual(a, EffectivePrivilege(norm(scan))) {
			t.Fatal("effective privilege is not deterministic")
		}
	}
}
