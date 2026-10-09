package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// agentLevel returns the effective_privilege_level materialized onto an agent, or "".
func agentLevel(g *normalize.NormalizedScan, agentNative string) string {
	for _, e := range g.Entities {
		if e.NativeID == agentNative {
			return e.Attributes["effective_privilege_level"]
		}
	}
	return ""
}

// awsAgentScan builds the real AWS shape: an ai_agent assumes a role, and the role reaches
// its privilege through an attached policy (privilege_level on the POLICY, over an assumes
// edge), which is how the AWS collectors emit it. roleAttrs lets a test add a boundary or a
// deny onto the role.
func awsAgentScan(roleAttrs map[string]string) *collect.Scan {
	return &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeAIAgent, "arn:aws:bedrock:us-east-1:1:agent/A", map[string]string{"source": "bedrock-agents"}),
			node(model.NodeRole, "arn:aws:iam::1:role/exec", roleAttrs),
			node(model.NodePolicy, "arn:aws:iam::aws:policy/AdministratorAccess", map[string]string{"privilege_level": "admin"}),
		},
		Links: []collect.Link{
			{SourceNativeID: "arn:aws:bedrock:us-east-1:1:agent/A", TargetNativeID: "arn:aws:iam::1:role/exec", Kind: model.EdgeAssumes},
			{SourceNativeID: "arn:aws:iam::1:role/exec", TargetNativeID: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: model.EdgeAssumes},
		},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
}

// TestMaterializeAgentPrivilegeAdmin proves an agent whose assumed role reaches an admin
// policy gets effective_privilege_level=admin (AWS shape: privilege on the policy, two hops).
func TestMaterializeAgentPrivilegeAdmin(t *testing.T) {
	g := norm(awsAgentScan(nil))
	MaterializeEffectivePrivilege(g)
	if got := agentLevel(g, "arn:aws:bedrock:us-east-1:1:agent/A"); got != "admin" {
		t.Errorf("agent effective_privilege_level = %q, want admin", got)
	}
}

// TestMaterializeAgentPrivilegeBoundaryCap is a mutation target (ADR-0022 deny semantics): an
// admin role capped by a read-only permission boundary must NOT leave the agent at admin.
// Dropping the boundary cap in applyCaps makes this fail.
func TestMaterializeAgentPrivilegeBoundaryCap(t *testing.T) {
	scan := awsAgentScan(map[string]string{"permission_boundary": "arn:aws:iam::1:policy/boundary"})
	// The boundary policy was read and is read-only (no privilege_level): it caps admin.
	scan.Nodes = append(scan.Nodes, node(model.NodePolicy, "arn:aws:iam::1:policy/boundary", map[string]string{"document_read": "true"}))
	g := norm(scan)
	MaterializeEffectivePrivilege(g)
	if got := agentLevel(g, "arn:aws:bedrock:us-east-1:1:agent/A"); got == "admin" {
		t.Errorf("CRITICAL: agent at admin despite a read-only permission boundary (cap dropped?); got %q", got)
	}
}

// TestMaterializeAgentPrivilegeDenyOverride is a mutation target: an explicit deny at the
// granted level removes the privilege, so the agent must NOT be admin. Dropping the deny
// override makes this fail.
func TestMaterializeAgentPrivilegeDenyOverride(t *testing.T) {
	g := norm(awsAgentScan(map[string]string{"deny_privilege_level": "admin"}))
	MaterializeEffectivePrivilege(g)
	if got := agentLevel(g, "arn:aws:bedrock:us-east-1:1:agent/A"); got == "admin" || got == "privileged" {
		t.Errorf("CRITICAL: agent retains %q despite an explicit deny (deny override dropped?)", got)
	}
}

// TestMaterializeAgentPrivilegeRoleNodeShape proves the cloud-agnostic path: when the role
// node itself carries privilege_level (the Azure/GCP shape), the agent still gets it. This
// is why the materialization will work for Azure/GCP agents once those collectors emit
// ai_agent nodes with an assumes edge to a role, without changing this code.
func TestMaterializeAgentPrivilegeRoleNodeShape(t *testing.T) {
	scan := &collect.Scan{
		Nodes: []collect.Node{
			node(model.NodeAIAgent, "agent:azure", nil),
			node(model.NodeRole, "role:Owner", map[string]string{"privilege_level": "admin"}),
		},
		Links:        []collect.Link{{SourceNativeID: "agent:azure", TargetNativeID: "role:Owner", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := norm(scan)
	MaterializeEffectivePrivilege(g)
	if got := agentLevel(g, "agent:azure"); got != "admin" {
		t.Errorf("role-node-shape agent effective_privilege_level = %q, want admin", got)
	}
}

// TestMaterializeAgentPrivilegeNoRole proves an agent with no assumed role gets no fact (not
// a false empty or a zero-value admin).
func TestMaterializeAgentPrivilegeNoRole(t *testing.T) {
	scan := &collect.Scan{
		Nodes:        []collect.Node{node(model.NodeAIAgent, "agent:bare", nil)},
		Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Complete}},
	}
	g := norm(scan)
	MaterializeEffectivePrivilege(g)
	if got := agentLevel(g, "agent:bare"); got != "" {
		t.Errorf("agent with no role got effective_privilege_level = %q, want empty", got)
	}
}
