package pack

import (
	"crypto/ed25519"
	"os"
	"testing"
	"testing/fstest"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/rules"
)

// The ai-guard pack (ADR-0033) is now embedded in packs.FS and signed by the offline pack
// key; that it ships signed and verifies under the shipped trust root is covered by
// TestEmbeddedPacksAreSignedAndVerify. These tests independently load the real committed
// pack files out-of-band, signing the manifest with an in-process test key, exactly the
// trust mechanism external packs use (pack.Load). They prove the shipped rules parse,
// verify, their manifest digests match, and they evaluate correctly.

const aiGuardDir = "../../../packs/ai-guard"

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads committed in-repo pack files by a constant relative path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// loadAIGuard loads the real committed ai-guard pack via pack.Load using a fresh test
// key, so the committed manifest digests and rule vocabulary are exercised for real.
func loadAIGuard(t *testing.T) []rules.Rule {
	t.Helper()
	manifest := mustRead(t, aiGuardDir+"/manifest.json")
	files := map[string][]byte{
		"ai-guard/manifest.json":                           manifest,
		"ai-guard/rules/ai_agent_excessive_privilege.json": mustRead(t, aiGuardDir+"/rules/ai_agent_excessive_privilege.json"),
		"ai-guard/rules/ai_agent_unsafe_tool.json":         mustRead(t, aiGuardDir+"/rules/ai_agent_unsafe_tool.json"),
		"ai-guard/rules/ai_agent_dangerous_data.json":      mustRead(t, aiGuardDir+"/rules/ai_agent_dangerous_data.json"),
	}
	priv, pub := genKey(t)
	sig := signArmored(t, priv, PackNamespace, "sha512", manifest)
	fsys := fstest.MapFS{}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: data}
	}
	fsys["ai-guard/manifest.json.sig"] = &fstest.MapFile{Data: sig}
	pk, err := Load([]ed25519.PublicKey{pub}, fsys, "ai-guard")
	if err != nil {
		t.Fatalf("ai-guard pack did not load: %v", err)
	}
	return pk.Rules
}

// TestAIGuardPackLoads proves the committed pack parses, verifies, its digests match,
// and all three rules validate (their node types, edge kinds, and facts are real).
func TestAIGuardPackLoads(t *testing.T) {
	rs := loadAIGuard(t)
	want := map[string]bool{
		"AIG-AGENT-EXCESSIVE-PRIVILEGE": false,
		"AIG-TOOL-UNSAFE":               false,
		"AIG-DATA-DANGEROUS":            false,
	}
	for _, r := range rs {
		if _, ok := want[r.ID]; !ok {
			t.Errorf("unexpected rule %q", r.ID)
		}
		want[r.ID] = true
		if r.PackID != "ai-guard" {
			t.Errorf("rule %s pack id = %q", r.ID, r.PackID)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("rule %s failed validation: %v", r.ID, err)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("rule %s missing from the loaded pack", id)
		}
	}
}

func aiAgent(id string, attrs map[string]string) collect.Node {
	return collect.Node{Type: model.NodeAIAgent, NativeID: id, Attributes: attrs}
}
func toolNode(id string, attrs map[string]string) collect.Node {
	return collect.Node{Type: model.NodeTool, NativeID: id, Attributes: attrs}
}
func link(src, dst string, kind model.EdgeKind) collect.Link {
	return collect.Link{SourceNativeID: src, TargetNativeID: dst, Kind: kind}
}

// TestAIGuardToolUnsafe proves AIG-TOOL-UNSAFE fails for an agent wired to an enabled
// code-execution or cross-account tool, and passes for an agent whose only tool is a
// benign enabled tool. A mutation that let an unsafe tool pass breaks the fail assertion.
func TestAIGuardToolUnsafe(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:bad", map[string]string{"source": "bedrock-agents"}),
			toolNode("agent:bad/action-group/x", map[string]string{"state": "enabled", "code_execution": "true", "cross_account": "false"}),
			aiAgent("agent:good", map[string]string{"source": "bedrock-agents"}),
			toolNode("agent:good/action-group/y", map[string]string{"state": "enabled", "code_execution": "false", "cross_account": "false"}),
		},
		Links: []collect.Link{
			link("agent:bad", "agent:bad/action-group/x", model.EdgeInvokesTool),
			link("agent:good", "agent:good/action-group/y", model.EdgeInvokesTool),
		},
		Completeness: []collect.Completeness{
			{Service: "bedrock.agents", Status: collect.Complete},
			{Service: "bedrock.actionGroups", Status: collect.Complete},
		},
	}
	results, err := rules.Evaluate(nrm(scan), rs)
	if err != nil {
		t.Fatal(err)
	}
	if got := stateFor(results, "AIG-TOOL-UNSAFE", "agent:bad"); got != model.Fail {
		t.Errorf("unsafe tool agent = %s, want fail", got)
	}
	if got := stateFor(results, "AIG-TOOL-UNSAFE", "agent:good"); got != model.Pass {
		t.Errorf("benign tool agent = %s, want pass", got)
	}
}

// TestAIGuardToolCrossAccountFires proves the cross-account branch also fails.
func TestAIGuardToolCrossAccountFires(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:xa", nil),
			toolNode("agent:xa/action-group/x", map[string]string{"state": "enabled", "code_execution": "false", "cross_account": "true"}),
		},
		Links:        []collect.Link{link("agent:xa", "agent:xa/action-group/x", model.EdgeInvokesTool)},
		Completeness: []collect.Completeness{{Service: "bedrock.agents", Status: collect.Complete}, {Service: "bedrock.actionGroups", Status: collect.Complete}},
	}
	results, _ := rules.Evaluate(nrm(scan), rs)
	if got := stateFor(results, "AIG-TOOL-UNSAFE", "agent:xa"); got != model.Fail {
		t.Errorf("cross-account tool agent = %s, want fail", got)
	}
}

// TestAIGuardToolDisabledPasses proves a disabled unsafe tool does not fire (state gates).
func TestAIGuardToolDisabledPasses(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:dis", nil),
			toolNode("agent:dis/action-group/x", map[string]string{"state": "disabled", "code_execution": "true", "cross_account": "true"}),
		},
		Links:        []collect.Link{link("agent:dis", "agent:dis/action-group/x", model.EdgeInvokesTool)},
		Completeness: []collect.Completeness{{Service: "bedrock.agents", Status: collect.Complete}, {Service: "bedrock.actionGroups", Status: collect.Complete}},
	}
	results, _ := rules.Evaluate(nrm(scan), rs)
	if got := stateFor(results, "AIG-TOOL-UNSAFE", "agent:dis"); got != model.Pass {
		t.Errorf("disabled tool agent = %s, want pass", got)
	}
}

// TestAIGuardDataDangerous proves AIG-DATA-DANGEROUS fails for an agent connected to a
// sensitive, internet-exposed, or external data store, and passes otherwise.
func TestAIGuardDataDangerous(t *testing.T) {
	rs := loadAIGuard(t)
	ds := func(id string, a map[string]string) collect.Node {
		return collect.Node{Type: model.NodeDataStore, NativeID: id, Attributes: a}
	}
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:sens", nil), ds("bucket:sens", map[string]string{"sensitivity": "high"}),
			aiAgent("agent:ext", nil), ds("ext:web", map[string]string{"external": "true"}),
			aiAgent("agent:clean", nil), ds("bucket:clean", map[string]string{"sensitivity": "low"}),
		},
		Links: []collect.Link{
			link("agent:sens", "bucket:sens", model.EdgeAccessesData),
			link("agent:ext", "ext:web", model.EdgeAccessesData),
			link("agent:clean", "bucket:clean", model.EdgeAccessesData),
		},
		Completeness: []collect.Completeness{
			{Service: "bedrock.agents", Status: collect.Complete},
			{Service: "bedrock.knowledgeBases", Status: collect.Complete},
		},
	}
	results, _ := rules.Evaluate(nrm(scan), rs)
	for _, id := range []string{"agent:sens", "agent:ext"} {
		if got := stateFor(results, "AIG-DATA-DANGEROUS", id); got != model.Fail {
			t.Errorf("%s = %s, want fail", id, got)
		}
	}
	if got := stateFor(results, "AIG-DATA-DANGEROUS", "agent:clean"); got != model.Pass {
		t.Errorf("clean data agent = %s, want pass", got)
	}
}

// TestAIGuardExcessiveAgencyNotAssessed proves the excessive-agency rule reports
// not-assessed (never a false pass or fail) while the effective-privilege fact is not
// collected (ADR-0021 DE-1): the honest state until that engine layer emits it.
func TestAIGuardExcessiveAgencyNotAssessed(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:p", map[string]string{"effective_privilege_level": "admin"}),
		},
		Completeness: []collect.Completeness{
			{Service: "bedrock.agents", Status: collect.Complete},
			// iam.identities is NOT recorded: the privilege data was not collected, so the
			// rule cannot be assessed even though an effective_privilege_level fact is present.
		},
	}
	results, _ := rules.Evaluate(nrm(scan), rs)
	got := stateFor(results, "AIG-AGENT-EXCESSIVE-PRIVILEGE", "agent:p")
	if got == model.Pass || got == model.Fail {
		t.Fatalf("CRITICAL: excessive-agency = %s, must be not-assessed (never pass/fail) without the identity collection", got)
	}
	if got != model.NotApplicable {
		t.Errorf("excessive-agency = %s, want not_applicable (iam.identities absent)", got)
	}
}

// TestAIGuardExcessiveAgencyFires proves the rule fails for an agent whose materialized
// effective_privilege_level is admin or privileged, and passes for a benign agent, once the
// identity collection is complete. The effective_privilege_level fact is what
// graph.MaterializeEffectivePrivilege writes onto the agent (tested in internal/graph); here
// the rule is driven directly with that fact.
func TestAIGuardExcessiveAgencyFires(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:adm", map[string]string{"effective_privilege_level": "admin"}),
			aiAgent("agent:priv", map[string]string{"effective_privilege_level": "privileged"}),
			aiAgent("agent:ok", map[string]string{"effective_privilege_level": "read"}),
			aiAgent("agent:none", nil),
		},
		Completeness: []collect.Completeness{
			{Service: "bedrock.agents", Status: collect.Complete},
			{Service: "iam.identities", Status: collect.Complete},
		},
	}
	results, _ := rules.Evaluate(nrm(scan), rs)
	for _, id := range []string{"agent:adm", "agent:priv"} {
		if got := stateFor(results, "AIG-AGENT-EXCESSIVE-PRIVILEGE", id); got != model.Fail {
			t.Errorf("%s = %s, want fail", id, got)
		}
	}
	for _, id := range []string{"agent:ok", "agent:none"} {
		if got := stateFor(results, "AIG-AGENT-EXCESSIVE-PRIVILEGE", id); got != model.Pass {
			t.Errorf("%s = %s, want pass (not over-privileged)", id, got)
		}
	}
}

// TestAIGuardExcessiveAgencyEndToEnd drives the real collector output shapes through the
// whole pipeline (normalize, materialize, evaluate): an AWS agent that assumes a role whose
// attached policy is admin (privilege_level on the POLICY, the real AWS shape) must produce
// a failing excessive-agency finding, because pipeline.Analyze runs
// graph.MaterializeEffectivePrivilege before the rules. This is the end-to-end proof the rule
// fires on real data, not just on a hand-placed fact.
func TestAIGuardExcessiveAgencyEndToEnd(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeAIAgent, NativeID: "arn:aws:bedrock:us-east-1:1:agent/A", Attributes: map[string]string{"source": "bedrock-agents"}},
			{Type: model.NodeRole, NativeID: "arn:aws:iam::1:role/exec"},
			{Type: model.NodePolicy, NativeID: "arn:aws:iam::aws:policy/AdministratorAccess", Attributes: map[string]string{"privilege_level": "admin"}},
		},
		Links: []collect.Link{
			{SourceNativeID: "arn:aws:bedrock:us-east-1:1:agent/A", TargetNativeID: "arn:aws:iam::1:role/exec", Kind: model.EdgeAssumes},
			{SourceNativeID: "arn:aws:iam::1:role/exec", TargetNativeID: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: model.EdgeAssumes},
		},
		Completeness: []collect.Completeness{
			{Service: "bedrock.agents", Status: collect.Complete},
			{Service: "iam.identities", Status: collect.Complete},
		},
	}
	res, err := pipeline.Analyze(nrm(scan), nil, rs)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, rf := range res.RankedFindings {
		if rf.Finding.Rule.RuleID == "AIG-AGENT-EXCESSIVE-PRIVILEGE" && rf.Native == "arn:aws:bedrock:us-east-1:1:agent/A" {
			found = true
			if rf.Finding.State != model.Fail {
				t.Errorf("excessive-agency end-to-end = %s, want fail", rf.Finding.State)
			}
		}
	}
	if !found {
		t.Error("no excessive-agency finding for the admin-role agent end-to-end")
	}
}

// TestAIGuardHonestUnknownOnDeniedCollection proves a denied action-group collection
// yields unknown, never a false pass, for an otherwise-unsafe tool.
func TestAIGuardHonestUnknownOnDeniedCollection(t *testing.T) {
	rs := loadAIGuard(t)
	scan := &collect.Scan{
		Nodes: []collect.Node{
			aiAgent("agent:u", nil),
			toolNode("agent:u/action-group/x", map[string]string{"state": "enabled", "code_execution": "true"}),
		},
		Links: []collect.Link{link("agent:u", "agent:u/action-group/x", model.EdgeInvokesTool)},
		Completeness: []collect.Completeness{
			{Service: "bedrock.agents", Status: collect.Complete},
			{Service: "bedrock.actionGroups", Status: collect.Denied},
		},
	}
	results, _ := rules.Evaluate(nrm(scan), rs)
	got := stateFor(results, "AIG-TOOL-UNSAFE", "agent:u")
	if got == model.Pass {
		t.Fatalf("CRITICAL: denied collection yielded pass; must be unknown")
	}
	if got != model.OutcomeUnknown {
		t.Errorf("denied action-group collection = %s, want unknown", got)
	}
}
