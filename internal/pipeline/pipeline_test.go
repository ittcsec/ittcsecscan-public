package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
	"github.com/ittcsec/ittcsecscan/internal/rules"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/packs"
)

type keyer struct{}

func (keyer) StableID(nativeID string) (model.StableID, error) {
	sum := sha256.Sum256([]byte(nativeID))
	return model.StableID(hex.EncodeToString(sum[:])), nil
}

func norm(t *testing.T, scan collect.Scan) *normalize.NormalizedScan {
	g, err := normalize.Normalize(scan, keyer{}, normalize.Meta{})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return &g
}

func builtinRules(t *testing.T) []rules.Rule {
	rs, err := pack.LoadBuiltinAll(packs.FS, nil)
	if err != nil {
		t.Fatalf("load builtin packs: %v", err)
	}
	return rs
}

func resultFor(res Result, ruleID, entityNative string) (rules.Result, bool) {
	for _, r := range res.Findings {
		if r.Rule.RuleID == ruleID && r.EntityID == entityNative {
			return r, true
		}
	}
	return rules.Result{}, false
}

// awsAllPortsScan is an AWS instance with a security group open to 0.0.0.0/0 on every
// port, and the networking reads it needs marked complete.
func awsAllPortsScan(sgStatus collect.Status) collect.Scan {
	return collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeCompute, NativeID: "arn:aws:ec2:u:1:instance/i-open", Attributes: map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-open"}},
			{Type: model.NodeControl, NativeID: "sg-open", Attributes: map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"-1","from_port":0,"to_port":0,"cidr":"0.0.0.0/0"}]`}},
		},
		Completeness: []collect.Completeness{
			{Service: "ec2.instances", Status: collect.Complete},
			{Service: "ec2.securityGroups", Status: sgStatus},
			{Service: "ec2.networkAcls", Status: collect.Complete},
		},
	}
}

// TestExposureRuleFiresEndToEnd proves the full wiring: reachability is materialized
// onto the graph and the core-p0 exposure rule then fails the all-ports-open instance.
func TestExposureRuleFiresEndToEnd(t *testing.T) {
	g := norm(t, awsAllPortsScan(collect.Complete))
	res, err := Analyze(g, nil, builtinRules(t))
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	r, ok := resultFor(res, "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS", "arn:aws:ec2:u:1:instance/i-open")
	if !ok {
		t.Fatalf("no result for the exposure rule on the open instance; findings: %+v", res.Findings)
	}
	if r.State != model.Fail {
		t.Errorf("exposure rule state = %s, want fail", r.State)
	}
}

// TestExposureRuleUnknownOnDeniedRead proves the honest-state discipline survives the
// wiring: when a networking read the exposure decision needs is denied, the rule is
// unknown, never a pass.
func TestExposureRuleUnknownOnDeniedRead(t *testing.T) {
	g := norm(t, awsAllPortsScan(collect.Denied))
	res, err := Analyze(g, nil, builtinRules(t))
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	var seen bool
	for _, r := range res.Findings {
		if r.Rule.RuleID != "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS" {
			continue
		}
		seen = true
		if r.State == model.Pass {
			t.Errorf("denied security-group read produced a pass, want unknown: %+v", r)
		}
		if r.State != model.OutcomeUnknown {
			t.Errorf("state = %s, want unknown on a denied read", r.State)
		}
	}
	if !seen {
		t.Error("expected a rule-level result citing the denied read, got none")
	}
}

// TestAnalyzeScanEndToEnd proves the one-call collect.Scan -> findings path: a raw
// collected scan is normalized with the tenant keyer and analyzed, and the exposure
// rule fails the all-ports-open instance. (EntityID is the native id the engine
// reports; the keyer keys the internal graph joins to the tenant's stable ids.)
func TestAnalyzeScanEndToEnd(t *testing.T) {
	scan := awsAllPortsScan(collect.Complete)
	res, err := AnalyzeScan(scan, keyer{}, model.AWS, nil, builtinRules(t))
	if err != nil {
		t.Fatalf("analyze scan: %v", err)
	}
	r, ok := resultFor(res, "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS", "arn:aws:ec2:u:1:instance/i-open")
	if !ok {
		t.Fatalf("no exposure finding from AnalyzeScan; findings: %+v", res.Findings)
	}
	if r.State != model.Fail {
		t.Errorf("state = %s, want fail", r.State)
	}
}

// TestExposureRuleAbsentWithoutMateralize is a guard on the wiring contract: without
// the exposure materialization step, the exposure facts are absent and the rule
// selects nothing (it never invents a finding from missing facts).
func TestExposureRuleAbsentWithoutMaterialize(t *testing.T) {
	g := norm(t, awsAllPortsScan(collect.Complete))
	findings, err := rules.Evaluate(g, builtinRules(t)) // no Materialize
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for _, r := range findings {
		if r.Rule.RuleID == "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS" {
			t.Errorf("exposure rule produced a result without materialization: %+v", r)
		}
	}
}

// sensitiveDataStoreScan is an AWS S3 bucket declared restricted, with a plain
// bucket, and the read the classification and detection need marked complete.
func sensitiveDataStoreScan() collect.Scan {
	return collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeDataStore, NativeID: "arn:aws:s3:::secret", Attributes: map[string]string{"tag:data_classification": "restricted"}},
			{Type: model.NodeDataStore, NativeID: "arn:aws:s3:::plain", Attributes: map[string]string{"region": "us-east-1"}},
		},
		Completeness: []collect.Completeness{{Service: "s3.bucketConfig", Status: collect.Complete}},
	}
}

// sensitivityRule is a rule that consumes the materialized sensitivity fact.
func sensitivityRule() rules.Rule {
	return rules.Rule{
		ID: "TEST-HIGH-SENSITIVITY-DATASTORE", Version: "1", PackID: "test",
		Title:      "high-sensitivity data store",
		Severity:   model.SeverityHigh,
		Selector:   rules.Selector{NodeType: model.NodeDataStore},
		Predicate:  rules.Predicate{Op: rules.OpFactEquals, Fact: "sensitivity", Value: "high"},
		Requires:   rules.Requirements{Nodes: []model.NodeType{model.NodeDataStore}, Completeness: []string{"s3.bucketConfig"}},
		Confidence: rules.ConfidenceModel{Base: 80},
	}
}

// TestClassificationConsumedByDetection proves the detection engine consumes the
// materialized sensitivity fact end to end: a rule keyed on sensitivity=high fails
// the declared-restricted bucket and passes the plain one.
func TestClassificationConsumedByDetection(t *testing.T) {
	g := norm(t, sensitiveDataStoreScan())
	res, err := Analyze(g, nil, []rules.Rule{sensitivityRule()})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	sec, ok := resultFor(res, "TEST-HIGH-SENSITIVITY-DATASTORE", "arn:aws:s3:::secret")
	if !ok || sec.State != model.Fail {
		t.Errorf("sensitivity rule should fail the restricted bucket: %+v (ok=%v)", sec, ok)
	}
	plain, ok := resultFor(res, "TEST-HIGH-SENSITIVITY-DATASTORE", "arn:aws:s3:::plain")
	if !ok || plain.State != model.Pass {
		t.Errorf("sensitivity rule should pass the plain bucket (unknown sensitivity): %+v (ok=%v)", plain, ok)
	}
	// Classification result is surfaced alongside findings.
	if len(res.Classification.Classifications) == 0 {
		t.Error("classification result not returned from the pipeline")
	}
}

// TestOverridesAppliedInPipeline proves an audited criticality override reaches the
// graph through the pipeline, setting the entity's criticality.
func TestOverridesAppliedInPipeline(t *testing.T) {
	g := norm(t, sensitiveDataStoreScan())
	target, _ := keyer{}.StableID("arn:aws:s3:::plain")
	overrides := []model.CriticalityOverride{{Entity: target, Criticality: 9, Actor: "alice", Reason: "regulated"}}
	if _, err := Analyze(g, overrides, []rules.Rule{sensitivityRule()}); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, e := range g.Entities {
		if e.ID == target {
			if e.Criticality != 9 || e.Attributes["criticality_override_actor"] != "alice" {
				t.Errorf("override not applied through pipeline: crit=%d attrs=%+v", e.Criticality, e.Attributes)
			}
		}
	}
}

// exposedToAdminScan is an internet-exposed instance that assumes an admin role.
func exposedToAdminScan() collect.Scan {
	return collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeCompute, NativeID: "arn:aws:ec2:u:1:instance/i-1", Attributes: map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-open"}},
			{Type: model.NodeControl, NativeID: "sg-open", Attributes: map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"-1","from_port":0,"to_port":0,"cidr":"0.0.0.0/0"}]`}},
			{Type: model.NodeRole, NativeID: "arn:aws:iam::1:role/admin", Attributes: map[string]string{"privilege_level": "admin"}},
		},
		Links: []collect.Link{{SourceNativeID: "arn:aws:ec2:u:1:instance/i-1", TargetNativeID: "arn:aws:iam::1:role/admin", Kind: model.EdgeAssumes}},
		Completeness: []collect.Completeness{
			{Service: "ec2.instances", Status: collect.Complete}, {Service: "ec2.securityGroups", Status: collect.Complete},
			{Service: "ec2.networkAcls", Status: collect.Complete}, {Service: "iam.identities", Status: collect.Complete},
		},
	}
}

// TestPipelineProducesPathsAndCuts proves the pipeline runs the attack-path and cut
// engines end to end (also bringing Reach/EffectivePrivilege into the real pipeline).
func TestPipelineProducesPathsAndCuts(t *testing.T) {
	g := norm(t, exposedToAdminScan())
	res, err := Analyze(g, nil, builtinRules(t))
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.Paths.Paths) == 0 {
		t.Fatal("no attack paths from the pipeline")
	}
	if len(res.Cuts) == 0 {
		t.Fatal("no cut candidates from the pipeline")
	}
	if res.Paths.Paths[0].Score != 100 {
		t.Errorf("path score = %d, want 100 (admin target)", res.Paths.Paths[0].Score)
	}
}

// TestPipelineRanksFindingsByRisk proves findings come back risk-ordered with risk
// populated, and that ranking never alters an observed fact (state/confidence).
func TestPipelineRanksFindingsByRisk(t *testing.T) {
	g := norm(t, sensitiveDataStoreScan())
	res, err := Analyze(g, nil, []rules.Rule{sensitivityRule()})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.RankedFindings) == 0 {
		t.Fatal("no ranked findings")
	}
	top := res.RankedFindings[0]
	if top.Finding.State != model.Fail || top.Native != "arn:aws:s3:::secret" {
		t.Errorf("top finding should be the restricted bucket fail: %+v", top)
	}
	if top.Finding.Risk <= 0 {
		t.Errorf("top finding risk = %d, want > 0", top.Finding.Risk)
	}
	if len(top.Basis) == 0 {
		t.Error("top finding has no risk basis")
	}
	// Facts unchanged: confidence matches the rule's base confidence, state is the observed outcome.
	if top.Finding.Confidence != 80 {
		t.Errorf("ranking altered confidence: %d, want 80", top.Finding.Confidence)
	}
	// Descending risk order.
	for i := 1; i < len(res.RankedFindings); i++ {
		if res.RankedFindings[i-1].Finding.Risk < res.RankedFindings[i].Finding.Risk {
			t.Errorf("findings not risk-descending at %d: %d < %d", i, res.RankedFindings[i-1].Finding.Risk, res.RankedFindings[i].Finding.Risk)
		}
	}
}
