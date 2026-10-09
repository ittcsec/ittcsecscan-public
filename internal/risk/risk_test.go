package risk

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestComputeTransparentAndVersioned proves a score carries a visible basis naming
// each dimension and weight, the model version, and the reserved-at-zero dimensions,
// so a risk number is never a black box.
func TestComputeTransparentAndVersioned(t *testing.T) {
	sc := Compute(Inputs{State: model.Fail, Severity: model.SeverityHigh, Confidence: 100, InternetExposed: true, Sensitivity: model.SensitivityHigh})
	if sc.Version != ModelVersion {
		t.Errorf("version = %d, want %d", sc.Version, ModelVersion)
	}
	joined := strings.Join(sc.Basis, " | ")
	for _, want := range []string{"severity=75(weight 50)", "exposure=70(weight 20)", "business_impact=", "exploitability=reserved(weight 0)", "confidence=100", "model_version=1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("basis missing %q: %s", want, joined)
		}
	}
}

// TestComputeConfidenceDiscountsNeverInflates proves evidence confidence lowers risk
// and never raises it above the undiscounted base. Mutation target: a flip that
// multiplies up, or ignores confidence, breaks this.
func TestComputeConfidenceDiscountsNeverInflates(t *testing.T) {
	in := Inputs{State: model.Fail, Severity: model.SeverityCritical, Confidence: 100, AllPortsExposed: true, Sensitivity: model.SensitivityHigh, Privilege: "admin"}
	full := Compute(in).Value
	in.Confidence = 50
	half := Compute(in).Value
	if half >= full {
		t.Errorf("confidence 50 (%d) should discount below confidence 100 (%d)", half, full)
	}
	if half > full {
		t.Error("confidence must never inflate risk")
	}
}

// TestComputeHonestUnknown is the honest-unknown guard: an unknown sensitivity
// contributes nothing to impact (never a fabricated high, never a silent low). A
// finding on a high-sensitivity asset must outrank the same finding on an
// unknown-sensitivity asset. Mutation target: treating unknown as high breaks this.
func TestComputeHonestUnknown(t *testing.T) {
	base := Inputs{State: model.Fail, Severity: model.SeverityHigh, Confidence: 100, InternetExposed: true}
	high := base
	high.Sensitivity = model.SensitivityHigh
	unknown := base
	unknown.Sensitivity = model.SensitivityUnknown
	empty := base // sensitivity ""
	if Compute(high).Value <= Compute(unknown).Value {
		t.Errorf("high-sensitivity risk (%d) must exceed unknown-sensitivity risk (%d)", Compute(high).Value, Compute(unknown).Value)
	}
	if Compute(unknown).Value != Compute(empty).Value {
		t.Error("unknown sensitivity must contribute the same as absent (zero), never a fabricated value")
	}
}

// TestComputePassAndNAHaveNoRisk proves a pass or not-applicable outcome scores zero.
func TestComputePassAndNAHaveNoRisk(t *testing.T) {
	for _, st := range []model.Outcome{model.Pass, model.NotApplicable} {
		if v := Compute(Inputs{State: st, Severity: model.SeverityCritical, Confidence: 100, AllPortsExposed: true}).Value; v != 0 {
			t.Errorf("state %s risk = %d, want 0", st, v)
		}
	}
}

// TestToFindingNeverAltersFacts is the safety-critical facts-unchanged boundary: the
// mapping copies State and Confidence straight from the observation and adds only Risk.
// Mutation target: deriving State or Confidence from risk breaks this.
func TestToFindingNeverAltersFacts(t *testing.T) {
	in := Inputs{State: model.Fail, Severity: model.SeverityLow, Confidence: 42, InternetExposed: false}
	f, sc := ToFinding(model.RuleRef{RuleID: "R", Version: "1", PackID: "p"}, "entity-1", in, "detail")
	if f.State != model.Fail {
		t.Errorf("mapping altered state: %s, want fail", f.State)
	}
	if f.Confidence != 42 {
		t.Errorf("mapping altered confidence: %d, want 42", f.Confidence)
	}
	if f.Risk != sc.Value {
		t.Errorf("finding risk %d != computed %d", f.Risk, sc.Value)
	}
	// A high-risk score must not bleed into confidence or state.
	in2 := Inputs{State: model.Fail, Severity: model.SeverityCritical, Confidence: 10, AllPortsExposed: true, Privilege: "admin", Sensitivity: model.SensitivityHigh}
	f2, _ := ToFinding(model.RuleRef{RuleID: "R"}, "e2", in2, "")
	if f2.Confidence != 10 || f2.State != model.Fail {
		t.Errorf("risk bled into observed facts: state=%s confidence=%d", f2.State, f2.Confidence)
	}
}

// TestSortByRiskDescDeterministic proves risk-descending order with a deterministic
// tiebreak, reordering only.
func TestSortByRiskDescDeterministic(t *testing.T) {
	fs := []model.Finding{
		{Rule: model.RuleRef{RuleID: "B"}, Entity: "e", Risk: 10},
		{Rule: model.RuleRef{RuleID: "A"}, Entity: "e", Risk: 90},
		{Rule: model.RuleRef{RuleID: "A"}, Entity: "d", Risk: 90},
	}
	SortByRisk(fs)
	if fs[0].Risk != 90 || fs[1].Risk != 90 || fs[2].Risk != 10 {
		t.Errorf("not risk-descending: %+v", fs)
	}
	// tiebreak: same risk -> rule id then entity
	if fs[0].Entity != "d" || fs[1].Entity != "e" {
		t.Errorf("tiebreak not deterministic (entity order): %+v", fs)
	}
}
