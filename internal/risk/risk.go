package risk

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// ModelVersion is the risk model's version. Every score records it, so a ranking is
// reproducible and attributable to a specific documented weighting (ADR-0027 §1).
const ModelVersion = 1

// dimWeight is one dimension's documented, versioned weight. The weights sum to 100.
type dimWeight struct {
	name   string
	weight int
}

// weights is the versioned dimension weight table (ADR-0027 §2). No opaque
// multiplication: each dimension contributes a visible, separately weighted sub-score.
// The three reserved dimensions have no honest signal yet and are weighted zero, named
// so the decomposition stays intact and the model never fabricates a weight for a
// signal it does not have (RC-1..RC-3).
var weights = []dimWeight{
	{"severity", 50},
	{"exposure", 20},
	{"business_impact", 30},
	{"exploitability", 0},   // RC-1: reserved, no verified-reachability signal yet
	{"blast_radius", 0},     // RC-2: reserved, no graph-fan-out signal yet
	{"threat_relevance", 0}, // RC-3: reserved, no threat-intelligence signal yet
}

// Inputs are the observed facts a risk score composes from. They are passed by value:
// Compute never mutates them and never reaches back to any engine's records. Unknown
// or empty sub-signals contribute nothing (never a fabricated high, never a silent low).
type Inputs struct {
	State           model.Outcome
	Severity        model.Severity
	Confidence      model.Confidence
	InternetExposed bool
	AllPortsExposed bool
	Sensitivity     model.Sensitivity // "" or unknown contributes nothing (honest-unknown)
	Privilege       string            // "admin" / "privileged" / "" (from privilege_level)
	Criticality     int               // business-criticality override level (0 = none)
}

// Score is a computed risk: a 0..100 value, the model version, and a transparent basis
// naming every dimension's sub-score and weight.
type Score struct {
	Value   int
	Version int
	Basis   []string
}

// Compute returns the risk score for a finding's inputs (ADR-0027). It is pure and
// deterministic: it composes separately weighted dimension sub-scores (documented,
// versioned, no opaque multiplication), discounts by evidence confidence, and records
// the full derivation in Basis. It never changes an input, and never overstates from an
// unknown: an unknown sub-signal contributes zero. A pass or not-applicable outcome has
// no risk.
func Compute(in Inputs) Score {
	if in.State == model.Pass || in.State == model.NotApplicable {
		return Score{Value: 0, Version: ModelVersion, Basis: []string{"state=" + string(in.State) + ": not a risk"}}
	}
	sub := map[string]int{
		"severity":        severityScore(in.Severity),
		"exposure":        exposureScore(in),
		"business_impact": impactScore(in),
	}
	weighted := 0
	basis := make([]string, 0, len(weights)+2)
	for _, dw := range weights {
		weighted += dw.weight * sub[dw.name] // reserved dims are absent from sub -> 0
		if dw.weight == 0 {
			basis = append(basis, dw.name+"=reserved(weight 0)")
		} else {
			basis = append(basis, fmt.Sprintf("%s=%d(weight %d)", dw.name, sub[dw.name], dw.weight))
		}
	}
	base := weighted / 100 // weights sum to 100, so this is a 0..100 weighted average
	// Evidence confidence discounts priority: a less certain finding ranks lower. This
	// is the one multiplication, and it is documented, not opaque.
	value := base * int(in.Confidence) / 100
	basis = append(basis, fmt.Sprintf("confidence=%d(discount)", int(in.Confidence)))
	basis = append(basis, "model_version="+strconv.Itoa(ModelVersion))
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	return Score{Value: value, Version: ModelVersion, Basis: basis}
}

func severityScore(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 100
	case model.SeverityHigh:
		return 75
	case model.SeverityMedium:
		return 45
	case model.SeverityLow:
		return 20
	}
	return 0 // unknown or missing severity contributes nothing, never a fabricated high
}

func exposureScore(in Inputs) int {
	switch {
	case in.AllPortsExposed:
		return 100
	case in.InternetExposed:
		return 70
	}
	return 0
}

// impactScore composes business impact from the affected asset's data sensitivity,
// effective privilege, and business criticality, each a documented contribution, capped
// at 100. An unknown sensitivity contributes zero: never treated as high, never as low.
func impactScore(in Inputs) int {
	score := 0
	switch in.Sensitivity {
	case model.SensitivityHigh:
		score += 50
	case model.SensitivityModerate:
		score += 30
	case model.SensitivityLow:
		score += 10
		// SensitivityUnknown / "": 0 (honest-unknown)
	}
	switch in.Privilege {
	case "admin":
		score += 40
	case "privileged":
		score += 25
	}
	if in.Criticality > 0 {
		c := in.Criticality * 10
		if c > 40 {
			c = 40
		}
		score += c
	}
	if score > 100 {
		score = 100
	}
	return score
}

// ToFinding maps an observed finding to a model.Finding with its computed risk. It is
// the facts-unchanged boundary (ADR-0027 §5): State and Confidence are copied straight
// from the observation; Risk is the only value the risk model adds. Risk scoring is
// priority, never fact, so this mapping never derives State or Confidence from risk.
// It returns the Score too, so the caller can surface the transparent basis. (FirstSeen
// and Status are left zero: they belong to persistence and the finding lifecycle,
// deferred, not to risk scoring.)
func ToFinding(rule model.RuleRef, entity model.StableID, in Inputs, detail string) (model.Finding, Score) {
	sc := Compute(in)
	return model.Finding{
		SchemaVersion: model.SchemaVersion,
		Rule:          rule,
		Entity:        entity,
		State:         in.State,      // copied unchanged: risk never alters the observed outcome
		Risk:          sc.Value,      // the only value risk adds
		Confidence:    in.Confidence, // copied unchanged: risk never alters evidence confidence
		Detail:        detail,
	}, sc
}

// SortByRisk orders findings by risk descending, with a deterministic tiebreak (rule
// id, then entity), so the highest-priority findings come first and identical input
// yields identical order. It reorders only; it changes no finding's fields.
func SortByRisk(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Risk != fs[j].Risk {
			return fs[i].Risk > fs[j].Risk
		}
		if fs[i].Rule.RuleID != fs[j].Rule.RuleID {
			return fs[i].Rule.RuleID < fs[j].Rule.RuleID
		}
		return fs[i].Entity < fs[j].Entity
	})
}
