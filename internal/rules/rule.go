package rules

import "github.com/ittcsec/ittcsecscan/internal/model"

// Op is one operator from the closed predicate set. The set is fixed in this file; a
// pack cannot introduce a new operator (that is an engine change under review), which
// is what makes evaluation deterministic and free of any call site (ADR-0021 §3). Each
// operator is a pure function of already-collected graph data: no I/O, no clock, no
// randomness, and bounded (has_edge follows exactly one hop).
type Op string

const (
	// Logical combinators over child predicates.
	OpAnd Op = "and"
	OpOr  Op = "or"
	OpNot Op = "not"

	// Fact tests over a node's attributes (the facts collectors set). A fact's value
	// is the collected string; comparisons are exact and total, never fuzzy.
	OpFactEquals   Op = "fact_equals"   // node has fact == value
	OpFactIn       Op = "fact_in"       // node's fact value is one of values
	OpFactPresent  Op = "fact_present"  // node has the fact (any value)
	OpFactAbsent   Op = "fact_absent"   // node does not have the fact
	OpFactContains Op = "fact_contains" // node's fact (a comma-joined list or string) contains value as a member/substring
	OpFactNum      Op = "fact_num"      // node's fact parses as a number and compares (cmp) to value

	// OpHasEdge is the one bounded graph join: the entity has an outgoing link of Edge
	// to a node that matches Target (its node type and optional predicate). Exactly one
	// hop; no recursion beyond the target's own (bounded) predicate.
	OpHasEdge Op = "has_edge"
)

// Ops is every operator, in code order. A predicate naming an operator not in this set
// fails validation at load, never at evaluation.
var Ops = []Op{OpAnd, OpOr, OpNot, OpFactEquals, OpFactIn, OpFactPresent, OpFactAbsent, OpFactContains, OpFactNum, OpHasEdge}

// Valid reports whether o is a known operator.
func (o Op) Valid() bool {
	for _, k := range Ops {
		if k == o {
			return true
		}
	}
	return false
}

// numeric comparators for OpFactNum.
const (
	CmpLT = "lt"
	CmpLE = "le"
	CmpGT = "gt"
	CmpGE = "ge"
	CmpEQ = "eq"
	CmpNE = "ne"
)

// Predicate is a boolean tree over the closed operator set. It is data: it describes a
// test, it does not contain code. The zero value is not a valid predicate; Validate
// checks well-formedness before any evaluation.
type Predicate struct {
	Op       Op             `json:"op"`
	Children []Predicate    `json:"children,omitempty"` // and / or / not
	Fact     string         `json:"fact,omitempty"`     // fact_* operators
	Value    string         `json:"value,omitempty"`    // fact_equals / fact_contains / fact_num threshold
	Values   []string       `json:"values,omitempty"`   // fact_in
	Cmp      string         `json:"cmp,omitempty"`      // fact_num comparator (lt/le/gt/ge/eq/ne)
	Edge     model.EdgeKind `json:"edge,omitempty"`     // has_edge
	Target   *Selector      `json:"target,omitempty"`   // has_edge far node
}

// Selector picks the entities a rule (or a has_edge target) evaluates: nodes of a type,
// optionally pre-filtered by a predicate. One finding is produced per selected entity.
type Selector struct {
	NodeType  model.NodeType `json:"node_type"`
	Predicate *Predicate     `json:"predicate,omitempty"`
}

// Requirements is a rule's input contract (ADR-0021 §1, §5): the node types and edge
// kinds it reads, and the completeness services whose records populate those inputs.
// The engine reconciles Completeness against the scan to drive honest unknown /
// not-applicable states, so a rule declares what it needs and the engine, not the rule,
// enforces the honest state.
type Requirements struct {
	Nodes        []model.NodeType `json:"nodes,omitempty"`
	Edges        []model.EdgeKind `json:"edges,omitempty"`
	Completeness []string         `json:"completeness"`
}

// ConfidenceFactor is one deterministic contributor to a finding's confidence: if When
// holds on the entity, Delta is added to the running score. Factors are recorded in the
// finding's trace, so the number always has a stated, reproducible basis (ADR-0021 §6).
type ConfidenceFactor struct {
	Name  string    `json:"name"`
	When  Predicate `json:"when"`
	Delta int       `json:"delta"`
}

// ConfidenceModel computes a finding's confidence from a fixed base plus fixed-weight
// factors. It is a documented function of the evidence (directness, completeness,
// corroboration), never a probability estimate.
type ConfidenceModel struct {
	Base    model.Confidence   `json:"base"`
	Factors []ConfidenceFactor `json:"factors,omitempty"`
}

// Rule is one declarative detection. Selector picks the entities; Predicate is the
// condition that, when it holds on an entity with complete evidence, makes the finding
// a fail (otherwise a pass). Requires is the input contract; Confidence is the scoring
// model. A rule is data, validated at load and evaluated by the engine's interpreter.
type Rule struct {
	ID         string          `json:"id"`
	Version    string          `json:"version"`
	PackID     string          `json:"pack_id"`
	Title      string          `json:"title"`
	Detail     string          `json:"detail,omitempty"`
	Severity   model.Severity  `json:"severity"`
	Selector   Selector        `json:"selector"`
	Predicate  Predicate       `json:"predicate"`
	Requires   Requirements    `json:"requires"`
	Confidence ConfidenceModel `json:"confidence"`
	// Indeterminate is an optional per-node honesty gate. When coverage is complete, a
	// selected node that matches Indeterminate is reported Unknown (never pass and never
	// fail), because the deciding data for that node is missing, a sentinel, or
	// unresolved. This expresses per-node unknown for a Complete scan, distinct from the
	// rule-level unknown that a gap in required completeness already drives. A node is
	// evaluated against Indeterminate before Predicate, so an undeterminable node is
	// never silently passed.
	Indeterminate *Predicate `json:"indeterminate,omitempty"`
}

// Ref is the rule's stable reference for a finding (maps to model.RuleRef).
func (r Rule) Ref() model.RuleRef {
	return model.RuleRef{RuleID: r.ID, Version: r.Version, PackID: r.PackID}
}
