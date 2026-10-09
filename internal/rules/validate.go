package rules

import "fmt"

// maxPredicateDepth bounds a predicate tree so evaluation is total and cheap; no real
// rule needs deep nesting, and the bound removes any doubt about termination.
const maxPredicateDepth = 32

// Validate reports whether a rule is well-formed: it names a real node type, its
// predicate uses only known operators with the fields each requires, every referenced
// edge kind and node type is valid, and it declares at least one completeness service
// (its input contract, ADR-0021 §1). A rule that fails Validate is refused at load, so
// a malformed or vocabulary-inventing rule never reaches evaluation.
func (r Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule has no id")
	}
	if r.Version == "" {
		return fmt.Errorf("rule %s has no version", r.ID)
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("rule %s has an unknown or missing severity %q (critical, high, medium, or low)", r.ID, r.Severity)
	}
	if !r.Selector.NodeType.Valid() {
		return fmt.Errorf("rule %s selects unknown node type %q", r.ID, r.Selector.NodeType)
	}
	if r.Selector.Predicate != nil {
		if err := r.Selector.Predicate.validate(0); err != nil {
			return fmt.Errorf("rule %s selector: %w", r.ID, err)
		}
	}
	if err := r.Predicate.validate(0); err != nil {
		return fmt.Errorf("rule %s predicate: %w", r.ID, err)
	}
	if r.Indeterminate != nil {
		if err := r.Indeterminate.validate(0); err != nil {
			return fmt.Errorf("rule %s indeterminate: %w", r.ID, err)
		}
	}
	if len(r.Requires.Completeness) == 0 {
		return fmt.Errorf("rule %s declares no completeness inputs (its input contract)", r.ID)
	}
	for _, nt := range r.Requires.Nodes {
		if !nt.Valid() {
			return fmt.Errorf("rule %s requires unknown node type %q", r.ID, nt)
		}
	}
	for _, ek := range r.Requires.Edges {
		if !ek.Valid() {
			return fmt.Errorf("rule %s requires unknown edge kind %q", r.ID, ek)
		}
	}
	if !r.Confidence.Base.Valid() {
		return fmt.Errorf("rule %s base confidence %d out of range", r.ID, r.Confidence.Base)
	}
	for _, f := range r.Confidence.Factors {
		if err := f.When.validate(0); err != nil {
			return fmt.Errorf("rule %s confidence factor %q: %w", r.ID, f.Name, err)
		}
	}
	return nil
}

// validate checks one predicate node and its subtree.
func (p Predicate) validate(depth int) error {
	if depth > maxPredicateDepth {
		return fmt.Errorf("predicate nested deeper than %d", maxPredicateDepth)
	}
	if !p.Op.Valid() {
		return fmt.Errorf("unknown operator %q", p.Op)
	}
	switch p.Op {
	case OpAnd, OpOr:
		if len(p.Children) == 0 {
			return fmt.Errorf("%s needs at least one child", p.Op)
		}
	case OpNot:
		if len(p.Children) != 1 {
			return fmt.Errorf("not needs exactly one child")
		}
	case OpFactEquals, OpFactContains:
		if p.Fact == "" {
			return fmt.Errorf("%s needs a fact", p.Op)
		}
	case OpFactPresent, OpFactAbsent:
		if p.Fact == "" {
			return fmt.Errorf("%s needs a fact", p.Op)
		}
	case OpFactIn:
		if p.Fact == "" || len(p.Values) == 0 {
			return fmt.Errorf("fact_in needs a fact and values")
		}
	case OpFactNum:
		if p.Fact == "" {
			return fmt.Errorf("fact_num needs a fact")
		}
		switch p.Cmp {
		case CmpLT, CmpLE, CmpGT, CmpGE, CmpEQ, CmpNE:
		default:
			return fmt.Errorf("fact_num has unknown comparator %q", p.Cmp)
		}
	case OpHasEdge:
		if !p.Edge.Valid() {
			return fmt.Errorf("has_edge names unknown edge kind %q", p.Edge)
		}
		if p.Target == nil || !p.Target.NodeType.Valid() {
			return fmt.Errorf("has_edge needs a target with a known node type")
		}
		if p.Target.Predicate != nil {
			if err := p.Target.Predicate.validate(depth + 1); err != nil {
				return err
			}
		}
	}
	for _, c := range p.Children {
		if err := c.validate(depth + 1); err != nil {
			return err
		}
	}
	return nil
}
