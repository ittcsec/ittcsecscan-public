package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// Evaluate runs every rule against a frozen, normalized scan and returns the findings
// in a fully deterministic order (rule id, then entity canonical id). It reads the
// canonical model graph (internal/normalize), not the raw collected graph, so no engine
// reads raw collection (ADR-0023). Given the same graph, rules, and engine, it returns
// byte-identical results in identical order: evaluation reads only collected data, uses
// no clock or randomness, and sorts every iteration (ADR-0021 §4). Every rule is
// validated first; an invalid rule is a caller error, not a silent skip.
//
// Honest state is enforced by the engine, not each rule: for each rule the engine
// reconciles the rule's declared completeness inputs against the scan (ADR-0021 §5). A
// pass or fail is produced only when every required input is Complete for the scan; a
// Denied, Partial, or Errored input yields unknown; an Unsupported or absent input
// yields not-applicable. A gap is never silently a pass, and never silently nothing:
// when a gap means no entities could be listed, one rule-level result still records it.
func Evaluate(g *normalize.NormalizedScan, ruleset []Rule) ([]Result, error) {
	for _, r := range ruleset {
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	v := newView(g)
	var comp []collect.Completeness
	if g != nil {
		comp = g.Completeness
	}

	ordered := append([]Rule(nil), ruleset...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].PackID != ordered[j].PackID {
			return ordered[i].PackID < ordered[j].PackID
		}
		return ordered[i].ID < ordered[j].ID
	})

	var out []Result
	for _, r := range ordered {
		out = append(out, evalRule(r, v, comp)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rule.RuleID != out[j].Rule.RuleID {
			return out[i].Rule.RuleID < out[j].Rule.RuleID
		}
		return out[i].EntityID < out[j].EntityID
	})
	return out, nil
}

func evalRule(r Rule, v *view, comp []collect.Completeness) []Result {
	cov := assessCoverage(r.Requires.Completeness, comp)
	entities := v.selectNodes(r.Selector)

	// Coverage gap: the deciding evidence was not fully collected. Never a pass or
	// fail; propagate the honest state and cite the gap.
	if !cov.complete {
		if len(entities) == 0 {
			// No entities could be listed (e.g. the list read was denied). Surface one
			// rule-level result so the gap is never silent.
			return []Result{{
				Rule:      r.Ref(),
				State:     cov.outcome,
				Grounding: Grounding{Completeness: cov.cited},
				Basis:     cov.cited,
				Trace:     []string{fmt.Sprintf("not assessed: required evidence incomplete (%s)", strings.Join(cov.cited, ", "))},
				Detail:    r.Detail,
			}}
		}
		res := make([]Result, 0, len(entities))
		for _, n := range entities {
			res = append(res, Result{
				Rule:       r.Ref(),
				EntityID:   n.NativeID,
				EntityType: n.Type,
				State:      cov.outcome,
				Grounding:  Grounding{Nodes: []string{n.NativeID}, Completeness: cov.cited},
				Basis:      cov.cited,
				Trace:      []string{fmt.Sprintf("%s %s: not assessed, required evidence incomplete (%s)", n.Type, n.NativeID, strings.Join(cov.cited, ", "))},
				Detail:     r.Detail,
			})
		}
		return res
	}

	// Coverage complete: decide pass/fail per entity from the predicate, but first the
	// per-node honesty gate: a selected node whose deciding data is missing, a sentinel,
	// or unresolved is Unknown, never silently passed.
	res := make([]Result, 0, len(entities))
	for _, n := range entities {
		g := Grounding{Nodes: []string{n.NativeID}, Completeness: cov.cited}
		var trace []string
		if r.Indeterminate != nil {
			var ig Grounding
			var itr []string
			if evalNode(*r.Indeterminate, n, v, &ig, &itr) {
				res = append(res, Result{
					Rule:       r.Ref(),
					EntityID:   n.NativeID,
					EntityType: n.Type,
					State:      model.OutcomeUnknown,
					Grounding:  Grounding{Nodes: []string{n.NativeID}, Facts: ig.Facts, Completeness: cov.cited},
					Basis:      cov.cited,
					Trace:      append([]string{fmt.Sprintf("%s %s: not assessed, the deciding data is missing, a sentinel, or unresolved", n.Type, n.NativeID)}, itr...),
					Detail:     r.Detail,
				})
				continue
			}
		}
		failed := evalNode(r.Predicate, n, v, &g, &trace)
		state := model.Pass
		if failed {
			state = model.Fail
		}
		conf, basis := confidence(r.Confidence, n, v)
		res = append(res, Result{
			Rule:       r.Ref(),
			EntityID:   n.NativeID,
			EntityType: n.Type,
			State:      state,
			Confidence: conf,
			Basis:      basis,
			Grounding:  g,
			Trace:      trace,
			Detail:     r.Detail,
		})
	}
	return res
}

// coverage is the reconciliation of a rule's required completeness inputs against the
// scan. complete is true only when every required service was Complete.
type coverage struct {
	complete bool
	outcome  model.Outcome // used only when !complete: unknown or not_applicable
	cited    []string      // "service:status" for each required input, sorted
}

func assessCoverage(required []string, comp []collect.Completeness) coverage {
	byService := map[string]collect.Status{}
	for _, c := range comp {
		// Keep the worst status seen for a service across scopes/regions, so one denied
		// scope makes the input not fully complete.
		if worst, ok := byService[c.Service]; !ok || statusRank(c.Status) > statusRank(worst) {
			byService[c.Service] = c.Status
		}
	}

	req := append([]string(nil), required...)
	sort.Strings(req)

	anyUnknown, anyNA, allComplete := false, false, true
	cited := make([]string, 0, len(req))
	for _, svc := range req {
		st, ok := byService[svc]
		if !ok {
			cited = append(cited, svc+":absent")
			anyNA = true
			allComplete = false
			continue
		}
		cited = append(cited, svc+":"+string(st))
		switch st {
		case collect.Complete:
		case collect.Denied, collect.Partial, collect.Errored:
			anyUnknown = true
			allComplete = false
		case collect.Unsupported:
			anyNA = true
			allComplete = false
		}
	}
	switch {
	case allComplete:
		return coverage{complete: true, cited: cited}
	case anyUnknown:
		return coverage{complete: false, outcome: model.OutcomeUnknown, cited: cited}
	case anyNA:
		return coverage{complete: false, outcome: model.NotApplicable, cited: cited}
	default:
		return coverage{complete: true, cited: cited}
	}
}

// statusRank orders statuses so the "worst" (most incomplete) wins when a service has
// several records: Complete is best, Errored worst.
func statusRank(s collect.Status) int {
	switch s {
	case collect.Complete:
		return 0
	case collect.Unsupported:
		return 1
	case collect.Partial:
		return 2
	case collect.Denied:
		return 3
	case collect.Errored:
		return 4
	}
	return 5
}

// edgeRef is an outgoing edge from a node, with its target already resolved to a
// canonical native id, so evaluation stays in native-id space even though the
// model graph keys edges by StableID.
type edgeRef struct {
	Kind           model.EdgeKind
	TargetNativeID string
}

// view is an indexed, read-only projection of a normalized scan for evaluation.
// Entities are indexed by their native id (the reporting key) and by type; edges
// are indexed by source native id, their StableID endpoints resolved back to
// native ids through the entity set.
type view struct {
	byID   map[string]model.Entity
	byType map[model.NodeType][]model.Entity
	out    map[string][]edgeRef
}

func newView(g *normalize.NormalizedScan) *view {
	v := &view{byID: map[string]model.Entity{}, byType: map[model.NodeType][]model.Entity{}, out: map[string][]edgeRef{}}
	if g == nil {
		return v
	}
	native := make(map[model.StableID]string, len(g.Entities))
	for _, e := range g.Entities {
		v.byID[e.NativeID] = e
		v.byType[e.Type] = append(v.byType[e.Type], e)
		native[e.ID] = e.NativeID
	}
	for t := range v.byType {
		nodes := v.byType[t]
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].NativeID < nodes[j].NativeID })
		v.byType[t] = nodes
	}
	for _, e := range g.Edges {
		src, ok1 := native[e.Source]
		dst, ok2 := native[e.Target]
		if !ok1 || !ok2 {
			// An endpoint outside the entity set. The normalizer already drops such
			// edges; skip defensively so evaluation never resolves a phantom.
			continue
		}
		v.out[src] = append(v.out[src], edgeRef{Kind: e.Kind, TargetNativeID: dst})
	}
	return v
}

// selectNodes returns the nodes a selector picks, sorted by canonical id.
func (v *view) selectNodes(s Selector) []model.Entity {
	candidates := v.byType[s.NodeType]
	if s.Predicate == nil {
		return candidates
	}
	var out []model.Entity
	for _, n := range candidates {
		var g Grounding
		var tr []string
		if evalNode(*s.Predicate, n, v, &g, &tr) {
			out = append(out, n)
		}
	}
	return out
}

// evalNode evaluates a predicate on a node, recording the facts and edges that
// supported a true result into g and a human-readable derivation into trace. It is a
// pure function of collected data: no I/O, no clock, no randomness.
func evalNode(p Predicate, n model.Entity, v *view, g *Grounding, trace *[]string) bool {
	switch p.Op {
	case OpAnd:
		for _, c := range p.Children {
			if !evalNode(c, n, v, g, trace) {
				return false
			}
		}
		return true
	case OpOr:
		ok := false
		for _, c := range p.Children {
			if evalNode(c, n, v, g, trace) {
				ok = true
			}
		}
		return ok
	case OpNot:
		// A sub-grounding so a false inner branch does not pollute the finding's facts.
		var ig Grounding
		var it []string
		return !evalNode(p.Children[0], n, v, &ig, &it)
	case OpFactEquals:
		if val, ok := n.Attributes[p.Fact]; ok && val == p.Value {
			record(g, trace, n, p.Fact, val)
			return true
		}
		return false
	case OpFactIn:
		if val, ok := n.Attributes[p.Fact]; ok {
			for _, w := range p.Values {
				if val == w {
					record(g, trace, n, p.Fact, val)
					return true
				}
			}
		}
		return false
	case OpFactPresent:
		if val, ok := n.Attributes[p.Fact]; ok {
			record(g, trace, n, p.Fact, val)
			return true
		}
		return false
	case OpFactAbsent:
		if _, ok := n.Attributes[p.Fact]; !ok {
			*trace = append(*trace, fmt.Sprintf("%s %s: fact %q is absent", n.Type, n.NativeID, p.Fact))
			g.Facts = append(g.Facts, fmt.Sprintf("%s absent on %s", p.Fact, n.NativeID))
			return true
		}
		return false
	case OpFactContains:
		if val, ok := n.Attributes[p.Fact]; ok && listContains(val, p.Value) {
			record(g, trace, n, p.Fact, val)
			return true
		}
		return false
	case OpFactNum:
		if val, ok := n.Attributes[p.Fact]; ok && numCompare(val, p.Cmp, p.Value) {
			record(g, trace, n, p.Fact, val)
			return true
		}
		return false
	case OpHasEdge:
		for _, l := range v.out[n.NativeID] {
			if l.Kind != p.Edge {
				continue
			}
			tgt, ok := v.byID[l.TargetNativeID]
			if !ok || tgt.Type != p.Target.NodeType {
				continue
			}
			if p.Target.Predicate == nil || evalNode(*p.Target.Predicate, tgt, v, g, trace) {
				g.Edges = append(g.Edges, fmt.Sprintf("%s -[%s]-> %s", n.NativeID, l.Kind, tgt.NativeID))
				g.Nodes = append(g.Nodes, tgt.NativeID)
				*trace = append(*trace, fmt.Sprintf("%s %s assumes/links via %s to %s %s", n.Type, n.NativeID, l.Kind, tgt.Type, tgt.NativeID))
				return true
			}
		}
		return false
	}
	return false
}

func record(g *Grounding, trace *[]string, n model.Entity, fact, val string) {
	g.Facts = append(g.Facts, fmt.Sprintf("%s=%s on %s", fact, val, n.NativeID))
	*trace = append(*trace, fmt.Sprintf("%s %s: fact %s=%q", n.Type, n.NativeID, fact, val))
}

// listContains reports whether value is a comma-separated member of s, or, failing
// that, a substring of s. Facts that hold lists are comma-joined by the collectors.
func listContains(s, value string) bool {
	for _, part := range strings.Split(s, ",") {
		if strings.TrimSpace(part) == value {
			return true
		}
	}
	return strings.Contains(s, value)
}

// numCompare parses s and threshold as numbers and applies cmp. A non-numeric fact
// value yields false (the numeric test simply does not hold), never an error.
func numCompare(s, cmp, threshold string) bool {
	a, err1 := strconv.ParseFloat(strings.TrimSpace(s), 64)
	b, err2 := strconv.ParseFloat(strings.TrimSpace(threshold), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch cmp {
	case CmpLT:
		return a < b
	case CmpLE:
		return a <= b
	case CmpGT:
		return a > b
	case CmpGE:
		return a >= b
	case CmpEQ:
		return a == b
	case CmpNE:
		return a != b
	}
	return false
}

// confidence computes a finding's confidence deterministically: the base plus every
// factor whose predicate holds on the entity, clamped to 0..100, with the applied
// factor names returned as the documented basis (ADR-0021 §6).
func confidence(m ConfidenceModel, n model.Entity, v *view) (model.Confidence, []string) {
	score := int(m.Base)
	var basis []string
	for _, f := range m.Factors {
		var g Grounding
		var tr []string
		if evalNode(f.When, n, v, &g, &tr) {
			score += f.Delta
			basis = append(basis, fmt.Sprintf("%s(%+d)", f.Name, f.Delta))
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	if len(basis) == 0 {
		basis = []string{fmt.Sprintf("base(%d)", int(m.Base))}
	}
	return model.Confidence(score), basis
}
