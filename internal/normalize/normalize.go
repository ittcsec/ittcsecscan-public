package normalize

import (
	"fmt"
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/repo"
)

// Meta is the scan-level context a collected Scan does not itself carry.
type Meta struct {
	// Provider is the cloud the scan collected, stamped onto every entity.
	Provider model.Provider
}

// NormalizedScan is the canonical model graph produced from one collected scan:
// the analysis substrate the detection and graph engines read (ADR-0023). Its
// Completeness is the collected records carried through unchanged, so the
// engines' honest-state machines see every gap intact.
type NormalizedScan struct {
	Entities     []model.Entity
	Edges        []model.Edge
	Evidence     []model.Evidence
	Completeness []collect.Completeness
	// DroppedEdges counts links whose source or target native id had no
	// collected node, so the edge could not be keyed and was not emitted.
	DroppedEdges int
}

// observedConfidence is the confidence of a directly collected relationship: an
// edge the normalizer emits is an observed link, not an inferred one, so it is
// asserted at full confidence. Engines that later infer edges compute their own.
const observedConfidence model.Confidence = 100

// Normalize converts a collected scan into the canonical model graph, keyed by
// the tenant's StableID through keyer (ADR-0023 §2). Output is deterministic:
// entities, edges, and evidence are emitted in a fixed order regardless of input
// order or map iteration. A keyer failure is returned, never swallowed.
func Normalize(scan collect.Scan, keyer repo.StableIDer, meta Meta) (NormalizedScan, error) {
	out := NormalizedScan{
		// Carry the collected completeness through unchanged (never dropped or
		// reinterpreted): the engines decide unknown/not_applicable from it.
		Completeness: append([]collect.Completeness(nil), scan.Completeness...),
	}

	// Evidence: every envelope becomes a model.Evidence, in a fixed order, so the
	// whole scan's reads stay auditable (ADR-0023 §3). byResource indexes the
	// evidence by the one native-id key an envelope carries (its resource scope),
	// which is how an edge is honestly correlated to a read of an endpoint.
	envs := append([]collect.Envelope(nil), scan.Envelopes...)
	sort.Slice(envs, func(i, j int) bool { return envelopeLess(envs[i], envs[j]) })
	byResource := make(map[string][]model.Evidence)
	for _, e := range envs {
		ev := toEvidence(e)
		out.Evidence = append(out.Evidence, ev)
		if r := e.Scope.Resource; r != "" {
			byResource[r] = append(byResource[r], ev)
		}
	}

	// Entities: every node, keyed, in native-id order. present records which
	// native ids exist so a dangling edge can be dropped rather than emitted.
	nodes := append([]collect.Node(nil), scan.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NativeID < nodes[j].NativeID })
	present := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		id, err := keyer.StableID(n.NativeID)
		if err != nil {
			return NormalizedScan{}, fmt.Errorf("normalize: keying entity %q: %w", n.NativeID, err)
		}
		present[n.NativeID] = struct{}{}
		out.Entities = append(out.Entities, model.Entity{
			SchemaVersion: model.SchemaVersion,
			ID:            id,
			Provider:      meta.Provider,
			Type:          n.Type,
			NativeID:      n.NativeID,
			Name:          n.Name,
			Attributes:    n.Attributes,
		})
	}

	// Edges: every link with both endpoints present, keyed, in a fixed order. An
	// edge to a missing endpoint is dropped and counted, never emitted dangling.
	links := append([]collect.Link(nil), scan.Links...)
	sort.Slice(links, func(i, j int) bool { return linkLess(links[i], links[j]) })
	for _, l := range links {
		if _, ok := present[l.SourceNativeID]; !ok {
			out.DroppedEdges++
			continue
		}
		if _, ok := present[l.TargetNativeID]; !ok {
			out.DroppedEdges++
			continue
		}
		src, err := keyer.StableID(l.SourceNativeID)
		if err != nil {
			return NormalizedScan{}, fmt.Errorf("normalize: keying edge source %q: %w", l.SourceNativeID, err)
		}
		dst, err := keyer.StableID(l.TargetNativeID)
		if err != nil {
			return NormalizedScan{}, fmt.Errorf("normalize: keying edge target %q: %w", l.TargetNativeID, err)
		}
		out.Edges = append(out.Edges, model.Edge{
			SchemaVersion: model.SchemaVersion,
			Source:        src,
			Target:        dst,
			Kind:          l.Kind,
			Conditions:    toConditions(l.Conditions),
			DenyEvaluated: model.Unknown, // no deny data is collected (ADR-0022)
			Freshness:     model.Fresh,   // derived from this scan's just-collected evidence
			Confidence:    observedConfidence,
			Evidence:      edgeEvidence(byResource, l.SourceNativeID, l.TargetNativeID),
			Explanation:   []string{"directly collected " + string(l.Kind) + " relationship"},
		})
	}
	return out, nil
}

// toEvidence maps a collected envelope to a model.Evidence. Freshness is fresh
// (just collected) and completeness is complete (the read succeeded and yielded
// this value); scope-level gaps live in NormalizedScan.Completeness, not here.
func toEvidence(e collect.Envelope) model.Evidence {
	return model.Evidence{
		SchemaVersion: model.SchemaVersion,
		Collector:     e.Provenance.Collector,
		API:           e.Operation,
		ObservedAt:    e.CollectedAt,
		Value:         string(e.Response),
		Freshness:     model.Fresh,
		Completeness:  model.Complete,
	}
}

// edgeEvidence returns the evidence for an edge: the envelopes whose resource
// scope matched either endpoint native id, deduplicated, in evidence order. It
// never fabricates a link where no resource-scoped read exists (ADR-0023 §3);
// such an edge carries no per-edge evidence, and the scan-level Evidence remains
// the provenance of record.
func edgeEvidence(byResource map[string][]model.Evidence, src, dst string) []model.Evidence {
	var out []model.Evidence
	seen := make(map[model.Evidence]struct{})
	add := func(native string) {
		for _, ev := range byResource[native] {
			if _, ok := seen[ev]; ok {
				continue
			}
			seen[ev] = struct{}{}
			out = append(out, ev)
		}
	}
	add(src)
	if dst != src {
		add(dst)
	}
	return out
}

// toConditions lifts a link's opaque condition map into canonical conditions, in
// key order. The collectors capture a condition as a raw key and value (an ABAC
// or CEL string, ADR-0022), not decomposed into an operator, so no operator is
// invented here (ADR-0022 EP-3).
func toConditions(m map[string]string) []model.Condition {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]model.Condition, 0, len(keys))
	for _, k := range keys {
		out = append(out, model.Condition{Key: k, Values: []string{m[k]}})
	}
	return out
}

// envelopeLess is a total order over envelopes for deterministic output: no
// envelope carries a unique id, so it orders by every field that identifies the
// read.
func envelopeLess(a, b collect.Envelope) bool {
	for _, p := range [][2]string{
		{string(a.Provider), string(b.Provider)},
		{a.Service, b.Service},
		{a.Operation, b.Operation},
		{a.Region, b.Region},
		{a.Scope.Account, b.Scope.Account},
		{a.Scope.Resource, b.Scope.Resource},
	} {
		if p[0] != p[1] {
			return p[0] < p[1]
		}
	}
	if !a.CollectedAt.Equal(b.CollectedAt) {
		return a.CollectedAt.Before(b.CollectedAt)
	}
	return string(a.Response) < string(b.Response)
}

// linkLess is a total order over links for deterministic output.
func linkLess(a, b collect.Link) bool {
	if a.SourceNativeID != b.SourceNativeID {
		return a.SourceNativeID < b.SourceNativeID
	}
	if a.TargetNativeID != b.TargetNativeID {
		return a.TargetNativeID < b.TargetNativeID
	}
	return a.Kind < b.Kind
}
