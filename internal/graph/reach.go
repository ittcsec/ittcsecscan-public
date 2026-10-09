package graph

import (
	"fmt"
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// maxReachDepth bounds the transitive closure so a pathological graph cannot make
// evaluation unbounded. It is generous for real identity graphs (chains of group
// and role nesting are short) and keeps the computation terminating and fast.
const maxReachDepth = 8

// principalTypes are the node types whose reachability this engine computes: a
// human identity, a machine workload (service account / principal / managed
// identity), or a group.
var principalTypes = map[model.NodeType]bool{
	model.NodeIdentity: true,
	model.NodeWorkload: true,
	model.NodeGroup:    true,
}

// Result is Layer B's output (ADR-0022): name-level authorization *reachability*
// and *trust*, never effective permissions. It never contains a model.Permission
// and never asserts an action or an allow/deny. Reaches are transitive principal
// to role/group edges derived from the collected assumes/member_of edges; Trust
// are external, public, and federated exposure edges. Complete is false when a
// required identity read was not fully collected, in which case the reachability
// is a floor (what the collected edges support), never asserted as exhaustive.
type Result struct {
	Reaches  []model.Edge
	Trust    []model.Edge
	Complete bool
	Gaps     []string // "service:status" for each non-complete completeness input, sorted
}

// hop is one outgoing edge with its target resolved to a native id.
type hop struct {
	kind   model.EdgeKind
	target string
}

// Reach computes name-level reachability and trust from the normalized graph. It
// is deterministic: principals, neighbors, and outputs are all ordered, so
// identical input yields identical output. It reads the canonical model graph, not
// raw collection (ADR-0023).
func Reach(g *normalize.NormalizedScan) Result {
	res := Result{Complete: true}
	if g == nil {
		return res
	}

	ent, native := indexEntities(g)

	// Adjacency over the two collected authorization edge kinds, resolved to native
	// ids and sorted for deterministic traversal.
	adj := make(map[string][]hop)
	for _, e := range g.Edges {
		if e.Kind != model.EdgeAssumes && e.Kind != model.EdgeMemberOf {
			continue
		}
		src, ok1 := native[e.Source]
		dst, ok2 := native[e.Target]
		if !ok1 || !ok2 {
			continue
		}
		adj[src] = append(adj[src], hop{kind: e.Kind, target: dst})
	}
	for s := range adj {
		hs := adj[s]
		sort.Slice(hs, func(i, j int) bool {
			if hs[i].target != hs[j].target {
				return hs[i].target < hs[j].target
			}
			return hs[i].kind < hs[j].kind
		})
		adj[s] = hs
	}

	res.Reaches = reachEdges(g.Entities, ent, adj)
	res.Trust = trustEdges(g.Edges, ent, native)
	res.Complete, res.Gaps = coverage(g.Completeness)
	return res
}

// reachEdges returns the transitive reachability edges: for each principal, a
// derived edge to every role/group it can reach in two or more hops (one-hop reach
// is already a collected edge, so it is not re-emitted). The terminal hop's kind
// labels the reach (assumes for an effective role, member_of for effective group
// membership). The path is recorded as the explanation trace.
func reachEdges(entities []model.Entity, ent map[string]model.Entity, adj map[string][]hop) []model.Edge {
	principals := make([]string, 0, len(entities))
	for _, e := range entities {
		if principalTypes[e.Type] {
			principals = append(principals, e.NativeID)
		}
	}
	sort.Strings(principals)

	var out []model.Edge
	for _, p := range principals {
		// Breadth-first, cycle-safe, bounded: the first time a target is reached is
		// its shortest path, and sorted neighbors make that path deterministic.
		type qitem struct {
			node string
			path []string
			kind model.EdgeKind
		}
		visited := map[string]bool{p: true}
		queue := []qitem{{node: p, path: []string{p}}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if len(cur.path) > maxReachDepth {
				continue
			}
			for _, h := range adj[cur.node] {
				if visited[h.target] {
					continue
				}
				visited[h.target] = true
				np := append(append([]string(nil), cur.path...), h.target)
				// Emit only genuine transitive reach (two or more hops); one-hop is
				// the collected direct edge.
				if len(np) >= 3 {
					out = append(out, reachEdge(p, h.target, h.kind, np, ent))
				}
				queue = append(queue, qitem{node: h.target, path: np, kind: h.kind})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// reachEdge builds one derived reachability edge. Confidence declines with the
// length of the chain (a longer transitive path is a weaker, more contingent
// reach); deny is unevaluated (Layer B has no deny data); evidence is the derived
// path, recorded in the explanation, not a fabricated per-edge observation.
func reachEdge(src, dst string, kind model.EdgeKind, path []string, ent map[string]model.Entity) model.Edge {
	hops := len(path) - 1
	conf := 80 - (hops-2)*15
	if conf < 30 {
		conf = 30
	}
	var trace []string
	trace = append(trace, fmt.Sprintf("transitive reachability (%d hops): %s", hops, pathString(path)))
	return model.Edge{
		SchemaVersion: model.SchemaVersion,
		Source:        srcID(src, ent),
		Target:        srcID(dst, ent),
		Kind:          kind,
		DenyEvaluated: model.Unknown,
		Freshness:     model.Fresh,
		Confidence:    model.Confidence(conf),
		Explanation:   trace,
	}
}

// trustEdges returns external, public, and federated trust exposure. For each
// collected assumes edge whose source principal is external (a public, federated,
// service, or foreign principal by its collected facts), it emits an edge from the
// trusting target (the role or policy) to that external principal, labeled trusts
// or federates_with. This is the honest, name-level "who outside can assume this"
// finding; it asserts nothing about which actions the assumption grants.
func trustEdges(edges []model.Edge, ent map[string]model.Entity, native map[model.StableID]string) []model.Edge {
	var out []model.Edge
	for _, e := range edges {
		if e.Kind != model.EdgeAssumes {
			continue
		}
		srcNative, ok := native[e.Source]
		if !ok {
			continue
		}
		p, ok := ent[srcNative]
		if !ok {
			continue
		}
		kind, reason, external := externalTrust(p)
		if !external {
			continue
		}
		tgtNative := native[e.Target]
		out = append(out, model.Edge{
			SchemaVersion: model.SchemaVersion,
			Source:        e.Target, // the trusting role/policy
			Target:        e.Source, // the external principal it is exposed to
			Kind:          kind,
			DenyEvaluated: model.Unknown,
			Freshness:     model.Fresh,
			Confidence:    90, // grounded directly in the principal's collected facts
			Explanation:   []string{fmt.Sprintf("%s is assumable by an external principal (%s): %s", tgtNative, reason, srcNative)},
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// externalTrust classifies a principal as external, public, or federated from the
// facts the collectors set (ADR-0022 §2; the identity inventory): AWS
// trust-policy principals (public "*", federated, service, canonical-user), and
// GCP members (allUsers public, workload-identity principal/principalSet, whole
// domain). A real in-account principal has none of these and is not external.
func externalTrust(p model.Entity) (kind model.EdgeKind, reason string, external bool) {
	a := p.Attributes
	switch {
	case a["federated"] == "true":
		return model.EdgeFederatesWith, "federated", true
	case a["member_type"] == "principal" || a["member_type"] == "principal_set":
		return model.EdgeFederatesWith, "workload-identity federation", true
	case a["public"] == "true":
		return model.EdgeTrusts, "public", true
	case a["service_principal"] == "true":
		return model.EdgeTrusts, "external service", true
	case a["canonical_user"] == "true":
		return model.EdgeTrusts, "external canonical user", true
	case a["member_type"] == "domain":
		return model.EdgeTrusts, "entire domain", true
	}
	return "", "", false
}

// coverage reconciles the scan's completeness for honest reachability state: the
// reachability is Complete only when every completeness record is Complete, since
// a denied or partial identity read means some edges may be missing and the closure
// is only a floor. Non-complete inputs are cited, sorted, never silently ignored.
func coverage(comp []collect.Completeness) (complete bool, gaps []string) {
	complete = true
	for _, c := range comp {
		if c.Status != collect.Complete {
			gaps = append(gaps, c.Service+":"+string(c.Status))
			complete = false
		}
	}
	sort.Strings(gaps)
	return complete, gaps
}

func srcID(nativeID string, ent map[string]model.Entity) model.StableID {
	return ent[nativeID].ID
}

func pathString(path []string) string {
	s := ""
	for i, n := range path {
		if i > 0 {
			s += " -> "
		}
		s += n
	}
	return s
}
