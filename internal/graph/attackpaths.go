package graph

import (
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// PathResult is the attack-path engine's output (ADR-0026): the routes from an
// internet-exposed workload entry, through the identity graph, to a privileged or
// externally-trusted identity target. Complete is false when a collection read a
// path decision needed was not complete; the path set is then a floor, never
// asserted exhaustive.
type PathResult struct {
	Paths    []model.AttackPath
	Complete bool
	Gaps     []string
}

// pathEdge is one traversable, emitted edge in the assembled attack graph.
type pathEdge struct {
	to   model.StableID
	kind model.EdgeKind
	conf model.Confidence
}

// crumb is a BFS breadcrumb: how a node was first (shortest) reached, and the running
// minimum confidence to it.
type crumb struct {
	prev model.StableID
	via  model.EdgeKind
	conf model.Confidence
	hops int
}

// Paths computes attack paths over the emitted edges only (ADR-0026). It assembles a
// unified graph from the collected identity edges, the Reach engine's derived
// transitive reach and trust edges, the Expose engine's internet entry markers, and
// the EffectivePrivilege engine's privileged targets, then finds, for each entry, the
// shortest route to each reachable target. It is deterministic and pure.
//
// It never overstates (the safety-critical core): an entry is configuration-exposed,
// never probe-verified; a path's confidence is the minimum of its traversed edges'
// confidences, never inflated; and it traverses only emitted edges, so it never
// fabricates a hop to reach a more valuable target. Paths to sensitive data are not
// constructed, because identity-to-data capability edges are not emitted (AP-1); that
// gap is reported, never bridged.
func Paths(g *normalize.NormalizedScan) PathResult {
	res := PathResult{Complete: true}
	if g == nil {
		return res
	}

	nodes := make(map[model.StableID]model.Entity, len(g.Entities))
	for _, e := range g.Entities {
		nodes[e.ID] = e
	}

	adj := map[model.StableID][]pathEdge{}
	addEdge := func(src, dst model.StableID, kind model.EdgeKind, conf model.Confidence) {
		if src == dst || src == "" || dst == "" {
			return // a self-edge is a finding, not a movement hop
		}
		adj[src] = append(adj[src], pathEdge{to: dst, kind: kind, conf: conf})
	}
	// Collected identity edges (assume-role, membership), including a workload's
	// assume-role edge that bridges an exposed workload into the identity graph.
	for _, e := range g.Edges {
		if e.Kind == model.EdgeAssumes || e.Kind == model.EdgeMemberOf {
			addEdge(e.Source, e.Target, e.Kind, e.Confidence)
		}
	}
	// Derived transitive reach and trust edges.
	reach := Reach(g)
	for _, e := range reach.Reaches {
		addEdge(e.Source, e.Target, e.Kind, e.Confidence)
	}
	for _, e := range reach.Trust {
		addEdge(e.Source, e.Target, e.Kind, e.Confidence)
	}
	for id := range adj {
		sort.Slice(adj[id], func(i, j int) bool {
			if adj[id][i].to != adj[id][j].to {
				return adj[id][i].to < adj[id][j].to
			}
			return adj[id][i].kind < adj[id][j].kind
		})
	}

	// Entries: internet-exposed workloads, with the exposure edge's confidence.
	entryConf := map[model.StableID]model.Confidence{}
	for _, e := range Expose(g).Edges {
		if e.Kind == model.EdgeExposedTo {
			entryConf[e.Source] = e.Confidence
		}
	}
	// Targets: privileged roles (the privilege_level fact Layer A puts on a role or
	// policy) and privileged principals (an EffectivePrivilege admin/privileged
	// grant, after deny-override). A path reaches a privileged role through the
	// assume chain, or a principal that resolves to privilege.
	targetWeight := map[model.StableID]int{}
	for _, e := range g.Entities {
		if w := privLevelWeight(e.Attributes["privilege_level"]); w > targetWeight[e.ID] {
			targetWeight[e.ID] = w
		}
	}
	for _, p := range EffectivePrivilege(g).Grants {
		if w := privilegeWeight(p.Action); w > targetWeight[p.Principal] {
			targetWeight[p.Principal] = w
		}
	}

	entries := make([]model.StableID, 0, len(entryConf))
	for id := range entryConf {
		entries = append(entries, id)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i] < entries[j] })

	for _, entry := range entries {
		res.Paths = append(res.Paths, shortestPaths(entry, entryConf[entry], adj, targetWeight)...)
	}
	sort.SliceStable(res.Paths, func(i, j int) bool {
		if res.Paths[i].Entry != res.Paths[j].Entry {
			return res.Paths[i].Entry < res.Paths[j].Entry
		}
		return res.Paths[i].Target < res.Paths[j].Target
	})
	res.Complete, res.Gaps = coverage(g.Completeness)
	return res
}

// maxPathHops bounds path length, so a pathological graph cannot make enumeration
// unbounded. It is generous: real assume-role and trust chains are short.
const maxPathHops = 12

// shortestPaths finds, by breadth-first search from entry, the shortest route to each
// privileged target reachable over the emitted edges, one path per target. The path
// confidence is the minimum of the entry exposure confidence and every traversed
// edge's confidence (a chain is only as strong as its weakest evidenced hop), never
// inflated. BFS gives a shortest path deterministically (neighbors are pre-sorted).
func shortestPaths(entry model.StableID, entryConf model.Confidence, adj map[model.StableID][]pathEdge, targetWeight map[model.StableID]int) []model.AttackPath {
	seen := map[model.StableID]crumb{entry: {conf: entryConf}}
	queue := []model.StableID{entry}
	var out []model.AttackPath
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		c := seen[cur]
		if c.hops >= maxPathHops {
			continue
		}
		for _, e := range adj[cur] {
			if _, ok := seen[e.to]; ok {
				continue // BFS: first visit is a shortest path; keep it stable
			}
			conf := c.conf
			if e.conf < conf {
				conf = e.conf
			}
			seen[e.to] = crumb{prev: cur, via: e.kind, conf: conf, hops: c.hops + 1}
			queue = append(queue, e.to)
			if targetWeight[e.to] > 0 {
				out = append(out, buildPath(entry, e.to, seen, targetWeight[e.to]))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// buildPath reconstructs the entry-to-target path from the BFS crumbs, in order, with
// per-step technique tagging and the path's minimum confidence and privilege score.
func buildPath(entry, target model.StableID, seen map[model.StableID]crumb, weight int) model.AttackPath {
	// Walk back from target to entry, then reverse.
	var rev []model.StableID
	var vias []model.EdgeKind
	for n := target; n != entry; n = seen[n].prev {
		rev = append(rev, n)
		vias = append(vias, seen[n].via)
	}
	steps := make([]model.PathStep, 0, len(rev)+1)
	steps = append(steps, model.PathStep{Node: entry, Technique: techniqueForEntry()})
	for i := len(rev) - 1; i >= 0; i-- {
		steps = append(steps, model.PathStep{Node: rev[i], Via: vias[i], Technique: techniqueForEdge(vias[i])})
	}
	return model.AttackPath{
		SchemaVersion: model.SchemaVersion,
		Entry:         entry,
		Target:        target,
		Score:         weight,
		Confidence:    seen[target].conf,
		Steps:         steps,
	}
}

// privilegeWeight maps an effective-privilege action to a target risk weight. Only
// admin and privileged identities are targets; everything else is not a target (0).
func privilegeWeight(action string) int {
	switch action {
	case "privilege:admin":
		return 100
	case "privilege:privileged":
		return 70
	}
	return 0
}

// privLevelWeight maps a role/policy privilege_level fact to a target risk weight.
func privLevelWeight(level string) int {
	switch level {
	case "admin":
		return 100
	case "privileged":
		return 70
	}
	return 0
}

// techniqueForEntry tags the entry step: reaching an internet-exposed workload is
// Exploit Public-Facing Application. Technique tagging is best-effort (AP-5).
func techniqueForEntry() string { return "T1190" }

// techniqueForEdge maps a traversed edge kind to a MITRE technique, best-effort.
func techniqueForEdge(kind model.EdgeKind) string {
	switch kind {
	case model.EdgeAssumes, model.EdgeMemberOf:
		return "T1078" // Valid Accounts
	case model.EdgeTrusts, model.EdgeFederatesWith:
		return "T1199" // Trusted Relationship
	}
	return ""
}
