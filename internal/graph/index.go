package graph

import (
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// indexEntities builds the graph engines' lookup maps from the normalized graph:
// entities by native id, and native id by StableID. When several collectors
// emitted the same native id with different facts (for example the identity
// collector setting a principal's permission_boundary and a deny collector setting
// its deny_privilege_level), their attributes are MERGED, so an engine sees every
// collected fact about an entity rather than only the last one indexed. Merging is
// deterministic: entities are folded in native-id order, and on a key conflict a
// non-empty later value wins (a collector that set a value overrides one that left
// it empty). The first non-empty Type and Name seen are kept.
func indexEntities(g *normalize.NormalizedScan) (byNative map[string]model.Entity, native map[model.StableID]string) {
	byNative = map[string]model.Entity{}
	native = map[model.StableID]string{}
	if g == nil {
		return byNative, native
	}
	order := append([]model.Entity(nil), g.Entities...)
	sort.SliceStable(order, func(i, j int) bool { return order[i].NativeID < order[j].NativeID })
	for _, e := range order {
		native[e.ID] = e.NativeID
		cur, seen := byNative[e.NativeID]
		if !seen {
			// Copy the attributes so merging never mutates the caller's map.
			cur = e
			cur.Attributes = copyAttrs(e.Attributes)
			byNative[e.NativeID] = cur
			continue
		}
		if cur.Type == "" {
			cur.Type = e.Type
		}
		if cur.Name == "" {
			cur.Name = e.Name
		}
		if cur.Attributes == nil {
			cur.Attributes = map[string]string{}
		}
		for k, v := range e.Attributes {
			if v != "" {
				cur.Attributes[k] = v
			}
		}
		byNative[e.NativeID] = cur
	}
	return byNative, native
}

func copyAttrs(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	out := make(map[string]string, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}
