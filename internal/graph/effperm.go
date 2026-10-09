package graph

import (
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// privRank orders privilege levels so a cap or deny can be compared: none < privileged < admin.
func privRank(level string) int {
	switch level {
	case "admin":
		return 2
	case "privileged":
		return 1
	default:
		return 0
	}
}

// EffectiveResult is the effective-privilege engine's output (ADR-0022 Step 4,
// Option A): effective-PRIVILEGE grants, not per-action effective permissions.
// Each Grant is a model.Permission whose Action names the effective privilege
// level and whose Effect is allow when the privilege survives, or deny when an
// explicit deny or a permission-boundary cap removed it. A deny always overrides
// an allow (ADR-0022 §5). Full per-action resolution is the named follow-up
// (Option B, EP-5), which needs a raw-action collection expansion.
type EffectiveResult struct {
	Grants   []model.Permission
	Complete bool
	Gaps     []string
}

// EffectivePrivilege resolves, for each principal, the highest privilege it holds
// through the roles and policies it reaches (Layer B closure), then applies
// deny-override: an AWS permission boundary caps the effective privilege to the
// boundary's own level, and an explicit deny (a deny-assignment, deny policy, or
// SCP, surfaced as the deny_privilege_level fact) removes privilege at or below
// its level. It is deterministic and reads only the collected graph.
func EffectivePrivilege(g *normalize.NormalizedScan) EffectiveResult {
	res := EffectiveResult{Complete: true}
	if g == nil {
		return res
	}
	ent, native := indexEntities(g)
	adj := buildAuthzAdj(g, native)

	var principals []string
	for _, e := range g.Entities {
		if principalTypes[e.Type] {
			principals = append(principals, e.NativeID)
		}
	}
	sort.Strings(principals)

	for _, p := range principals {
		grant := resolvePrincipal(p, ent, adj)
		if grant == nil {
			continue
		}
		res.Grants = append(res.Grants, *grant)
	}
	res.Complete, res.Gaps = coverage(g.Completeness)
	return res
}

// buildAuthzAdj indexes the assumes/member_of edges by source native id.
func buildAuthzAdj(g *normalize.NormalizedScan, native map[model.StableID]string) map[string][]hop {
	adj := map[string][]hop{}
	for _, e := range g.Edges {
		if e.Kind != model.EdgeAssumes && e.Kind != model.EdgeMemberOf {
			continue
		}
		s, ok1 := native[e.Source]
		d, ok2 := native[e.Target]
		if ok1 && ok2 {
			adj[s] = append(adj[s], hop{kind: e.Kind, target: d})
		}
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
	return adj
}

// resolvePrincipal computes one principal's effective-privilege grant, or nil when
// it holds no privilege. It finds the highest privilege reachable, then applies the
// boundary cap and any explicit deny, and records the outcome and its basis.
func resolvePrincipal(p string, ent map[string]model.Entity, adj map[string][]hop) *model.Permission {
	self := ent[p]
	granted, via := reachablePrivilege(p, ent, adj)
	// The principal's own inline privilege (AWS inline policies) also counts.
	if lvl := self.Attributes["inline_privilege"]; privRank(lvl) > privRank(granted) {
		granted, via = lvl, p+" (inline policy)"
	}
	if privRank(granted) == 0 {
		return nil // no privilege to resolve
	}

	effect := model.EffectAllow
	effective, deniedBy := applyCaps(granted, self, p, ent)
	if privRank(effective) < privRank(granted) {
		effect = model.EffectDeny // the granted privilege was overridden down
	}

	return &model.Permission{
		SchemaVersion: model.SchemaVersion,
		Principal:     self.ID,
		Resource:      self.ID, // the privilege is over the principal's own scope; per-resource scoping is Option B
		Action:        "privilege:" + granted,
		Effect:        effect,
		Condition:     grantCondition(via, deniedBy),
	}
}

// accountOf returns the AWS account id embedded in a principal's ARN, or "" when
// the native id is not an AWS ARN. The account is the fifth colon-delimited field
// (arn:aws:iam::<account>:user/...), so an SCP cap on that account node applies.
func accountOf(nativeID string) string {
	if !strings.HasPrefix(nativeID, "arn:") {
		return ""
	}
	parts := strings.Split(nativeID, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

// applyCaps reduces a granted privilege level by the deny-override rules, reading the caps
// from the subject's own facts: the AWS permission-boundary cap, an explicit deny
// (deny_privilege_level), and an account SCP cap. It returns the level that survives and a
// short description of the strongest reducer. Deny overrides allow; a boundary we could not
// classify removes the assertion rather than granting fully (never a silent full grant). It
// is the shared core of resolvePrincipal and the agent materialization, so both reduce a
// privilege identically.
func applyCaps(granted string, self model.Entity, nativeID string, ent map[string]model.Entity) (effective, deniedBy string) {
	effective = granted
	if b := self.Attributes["permission_boundary"]; b != "" {
		blevel, known := boundaryLevel(b, ent)
		if !known || privRank(blevel) < privRank(granted) {
			effective = blevel
			deniedBy = "permission boundary " + b
		}
	}
	if d := self.Attributes["deny_privilege_level"]; d != "" && privRank(d) >= privRank(effective) {
		effective = ""
		deniedBy = "explicit deny (" + d + ")"
	}
	if acct := accountOf(nativeID); acct != "" {
		if a, ok := ent[acct]; ok {
			if capLvl := a.Attributes["deny_privilege_level"]; capLvl != "" && privRank(capLvl) >= privRank(effective) {
				effective = ""
				deniedBy = "account SCP cap (" + acct + ")"
			}
		}
	}
	return effective, deniedBy
}

// MaterializeEffectivePrivilege writes, onto each AI agent node, the effective privilege the
// agent holds through the role(s) it assumes, as the effective_privilege_level fact, so a
// closed-predicate detection (ITTCsecAI Guard excessive agency, ADR-0033) can read it. It
// reuses the deny-aware effective-privilege resolution (attached policies, inline privilege,
// permission-boundary cap, explicit deny, account SCP cap) rather than a heuristic.
//
// It is cloud-agnostic by construction: an AWS agent reaches its privilege through
// role -> policy (privilege_level sits on the policy, read over the assumes hop), while an
// Azure or GCP agent (once those collectors emit ai_agent nodes with an assumes edge to a
// role) reaches it through the role node itself, which already carries privilege_level. Both
// are resolved here; no collector for those clouds is built by this function.
//
// It mutates only ai_agent nodes. It does not change principalTypes or the attack-path
// engine: those still resolve identity/workload/group principals exactly as before.
func MaterializeEffectivePrivilege(g *normalize.NormalizedScan) {
	if g == nil {
		return
	}
	ent, native := indexEntities(g)
	adj := buildAuthzAdj(g, native)
	for i := range g.Entities {
		if g.Entities[i].Type != model.NodeAIAgent {
			continue
		}
		best := ""
		for _, h := range adj[g.Entities[i].NativeID] {
			role, ok := ent[h.target]
			if !ok || role.Type != model.NodeRole {
				continue
			}
			if lvl := roleEffectiveLevel(h.target, role, ent, adj); privRank(lvl) > privRank(best) {
				best = lvl
			}
		}
		if best == "" {
			continue
		}
		if g.Entities[i].Attributes == nil {
			g.Entities[i].Attributes = map[string]string{}
		}
		g.Entities[i].Attributes["effective_privilege_level"] = best
	}
}

// roleEffectiveLevel resolves one role's effective privilege: the highest privilege it holds
// (its own privilege_level for an Azure/GCP role node, its attached policies' privilege_level
// reached over assumes for an AWS role, and its inline privilege), reduced by the role's own
// permission boundary, explicit deny, and account SCP cap. Deny overrides allow.
func roleEffectiveLevel(roleNative string, role model.Entity, ent map[string]model.Entity, adj map[string][]hop) string {
	granted, _ := reachablePrivilege(roleNative, ent, adj) // AWS: role -> attached policy[privilege_level]
	if lvl := role.Attributes["privilege_level"]; privRank(lvl) > privRank(granted) {
		granted = lvl // Azure/GCP: privilege_level sits on the role node itself
	}
	if lvl := role.Attributes["inline_privilege"]; privRank(lvl) > privRank(granted) {
		granted = lvl // AWS: role inline policies
	}
	if privRank(granted) == 0 {
		return ""
	}
	effective, _ := applyCaps(granted, role, roleNative, ent)
	return effective
}

// reachablePrivilege returns the highest privilege level the principal reaches
// through assumes/member_of, and a short description of the granting path. It is
// bounded and cycle-safe.
func reachablePrivilege(p string, ent map[string]model.Entity, adj map[string][]hop) (string, string) {
	best := ""
	via := ""
	visited := map[string]bool{p: true}
	type item struct {
		node  string
		depth int
	}
	queue := []item{{p, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxReachDepth {
			continue
		}
		for _, h := range adj[cur.node] {
			if visited[h.target] {
				continue
			}
			visited[h.target] = true
			if lvl := ent[h.target].Attributes["privilege_level"]; privRank(lvl) > privRank(best) {
				best, via = lvl, h.target
			}
			queue = append(queue, item{h.target, cur.depth + 1})
		}
	}
	return best, via
}

// boundaryLevel returns the privilege level of a boundary policy, and whether it
// was known (present and classified). An unknown boundary is not assumed harmless.
func boundaryLevel(boundaryNative string, ent map[string]model.Entity) (string, bool) {
	b, ok := ent[boundaryNative]
	if !ok {
		return "", false
	}
	if b.Attributes["document_read"] != "true" {
		return "", false
	}
	return b.Attributes["privilege_level"], true
}

// grantCondition records the grant's basis on the permission as conditions, so the
// effective privilege is auditable on the grant itself: what granted it, and (when
// overridden) what deny or cap removed it.
func grantCondition(via, deniedBy string) []model.Condition {
	out := []model.Condition{{Key: "granted_via", Values: []string{via}}}
	if deniedBy != "" {
		out = append(out, model.Condition{Key: "overridden_by", Values: []string{deniedBy}})
	}
	return out
}
