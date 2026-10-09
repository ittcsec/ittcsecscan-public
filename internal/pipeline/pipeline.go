// Package pipeline wires the analysis engines together over one normalized graph.
// It is the seam the reachability engine (internal/graph) and the detection pack
// engine (internal/rules) meet at: reachability is computed once and projected onto
// the graph as grounded facts, then the ruleset is evaluated over the augmented
// graph, so exposure-aware detections consume real reachability facts under the same
// honest-state and completeness discipline as any collected fact.
package pipeline

import (
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/graph"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
	"github.com/ittcsec/ittcsecscan/internal/repo"
	"github.com/ittcsec/ittcsecscan/internal/rules"
)

// Result bundles a detection run with the reachability, classification, and
// attack-path records that fed it.
type Result struct {
	Findings       []rules.Result
	Exposure       graph.ExposureResult
	Classification graph.ClassificationResult
	Paths          graph.PathResult
	Cuts           []model.CutSet
	// Identity is the effective-privilege resolution with deny-override semantics
	// (ADR-0022), surfaced for the ITTCsecID report section and CLI view. It is the
	// same resolution Paths consumes internally; nothing new is computed.
	Identity graph.EffectiveResult
	// RankedFindings and RankedPaths are the findings and paths scored by the risk
	// model and ordered by risk descending (ADR-0027). They carry the transparent
	// risk basis; the observed facts in Findings/Paths are unchanged.
	RankedFindings []RankedFinding
	RankedPaths    []RankedPath
}

// Analyze runs the analysis engines over g in a fixed order and evaluates ruleset
// over the augmented graph: classify (materialize sensitivity facts), apply the
// audited criticality overrides, materialize internet-exposure facts, then evaluate.
// Every engine runs before evaluation, so a detection sees real classification,
// override, and reachability facts; a collection gap an engine needed is carried
// through each rule's own Requires.Completeness, so a gap becomes unknown, never a
// pass. Analyze does not mutate ruleset and returns the findings alongside the
// structured classification and exposure results.
func Analyze(g *normalize.NormalizedScan, overrides []model.CriticalityOverride, ruleset []rules.Rule) (Result, error) {
	cls := graph.MaterializeClassification(g)
	graph.ApplyOverrides(g, overrides)
	ex := graph.Materialize(g)
	// Paths assembles the reachability and identity engines (it calls Reach, Expose,
	// and EffectivePrivilege internally, bringing them into the real run), then Cuts
	// ranks remediation candidates over the paths.
	pr := graph.Paths(g)
	cuts := graph.Cuts(pr.Paths)
	// Surface the effective-privilege resolution (the same engine Paths uses) for the
	// ITTCsecID view. Deterministic and read-only; no new logic.
	identity := graph.EffectivePrivilege(g)
	// Materialize each AI agent's effective privilege (through its assumed role, deny-
	// evaluated) onto the agent node so the excessive-agency detection can read it
	// (ADR-0033). It mutates only ai_agent nodes; principalTypes and attack paths are
	// unchanged. Runs before rules.Evaluate so the fact is present when rules read it.
	graph.MaterializeEffectivePrivilege(g)
	findings, err := rules.Evaluate(g, ruleset)
	// Rank findings and paths by the risk model (ADR-0027). All engine facts are on
	// the graph by now, so risk inputs are read from real materialized facts. Ranking
	// reads only; it never alters an observed finding or path.
	ranked := rankFindings(g, findings, ruleset)
	rankedPaths := rankPaths(g, pr.Paths)
	return Result{
		Findings: findings, Exposure: ex, Classification: cls, Paths: pr, Cuts: cuts,
		RankedFindings: ranked, RankedPaths: rankedPaths, Identity: identity,
	}, err
}

// AnalyzeScan is the one-call path from a freshly collected provider scan to
// findings: it normalizes the scan into the canonical graph (keyed by the tenant's
// stable ids through keyer, the same keying persistence uses, and stamped with
// provider), then analyzes it with the tenant's audited criticality overrides. It is
// what the scan command calls after collection. A keyer or normalization failure is
// returned, never swallowed.
func AnalyzeScan(scan collect.Scan, keyer repo.StableIDer, provider model.Provider, overrides []model.CriticalityOverride, ruleset []rules.Rule) (Result, error) {
	g, err := normalize.Normalize(scan, keyer, normalize.Meta{Provider: provider})
	if err != nil {
		return Result{}, err
	}
	return Analyze(&g, overrides, ruleset)
}
