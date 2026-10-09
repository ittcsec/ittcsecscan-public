package main

import (
	"fmt"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// attackSection is the attack-path part of a scan's JSON output: the paths found and
// the ranked cut candidates (most leverage first, as the engine ordered them).
type attackSection struct {
	Paths []attackPathJSON `json:"paths"`
	Cuts  []cutJSON        `json:"cuts"`
}

type attackPathJSON struct {
	Entry      string     `json:"entry"`
	Target     string     `json:"target"`
	Score      int        `json:"score"`
	Confidence int        `json:"confidence"`
	Risk       int        `json:"risk"`
	RiskBasis  []string   `json:"risk_basis"`
	Steps      []stepJSON `json:"steps"`
}

type stepJSON struct {
	Node      string `json:"node"`
	Via       string `json:"via,omitempty"`
	Technique string `json:"technique,omitempty"`
}

type cutJSON struct {
	Kind          string `json:"kind"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	Description   string `json:"description"`
	PathsRemoved  int    `json:"paths_removed"`
	RiskReduction int    `json:"risk_reduction"`
	Effort        int    `json:"effort"`
	Disruption    int    `json:"disruption"`
}

func toAttackSection(paths []pipeline.RankedPath, cuts []model.CutSet) *attackSection {
	sec := &attackSection{Paths: []attackPathJSON{}, Cuts: []cutJSON{}}
	for _, rp := range paths {
		p := rp.Path
		pj := attackPathJSON{
			Entry: string(p.Entry), Target: string(p.Target),
			Score: p.Score, Confidence: int(p.Confidence),
			Risk: rp.Risk, RiskBasis: redactAll(rp.Basis), Steps: []stepJSON{},
		}
		for _, s := range p.Steps {
			pj.Steps = append(pj.Steps, stepJSON{Node: string(s.Node), Via: string(s.Via), Technique: s.Technique})
		}
		sec.Paths = append(sec.Paths, pj)
	}
	for _, c := range cuts {
		if len(c.Changes) == 0 {
			continue
		}
		ch := c.Changes[0]
		sec.Cuts = append(sec.Cuts, cutJSON{
			Kind: string(ch.Kind), Source: string(ch.Source), Target: string(ch.Target),
			Description:  redact.String(ch.Description),
			PathsRemoved: c.PathsRemoved, RiskReduction: c.RiskReduction, Effort: c.Effort, Disruption: c.Disruption,
		})
	}
	return sec
}

// writeAttackText appends a human-readable attack-path summary: counts, the
// top-ranked paths by risk, then the top-ranked cut candidates (by leverage).
func writeAttackText(b *strings.Builder, paths []pipeline.RankedPath, cuts []model.CutSet) {
	fmt.Fprintf(b, "Attack paths: %d (%d cut candidates)\n", len(paths), len(cuts))
	const topPaths = 5
	for i, rp := range paths {
		if i >= topPaths {
			break
		}
		fmt.Fprintf(b, "  path: risk=%d %s -> %s (%d hops, confidence %d)\n",
			rp.Risk, string(rp.Path.Entry), string(rp.Path.Target), len(rp.Path.Steps)-1, int(rp.Path.Confidence))
	}
	const topN = 5
	for i, c := range cuts {
		if i >= topN || len(c.Changes) == 0 {
			break
		}
		ch := c.Changes[0]
		fmt.Fprintf(b, "  cut: %s (removes %d path(s), risk %d, effort %d, disruption %d) %s\n",
			ch.Kind, c.PathsRemoved, c.RiskReduction, c.Effort, c.Disruption, redact.String(ch.Description))
	}
}
