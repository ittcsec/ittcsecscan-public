package graph

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// Materialize runs the internet reachability engine over g and projects its findings
// back onto g as entity facts the detection engine's closed predicates can read. It
// is the seam between the reachability engine (ADR-0024) and the detection pack
// engine (ADR-0021): exposure is computed once from the collected graph and written
// as grounded, deterministic facts. It never probes and never asserts verified
// reachability (each record keeps Effective=unknown); the facts are configuration
// exposure. It only adds facts, never removes or overwrites unrelated ones, so a
// detection that does not read them is unperturbed. It returns the ExposureResult so
// a caller that also wants the structured records (edges, gaps) has them.
//
// The facts written on each exposed entity are:
//   - internet_exposed          = "true"
//   - exposure_provider         = "aws" | "azure" | "gcp"  (for per-cloud rule scoping)
//   - internet_exposed_all_ports = "true"                  (only when a span covers all ports)
//   - internet_exposed_ports    = a sorted "proto/ports" list (evidence and richer rules)
func Materialize(g *normalize.NormalizedScan) ExposureResult {
	res := Expose(g)
	if g == nil {
		return res
	}
	byEntity := map[model.StableID][]model.Exposure{}
	for _, ex := range res.Exposures {
		byEntity[ex.Entity] = append(byEntity[ex.Entity], ex)
	}
	for i := range g.Entities {
		exps, ok := byEntity[g.Entities[i].ID]
		if !ok {
			continue
		}
		if g.Entities[i].Attributes == nil {
			g.Entities[i].Attributes = map[string]string{}
		}
		a := g.Entities[i].Attributes
		a["internet_exposed"] = "true"
		a["exposure_provider"] = providerOf(g.Entities[i])
		if anyAllPorts(exps) {
			a["internet_exposed_all_ports"] = "true"
		}
		a["internet_exposed_ports"] = exposedPortsFact(exps)
	}
	return res
}

// providerOf attributes an exposed entity to its cloud, mirroring the reachability
// engine's own dispatch (exposedPorts). It is called only on entities the engine
// produced an exposure for, so one of the arms always matches.
func providerOf(e model.Entity) string {
	switch {
	case e.Attributes["azure_type"] == "virtual_machine":
		return "azure"
	case strings.HasPrefix(e.NativeID, "//compute.googleapis.com/"):
		return "gcp"
	case e.Attributes["aws_type"] == "instance" || strings.HasPrefix(e.NativeID, "arn:aws:"):
		return "aws"
	}
	return ""
}

// anyAllPorts reports whether any exposure covers every port (a span with no specific
// protocol and no port range, the reachability engine's all-ports encoding).
func anyAllPorts(exps []model.Exposure) bool {
	for _, e := range exps {
		if e.Protocol == nil && e.Ports == nil {
			return true
		}
	}
	return false
}

// exposedPortsFact renders the exposed spans as a sorted, deduplicated "proto/ports"
// list ("all" for an all-ports span, "tcp/443" for a single port, "tcp/20-25" for a
// range). It is evidence and a surface for richer future rules; it is deterministic.
func exposedPortsFact(exps []model.Exposure) string {
	seen := map[string]bool{}
	var parts []string
	for _, e := range exps {
		s := spanToken(e)
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func spanToken(e model.Exposure) string {
	if e.Protocol == nil && e.Ports == nil {
		return "all"
	}
	var proto string
	switch {
	case e.Protocol == nil:
		proto = "all"
	case *e.Protocol == 6:
		proto = "tcp"
	case *e.Protocol == 17:
		proto = "udp"
	case *e.Protocol == 1:
		proto = "icmp"
	default:
		proto = "proto" + strconv.Itoa(*e.Protocol)
	}
	if e.Ports == nil {
		return proto + "/*"
	}
	if e.Ports.From == e.Ports.To {
		return proto + "/" + strconv.Itoa(e.Ports.From)
	}
	return proto + "/" + strconv.Itoa(e.Ports.From) + "-" + strconv.Itoa(e.Ports.To)
}
