package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// ExposureResult is the internet reachability engine's output (ADR-0024): per
// internet-exposed resource, model.Exposure records (Zone internet, Effective
// unknown, never a claimed verified reachability) and EdgeExposedTo edges, with
// reason traces. Complete is false when a networking read the decision needed was
// not fully collected; the exposure set is then a floor, never asserted exhaustive.
type ExposureResult struct {
	Exposures []model.Exposure
	Edges     []model.Edge
	Complete  bool
	Gaps      []string
}

// internetNodeID is the synthetic StableID for the public-internet zone that
// EdgeExposedTo edges point to. It is a fixed, non-tenant marker (not a keyed
// native id), distinct from any real entity.
const internetNodeID model.StableID = "0000000000000000000000000000000000000000000000000000000000000000"

// Expose computes configuration exposure from the collected network graph. It is
// deterministic and reads only collected facts; it never probes (the internal/graph
// gate forbids net), so every exposure it emits has Effective=unknown (configuration
// exposure, not verified reachability). It reconstructs the topology from the
// forward-key facts (no reachability edges are collected), evaluates each cloud's
// rule layers with their real defaults and intersection semantics, and emits the
// EdgeExposedTo edges are deferred.
func Expose(g *normalize.NormalizedScan) ExposureResult {
	res := ExposureResult{Complete: true}
	if g == nil {
		return res
	}
	ent, _ := indexEntities(g)
	idx := newNetIndex(ent)

	// Resources are processed in native-id order for deterministic output.
	var ids []string
	for id := range ent {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		e := ent[id]
		open, trace, ok := exposedPorts(e, idx)
		if !ok {
			continue // not an internet-facing resource this engine models
		}
		for _, s := range open {
			res.Exposures = append(res.Exposures, exposureRecord(e, s, trace))
		}
		if len(open) > 0 {
			res.Edges = append(res.Edges, model.Edge{
				SchemaVersion: model.SchemaVersion,
				Source:        e.ID,
				Target:        internetNodeID,
				Kind:          model.EdgeExposedTo,
				DenyEvaluated: model.Unknown,
				Freshness:     model.Fresh,
				Confidence:    80, // grounded in the public-IP + rule facts; not probe-verified
				Explanation:   trace,
			})
		}
	}
	res.Complete, res.Gaps = coverage(g.Completeness)
	if len(idx.gaps) > 0 {
		// A per-resource honesty gap (for example an Azure public IP whose SKU could
		// not be determined) makes the result a floor, never asserted exhaustive.
		res.Complete = false
		res.Gaps = append(res.Gaps, idx.gaps...)
		sort.Strings(res.Gaps)
	}
	sort.SliceStable(res.Exposures, func(i, j int) bool { return res.Exposures[i].Entity < res.Exposures[j].Entity })
	sort.SliceStable(res.Edges, func(i, j int) bool { return res.Edges[i].Source < res.Edges[j].Source })
	return res
}

// exposureRecord builds one model.Exposure. Effective is always unknown
// (configuration exposure, never probe-verified); auth_required is unknown (no
// auth-gate data is collected).
func exposureRecord(e model.Entity, s portSpan, trace []string) model.Exposure {
	ex := model.Exposure{
		SchemaVersion: model.SchemaVersion,
		Entity:        e.ID,
		Zone:          model.ZoneInternet,
		AuthRequired:  model.Unknown,
		Effective:     model.Unknown, // configuration exposure, not verified reachability
		Trace:         trace,
	}
	if p := ianaProto(s.Proto); p != nil {
		ex.Protocol = p
	}
	if !s.AllPorts {
		ex.Ports = &model.PortRange{From: s.From, To: s.To}
	}
	return ex
}

// ianaProto maps a normalized protocol token to its IANA number, or nil for "all"
// / unknown (which the model records as every protocol).
func ianaProto(p string) *int {
	n := map[string]int{"tcp": 6, "udp": 17, "icmp": 1}
	if v, ok := n[strings.ToLower(p)]; ok {
		return &v
	}
	return nil
}

// exposedPorts returns the internet-open protocol/port spans for a resource, a
// trace, and whether the resource is one this engine models (an internet-facing
// compute resource). It applies each cloud's rule layers with their real defaults:
//   - AWS: the security group is the gate (default-deny); the network ACL, default
//     allow-all, intersects when present. open = SG-open ∩ (NACL-open or all).
//   - Azure: when an NSG is present it governs (open = intersection of the NIC and
//     subnet NSG layers). With no NSG the outcome depends on the public IP SKU
//     (Standard is secure by default, Basic is open by default, undetermined is an
//     honest exposure floor); see azureNoNSGExposure.
//   - GCP: ingress is implied deny-all, so open = the firewalls that allow.
func exposedPorts(e model.Entity, idx *netIndex) ([]portSpan, []string, bool) {
	switch {
	case e.Attributes["aws_type"] == "instance" || (e.Type == model.NodeCompute && strings.HasPrefix(e.NativeID, "arn:aws:")):
		return idx.awsInstanceExposure(e)
	case e.Attributes["azure_type"] == "virtual_machine":
		return idx.azureVMExposure(e)
	case e.Type == model.NodeCompute && strings.HasPrefix(e.NativeID, "//compute.googleapis.com/"):
		return idx.gcpInstanceExposure(e)
	}
	return nil, nil, false
}

// intersectSpans returns the port spans reachable through BOTH layers: a protocol
// present in both (or "all" on one side), over the overlapping port range. This is
// the layer-AND at the heart of the engine (a deny in either layer removes the
// port), so it is mutation-tested.
func intersectSpans(a, b []portSpan) []portSpan {
	var out []portSpan
	for _, x := range a {
		for _, y := range b {
			if s, ok := overlap(x, y); ok {
				out = append(out, s)
			}
		}
	}
	return dedupSpans(out)
}

func overlap(x, y portSpan) (portSpan, bool) {
	proto := ""
	switch {
	case x.Proto == y.Proto:
		proto = x.Proto
	case x.Proto == "all":
		proto = y.Proto
	case y.Proto == "all":
		proto = x.Proto
	default:
		return portSpan{}, false
	}
	xl, xh := portBounds(x)
	yl, yh := portBounds(y)
	lo, hi := xl, xh
	if yl > lo {
		lo = yl
	}
	if yh < hi {
		hi = yh
	}
	if lo > hi {
		return portSpan{}, false
	}
	return portSpan{Proto: proto, AllPorts: lo == 0 && hi == 65535, From: lo, To: hi}, true
}

func portBounds(s portSpan) (int, int) {
	if s.AllPorts {
		return 0, 65535
	}
	return s.From, s.To
}

func dedupSpans(in []portSpan) []portSpan {
	seen := map[portSpan]bool{}
	var out []portSpan
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].From < out[j].From
	})
	return out
}

func exposureTrace(resource, layer string, open []portSpan) string {
	return fmt.Sprintf("%s: internet-facing; %s permits %s", resource, layer, spansString(open))
}

func spansString(s []portSpan) string {
	parts := make([]string, 0, len(s))
	for _, x := range s {
		if x.AllPorts {
			parts = append(parts, x.Proto+":*")
		} else {
			parts = append(parts, fmt.Sprintf("%s:%d-%d", x.Proto, x.From, x.To))
		}
	}
	return strings.Join(parts, ", ")
}
