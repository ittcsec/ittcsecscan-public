// Package ingest maps a collector's accumulated scan (internal/collect) into the
// store's ingest input (internal/store), the wiring that neither package imports
// the other to provide (ADR-0018 §3). It translates the native-id graph,
// evidence, and completeness into the store's ScanInput, including the collection
// status to the store's coarse completeness code plus a pinned reason.
package ingest

import (
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// Meta is the scan-level context the collector's Scan does not carry.
type Meta struct {
	ToolVersion string
	Provider    model.Provider
	Started     time.Time
	Completed   time.Time
}

// ToStore converts a collected scan into the store's ScanInput. Completeness is
// mapped to the store's untouched coarse code (complete/partial/unknown) plus a
// pinned reason (denied/unsupported/error) so the report engine reads both from
// scopes, not from evidence.
func ToStore(scan collect.Scan, meta Meta) store.ScanInput {
	in := store.ScanInput{
		ToolVersion: meta.ToolVersion,
		Started:     meta.Started,
		Completed:   meta.Completed,
	}
	for _, n := range scan.Nodes {
		in.Entities = append(in.Entities, store.EntityInput{
			Provider: meta.Provider, Type: n.Type, NativeID: n.NativeID, Name: n.Name, Attributes: n.Attributes,
		})
	}
	for _, l := range scan.Links {
		in.Edges = append(in.Edges, store.EdgeInput{
			SourceNativeID: l.SourceNativeID, TargetNativeID: l.TargetNativeID, Kind: l.Kind, Conditions: l.Conditions,
		})
	}
	for _, e := range scan.Envelopes {
		in.Evidence = append(in.Evidence, store.EvidenceInput{
			Collector: e.Provenance.Collector, API: e.Operation, Observed: e.CollectedAt, Value: e.Response,
		})
	}
	for _, c := range scan.Completeness {
		coarse, reason := completeness(c.Status)
		in.Scopes = append(in.Scopes, store.ScopeInput{
			Provider: meta.Provider, Account: c.Scope.Account, Region: c.Region,
			Requested: c.Collected, Observed: c.Collected, Completeness: coarse, Reason: reason,
		})
	}
	return in
}

// completeness maps a collection status to the store's coarse completeness code
// and a pinned reason. The three non-coverage statuses collapse to the coarse
// "unknown" (fail closed) but keep their distinct reason.
func completeness(s collect.Status) (coarse, reason string) {
	switch s {
	case collect.Complete:
		return "complete", ""
	case collect.Partial:
		return "partial", ""
	case collect.Denied:
		return "unknown", "denied"
	case collect.Unsupported:
		return "unknown", "unsupported"
	default: // Errored and any unknown status
		return "unknown", "error"
	}
}
