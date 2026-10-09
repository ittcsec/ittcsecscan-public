package store

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// ScanInput is a collected scan in provider-native terms, the public boundary a
// collector run ingests through (ADR-0018 §3). The store computes stable ids,
// seals fields, runs change detection against the previous scan, and applies
// retention; the caller never touches transactions, tenant files, or keys.
type ScanInput struct {
	ToolVersion        string
	Manifest           []byte
	Started, Completed time.Time
	Entities           []EntityInput
	Edges              []EdgeInput
	Evidence           []EvidenceInput
	Scopes             []ScopeInput
}

// EntityInput is one collected entity, keyed by its provider-native id.
type EntityInput struct {
	Provider    model.Provider
	Type        model.NodeType
	NativeID    string
	Name        string
	Criticality int
	Tags        map[string]string
	Attributes  map[string]string
}

// EdgeInput is one collected relationship between two native ids. An edge whose
// endpoints are not both among the scan's entities is dropped and counted, never
// ingested (ADR-0018).
type EdgeInput struct {
	SourceNativeID string
	TargetNativeID string
	Kind           model.EdgeKind
	Conditions     map[string]string
}

// EvidenceInput is one redacted observation.
type EvidenceInput struct {
	Collector, API string
	Observed       time.Time
	Value          []byte
}

// ScopeInput is one enumeration's coverage. Completeness is the coarse code
// ("complete", "partial", "unknown"); Reason is the pinned reason a non-complete
// coverage carries ("denied", "unsupported", "error"), or "" for none.
type ScopeInput struct {
	Provider            model.Provider
	Account, Region     string
	Requested, Observed int
	Completeness        string
	Reason              string
}

// Result reports what an ingest did.
type Result struct {
	ScanID       int64
	DroppedEdges int // edges dropped because an endpoint was not a known entity
}

// collectedConfidence is the confidence recorded for a directly collected edge:
// full, because it was read from the provider, not inferred.
const collectedConfidence = 100

// Ingest writes a collected scan: the tenant's first scan on an empty tenant,
// otherwise a later scan with change detection. It reuses the sealing,
// stable-id, seal-count, and retention machinery unchanged; it only converts the
// native-id input into the store's records and resolves edges to positions.
func (t *Tenant) Ingest(ctx context.Context, in ScanInput) (Result, error) {
	first, err := t.noScansYet(ctx)
	if err != nil {
		return Result{}, err
	}

	// Multiple collectors legitimately report the same real-world entity (a
	// service account the identity collector lists and the IAM policy names as a
	// member), so the merged scan can carry the same native id more than once.
	// The stable id is keyed by native id and is unique, so those must become one
	// entity, not two colliding rows. Merge them here, at the boundary, before any
	// record or id is built.
	in.Entities, err = dedupEntities(in.Entities)
	if err != nil {
		return Result{}, err
	}

	entities, err := in.entityRecords()
	if err != nil {
		return Result{}, err
	}
	pos := make(map[string]int, len(entities))
	for i := range entities {
		pos[entities[i].nativeID] = i
	}
	edges, dropped, err := in.edgeRecords(pos, len(in.Evidence))
	if err != nil {
		return Result{}, err
	}
	scopes, err := in.scopeRecords()
	if err != nil {
		return Result{}, err
	}
	evidence := in.evidenceRecords()

	if first {
		fs := firstScan{
			toolVersion: in.ToolVersion, manifest: in.Manifest, started: in.Started, completed: in.Completed,
			evidence: evidence, entities: entities, scopes: scopes,
			edges: sliceSeq(edges),
		}
		id, err := t.loadFirstScan(ctx, fs)
		return Result{ScanID: id, DroppedEdges: dropped}, err
	}
	ls := laterScan{
		toolVersion: in.ToolVersion, manifest: in.Manifest, started: in.Started, completed: in.Completed,
		evidence: evidence, entities: entities, edges: edges, scopes: scopes,
	}
	id, err := t.ingestScan(ctx, ls)
	return Result{ScanID: id, DroppedEdges: dropped}, err
}

// noScansYet reports whether the tenant has no scans, so Ingest can choose the
// first-scan bulk load or a later scan with change detection.
func (t *Tenant) noScansYet(ctx context.Context) (bool, error) {
	var n int
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return c.QueryRowContext(ctx, "SELECT count(*) FROM scans").Scan(&n)
	})
	return n == 0, err
}

// dedupEntities collapses entities that share a native id into one, so several
// collectors can independently report the same real-world entity. Entities are
// keyed by native id (as the stable id is), and merged in first-seen order: the
// first non-empty name and the first value for each tag and attribute key win,
// later ones only fill gaps, and criticality takes the maximum so a merge never
// lowers a risk signal.
//
// The same native id reported with a different provider or type is a genuine
// conflict, two collectors disagreeing about what the entity is, and is a hard
// error, never resolved by which collector ran first: an unresolved
// disagreement stops the ingest, it is not silently picked.
func dedupEntities(entities []EntityInput) ([]EntityInput, error) {
	at := make(map[string]int, len(entities))
	out := make([]EntityInput, 0, len(entities))
	for _, e := range entities {
		i, seen := at[e.NativeID]
		if !seen {
			at[e.NativeID] = len(out)
			out = append(out, e)
			continue
		}
		merged, err := mergeEntity(out[i], e)
		if err != nil {
			return nil, err
		}
		out[i] = merged
	}
	return out, nil
}

// mergeEntity merges b into a (same native id). A differing provider or type is a
// conflict and an error.
func mergeEntity(a, b EntityInput) (EntityInput, error) {
	if a.Provider != b.Provider || a.Type != b.Type {
		return EntityInput{}, fmt.Errorf("store: entity %q reported as both (%s, %s) and (%s, %s)",
			a.NativeID, a.Provider, a.Type, b.Provider, b.Type)
	}
	if a.Name == "" {
		a.Name = b.Name
	}
	if b.Criticality > a.Criticality {
		a.Criticality = b.Criticality
	}
	a.Tags = fillMap(a.Tags, b.Tags)
	a.Attributes = fillMap(a.Attributes, b.Attributes)
	return a, nil
}

// fillMap returns a with any key it lacks filled from b (first value wins).
func fillMap(a, b map[string]string) map[string]string {
	if len(b) == 0 {
		return a
	}
	if a == nil {
		a = make(map[string]string, len(b))
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			a[k] = v
		}
	}
	return a
}

func (in ScanInput) entityRecords() ([]entityRecord, error) {
	out := make([]entityRecord, 0, len(in.Entities))
	for _, e := range in.Entities {
		p, ok := providerCodes.code(string(e.Provider))
		if !ok {
			return nil, fmt.Errorf("store: unknown provider %q", e.Provider)
		}
		nt, ok := nodeTypeCodes.code(string(e.Type))
		if !ok {
			return nil, fmt.Errorf("store: unknown node type %q", e.Type)
		}
		out = append(out, entityRecord{
			nativeID: e.NativeID, name: e.Name, provider: p, nodeType: nt,
			criticality: int64(e.Criticality), tags: e.Tags, attributes: e.Attributes,
		})
	}
	return out, nil
}

// edgeRecords resolves each edge's endpoints to entity positions, dropping and
// counting any edge whose endpoints are not both known. Each edge references the
// first evidence record; precise per-edge evidence is a follow-up.
func (in ScanInput) edgeRecords(pos map[string]int, evidenceCount int) ([]edgeRecord, int, error) {
	out := make([]edgeRecord, 0, len(in.Edges))
	dropped := 0
	for _, e := range in.Edges {
		src, sok := pos[e.SourceNativeID]
		dst, dok := pos[e.TargetNativeID]
		// An edge needs both endpoints known and an evidence record to
		// reference; otherwise it is dropped and counted, never ingested.
		if !sok || !dok || evidenceCount == 0 {
			dropped++
			continue
		}
		k, ok := edgeKindCodes.code(string(e.Kind))
		if !ok {
			return nil, 0, fmt.Errorf("store: unknown edge kind %q", e.Kind)
		}
		out = append(out, edgeRecord{src: src, dst: dst, kind: k, confidence: collectedConfidence, evidence: 0, conditions: e.Conditions})
	}
	return out, dropped, nil
}

func (in ScanInput) scopeRecords() ([]scopeRecord, error) {
	out := make([]scopeRecord, 0, len(in.Scopes))
	for _, s := range in.Scopes {
		p, ok := providerCodes.code(string(s.Provider))
		if !ok {
			return nil, fmt.Errorf("store: unknown provider %q", s.Provider)
		}
		comp, ok := completenessCodes.code(s.Completeness)
		if !ok {
			return nil, fmt.Errorf("store: unknown completeness %q", s.Completeness)
		}
		var reason int64
		if s.Reason != "" {
			r, ok := scopeReasonCodes.code(s.Reason)
			if !ok {
				return nil, fmt.Errorf("store: unknown scope reason %q", s.Reason)
			}
			reason = r
		}
		out = append(out, scopeRecord{
			provider: p, account: s.Account, region: s.Region,
			requested: s.Requested, observed: s.Observed, completeness: comp, reason: reason,
		})
	}
	return out, nil
}

func (in ScanInput) evidenceRecords() []evidenceRecord {
	out := make([]evidenceRecord, 0, len(in.Evidence))
	for _, e := range in.Evidence {
		out = append(out, evidenceRecord{collector: e.Collector, api: e.API, observed: e.Observed, value: e.Value})
	}
	return out
}

// sliceSeq adapts a slice to the restartable iter.Seq firstScan.edges needs.
func sliceSeq(s []edgeRecord) iter.Seq[edgeRecord] {
	if len(s) == 0 {
		return nil
	}
	return func(yield func(edgeRecord) bool) {
		for _, e := range s {
			if !yield(e) {
				return
			}
		}
	}
}
