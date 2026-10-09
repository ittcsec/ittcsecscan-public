package store

import (
	"context"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func acct(native, name string) EntityInput {
	return EntityInput{Provider: model.AWS, Type: model.NodeAccount, NativeID: native, Name: name}
}
func user(native, name string) EntityInput {
	return EntityInput{Provider: model.AWS, Type: model.NodeIdentity, NativeID: native, Name: name}
}

func oneEvidence(now time.Time) []EvidenceInput {
	return []EvidenceInput{{Collector: "collector:aws.iam.identities", API: "GetAccountAuthorizationDetails", Observed: now, Value: []byte(`{"ok":true}`)}}
}

// TestDedupEntities proves the merge semantics: entities sharing a native id
// collapse into one, the first non-empty name and first value per key win, later
// values fill gaps, and criticality takes the maximum.
func TestDedupEntities(t *testing.T) {
	named := EntityInput{Provider: model.GCP, Type: model.NodeWorkload, NativeID: "sa@p", Name: "CI Runner", Attributes: map[string]string{"a": "1"}}
	attr := EntityInput{Provider: model.GCP, Type: model.NodeWorkload, NativeID: "sa@p", Name: "ignored", Attributes: map[string]string{"a": "later", "b": "2"}, Criticality: 3}
	proj := EntityInput{Provider: model.GCP, Type: model.NodeProject, NativeID: "p"}

	out, err := dedupEntities([]EntityInput{named, attr, proj})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("deduped to %d entities, want 2", len(out))
	}
	sa := out[0]
	if sa.Name != "CI Runner" {
		t.Errorf("name = %q, want the first non-empty (CI Runner)", sa.Name)
	}
	if sa.Attributes["a"] != "1" || sa.Attributes["b"] != "2" {
		t.Errorf("attributes not merged first-wins-later-fills: %v", sa.Attributes)
	}
	if sa.Criticality != 3 {
		t.Errorf("criticality = %d, want the max (3)", sa.Criticality)
	}
}

// TestDedupEntitiesConflictIsError proves a native id reported with a different
// provider or type is a hard error, never resolved by which collector ran first.
func TestDedupEntitiesConflictIsError(t *testing.T) {
	base := EntityInput{Provider: model.GCP, Type: model.NodeWorkload, NativeID: "x"}
	if _, err := dedupEntities([]EntityInput{base, {Provider: model.GCP, Type: model.NodeIdentity, NativeID: "x"}}); err == nil {
		t.Error("a native id reported as two types must be an error")
	}
	if _, err := dedupEntities([]EntityInput{base, {Provider: model.AWS, Type: model.NodeWorkload, NativeID: "x"}}); err == nil {
		t.Error("a native id reported for two providers must be an error")
	}
}

// TestIngestDedupsEntitiesAndResolvesEdge proves the fix end to end: the same
// service account reported by two collectors becomes one entity row (not a
// stable-id collision), and an edge to it still resolves. Removing the dedup step
// makes this fail on the unique stable-id index.
func TestIngestDedupsEntitiesAndResolvesEdge(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	now := time.Now().UTC()

	res, err := tn.Ingest(context.Background(), ScanInput{
		ToolVersion: "v", Started: now, Completed: now,
		Entities: []EntityInput{
			{Provider: model.GCP, Type: model.NodeProject, NativeID: "p", Name: "proj"},
			{Provider: model.GCP, Type: model.NodeWorkload, NativeID: "sa@p", Name: "CI Runner"},                               // from the SA collector
			{Provider: model.GCP, Type: model.NodeWorkload, NativeID: "sa@p", Attributes: map[string]string{"role": "editor"}}, // same SA, from the policy collector
		},
		Edges:    []EdgeInput{{SourceNativeID: "sa@p", TargetNativeID: "p", Kind: model.EdgeMemberOf}},
		Evidence: oneEvidence(now),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM entities"); got != 2 {
		t.Errorf("entities = %d, want 2 (project + one merged service account)", got)
	}
	if res.DroppedEdges != 0 {
		t.Errorf("dropped edges = %d, want 0 (the edge resolves to the merged entity)", res.DroppedEdges)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM edges"); got != 1 {
		t.Errorf("edges = %d, want 1", got)
	}
}

// TestIngestRejectsEntityTypeConflict proves a conflicting entity fails the whole
// ingest and writes nothing, rather than silently picking one collector's view.
func TestIngestRejectsEntityTypeConflict(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	now := time.Now().UTC()

	_, err := tn.Ingest(context.Background(), ScanInput{
		ToolVersion: "v", Started: now, Completed: now,
		Entities: []EntityInput{
			{Provider: model.GCP, Type: model.NodeWorkload, NativeID: "x", Name: "as workload"},
			{Provider: model.GCP, Type: model.NodeIdentity, NativeID: "x", Name: "as identity"},
		},
		Evidence: oneEvidence(now),
	})
	if err == nil {
		t.Fatal("conflicting entity types for one native id must fail the ingest")
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM scans"); got != 0 {
		t.Errorf("a scan was written despite the conflict: %d scans", got)
	}
}

// TestIngestFirstScanScopesAndDanglingEdge proves the bridge: a native-id scan
// becomes sealed store rows, the coverage lands in scopes with the pinned reason
// code, and an edge to an unknown entity is dropped and counted, not ingested.
func TestIngestFirstScanScopesAndDanglingEdge(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	now := time.Now().UTC()

	res, err := tn.Ingest(context.Background(), ScanInput{
		ToolVersion: "v1", Started: now, Completed: now,
		Entities: []EntityInput{acct("acct-1", "acme"), user("user-1", "Alice")},
		Edges: []EdgeInput{
			{SourceNativeID: "user-1", TargetNativeID: "acct-1", Kind: model.EdgeMemberOf},
			{SourceNativeID: "user-1", TargetNativeID: "ghost", Kind: model.EdgeMemberOf}, // dangling
		},
		Evidence: oneEvidence(now),
		Scopes: []ScopeInput{
			{Provider: model.AWS, Account: "acct-1", Region: "global", Requested: 2, Observed: 2, Completeness: "complete"},
			{Provider: model.AWS, Account: "acct-1", Region: "us-east-1", Requested: 5, Observed: 0, Completeness: "unknown", Reason: "denied"},
		},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.ScanID == 0 {
		t.Error("no scan id returned")
	}
	if res.DroppedEdges != 1 {
		t.Errorf("dropped edges = %d, want 1 (the dangling one)", res.DroppedEdges)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM entities"); got != 2 {
		t.Errorf("entities = %d, want 2", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM edges"); got != 1 {
		t.Errorf("edges = %d, want 1 (dangling dropped)", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM scopes"); got != 2 {
		t.Errorf("scopes = %d, want 2", got)
	}
	denied, _ := scopeReasonCodes.code("denied")
	if got := rowCount(t, tn, "SELECT count(*) FROM scopes WHERE reason = ?", denied); got != 1 {
		t.Errorf("scopes with reason=denied = %d, want 1", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM scopes WHERE reason IS NULL"); got != 1 {
		t.Errorf("scopes with NULL reason (the complete one) = %d, want 1", got)
	}
	complete, _ := completenessCodes.code("complete")
	if got := rowCount(t, tn, "SELECT count(*) FROM scopes WHERE completeness = ?", complete); got != 1 {
		t.Errorf("complete scopes = %d, want 1 (the coarse vocabulary is untouched)", got)
	}
}

// TestIngestDispatchesFirstThenLater proves Ingest chooses the first-scan load
// then the later-scan change-detection path automatically, reusing the store's
// existing machinery.
func TestIngestDispatchesFirstThenLater(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	now := time.Now().UTC()
	scan := func(users ...EntityInput) ScanInput {
		return ScanInput{ToolVersion: "v", Started: now, Completed: now,
			Entities: append([]EntityInput{acct("acct-1", "acme")}, users...), Evidence: oneEvidence(now),
			Scopes: []ScopeInput{{Provider: model.AWS, Account: "acct-1", Region: "global", Requested: 1, Observed: 1, Completeness: "complete"}}}
	}

	if _, err := tn.Ingest(context.Background(), scan(user("user-1", "Alice"), user("user-2", "Bob"))); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	// user-2 gone, user-3 new; account and user-1 unchanged.
	if _, err := tn.Ingest(context.Background(), scan(user("user-1", "Alice"), user("user-3", "Carol"))); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if got := scanNumbers(t, tn); len(got) != 2 {
		t.Fatalf("want 2 scans, got %d", len(got))
	}
	if got := entitySnapshots(t, tn, "appeared"); got != 1 {
		t.Errorf("appeared = %d, want 1 (user-3)", got)
	}
	if got := entitySnapshots(t, tn, "disappeared"); got != 1 {
		t.Errorf("disappeared = %d, want 1 (user-2)", got)
	}
}
