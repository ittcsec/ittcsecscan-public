package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// fakeKeyer derives a valid (64-hex) StableID deterministically from the native
// id, so a test can assert both endpoints are keyed with the same keyer without
// a real tenant. err, when set, makes every derivation fail.
type fakeKeyer struct{ err error }

func (f fakeKeyer) StableID(nativeID string) (model.StableID, error) {
	if f.err != nil {
		return "", f.err
	}
	sum := sha256.Sum256([]byte(nativeID))
	return model.StableID(hex.EncodeToString(sum[:])), nil
}

func sid(nativeID string) model.StableID {
	id, _ := fakeKeyer{}.StableID(nativeID)
	return id
}

var meta = Meta{Provider: model.AWS}

// TestNormalizeProducesCanonicalGraph proves nodes and links become keyed,
// well-formed model entities and edges with the documented fixed fields.
func TestNormalizeProducesCanonicalGraph(t *testing.T) {
	scan := collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeIdentity, NativeID: "arn:user/a", Name: "a", Attributes: map[string]string{"user_id": "1"}},
			{Type: model.NodeRole, NativeID: "arn:role/r"},
		},
		Links: []collect.Link{
			{SourceNativeID: "arn:user/a", TargetNativeID: "arn:role/r", Kind: model.EdgeAssumes, Conditions: map[string]string{"scope": "s", "condition": "c"}},
		},
	}
	out, err := Normalize(scan, fakeKeyer{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entities) != 2 || len(out.Edges) != 1 {
		t.Fatalf("got %d entities, %d edges; want 2, 1", len(out.Entities), len(out.Edges))
	}
	e := out.Edges[0]
	if e.Source != sid("arn:user/a") || e.Target != sid("arn:role/r") {
		t.Errorf("edge endpoints not keyed by the keyer: %s -> %s", e.Source, e.Target)
	}
	if e.Kind != model.EdgeAssumes {
		t.Errorf("edge kind = %s, want assumes", e.Kind)
	}
	if e.DenyEvaluated != model.Unknown {
		t.Errorf("deny_evaluated = %s, want unknown (no deny data collected)", e.DenyEvaluated)
	}
	if e.Freshness != model.Fresh || e.Confidence != observedConfidence {
		t.Errorf("freshness/confidence = %s/%d, want fresh/%d", e.Freshness, e.Confidence, observedConfidence)
	}
	if len(e.Explanation) == 0 {
		t.Error("edge has no explanation trace")
	}
	// Conditions lifted in key order, no operator invented.
	if len(e.Conditions) != 2 || e.Conditions[0].Key != "condition" || e.Conditions[1].Key != "scope" {
		t.Errorf("conditions not lifted in key order: %+v", e.Conditions)
	}
	if e.Conditions[0].Operator != "" {
		t.Errorf("operator invented on a raw condition: %q", e.Conditions[0].Operator)
	}
	// Entity fields carried, StableID valid.
	if !out.Entities[0].ID.Valid() {
		t.Errorf("entity id %q is not a valid stable id", out.Entities[0].ID)
	}
	if out.Entities[0].Provider != model.AWS {
		t.Errorf("entity provider = %s, want aws", out.Entities[0].Provider)
	}
}

// TestKeyerFailureIsReturned proves a keying failure is surfaced, never swallowed
// into a partial graph.
func TestKeyerFailureIsReturned(t *testing.T) {
	scan := collect.Scan{Nodes: []collect.Node{{Type: model.NodeRole, NativeID: "arn:role/r"}}}
	if _, err := Normalize(scan, fakeKeyer{err: errors.New("boom")}, meta); err == nil {
		t.Fatal("expected an error when the keyer fails")
	}
}

// TestProvenanceCarriesEveryEnvelopeAndCorrelates is the provenance guarantee of
// ADR-0023 §3: every envelope is carried, and an edge references exactly the
// envelopes whose resource scope matches an endpoint. It is the mutation target:
// dropping an envelope, skipping a matching one, or attaching a non-matching one
// each breaks it.
func TestProvenanceCarriesEveryEnvelopeAndCorrelates(t *testing.T) {
	at := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	scan := collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeIdentity, NativeID: "arn:user/a"},
			{Type: model.NodeRole, NativeID: "arn:role/r"},
		},
		Links: []collect.Link{{SourceNativeID: "arn:user/a", TargetNativeID: "arn:role/r", Kind: model.EdgeAssumes}},
		Envelopes: []collect.Envelope{
			{Provider: model.AWS, Service: "iam", Operation: "GetRole", CollectedAt: at, Scope: collect.Scope{Resource: "arn:role/r"}, Response: []byte(`{"r":1}`)},
			{Provider: model.AWS, Service: "s3", Operation: "ListBuckets", CollectedAt: at, Scope: collect.Scope{Resource: "arn:s3:::unrelated"}, Response: []byte(`{"b":1}`)},
		},
	}
	out, err := Normalize(scan, fakeKeyer{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	// Every envelope is carried through, none dropped.
	if len(out.Evidence) != 2 {
		t.Fatalf("carried %d evidence, want 2 (every envelope)", len(out.Evidence))
	}
	// The edge references the role read (resource scope matches its target) and
	// only that one, never the unrelated s3 read.
	ev := out.Edges[0].Evidence
	if len(ev) != 1 || ev[0].API != "GetRole" {
		t.Fatalf("edge evidence = %+v, want exactly the GetRole read that scoped an endpoint", ev)
	}
}

// TestNoFabricatedEvidenceWithoutResourceScope proves an edge whose endpoints
// had no resource-scoped read carries no per-edge evidence, rather than a
// fabricated or guessed link (ADR-0023 §3).
func TestNoFabricatedEvidenceWithoutResourceScope(t *testing.T) {
	scan := collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeIdentity, NativeID: "arn:user/a"},
			{Type: model.NodeRole, NativeID: "arn:role/r"},
		},
		Links: []collect.Link{{SourceNativeID: "arn:user/a", TargetNativeID: "arn:role/r", Kind: model.EdgeAssumes}},
		// A read that scopes neither endpoint.
		Envelopes: []collect.Envelope{{Provider: model.AWS, Service: "iam", Operation: "GetAccountAuthorizationDetails", Scope: collect.Scope{Account: "1"}, Response: []byte(`{}`)}},
	}
	out, err := Normalize(scan, fakeKeyer{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Evidence) != 1 {
		t.Fatalf("carried %d evidence, want 1", len(out.Evidence))
	}
	if len(out.Edges[0].Evidence) != 0 {
		t.Errorf("edge evidence = %+v, want none (no resource-scoped read touched an endpoint)", out.Edges[0].Evidence)
	}
}

// TestDanglingEdgeDropped proves a link to a native id with no collected node is
// dropped and counted, never emitted as an edge to a phantom endpoint.
func TestDanglingEdgeDropped(t *testing.T) {
	scan := collect.Scan{
		Nodes: []collect.Node{{Type: model.NodeIdentity, NativeID: "arn:user/a"}},
		Links: []collect.Link{
			{SourceNativeID: "arn:user/a", TargetNativeID: "arn:role/missing", Kind: model.EdgeAssumes},
			{SourceNativeID: "arn:role/missing", TargetNativeID: "arn:user/a", Kind: model.EdgeAssumes},
		},
	}
	out, err := Normalize(scan, fakeKeyer{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Edges) != 0 {
		t.Errorf("emitted %d edges, want 0 (both dangle)", len(out.Edges))
	}
	if out.DroppedEdges != 2 {
		t.Errorf("DroppedEdges = %d, want 2", out.DroppedEdges)
	}
}

// TestCompletenessPassThrough proves the collected completeness is carried
// through unchanged, so a gap reaches the analysis engines intact.
func TestCompletenessPassThrough(t *testing.T) {
	comp := []collect.Completeness{
		{Service: "iam.identities", Status: collect.Complete},
		{Service: "rbac.roleAssignments", Status: collect.Denied, Reason: "access denied"},
	}
	out, err := Normalize(collect.Scan{Completeness: comp}, fakeKeyer{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Completeness, comp) {
		t.Errorf("completeness changed in normalize:\n got %+v\nwant %+v", out.Completeness, comp)
	}
}

// TestNormalizeDeterministic is the determinism guarantee (ADR-0023 §6): fed
// input in a jumbled order, normalize emits a fixed, sorted order, and two runs
// are byte-identical. It is the mutation target for the sorts and the condition
// ordering: dropping the node sort makes the entity order follow input order and
// fail the sorted-order assertion; dropping the condition sort makes two runs
// differ under Go's randomized map iteration.
func TestNormalizeDeterministic(t *testing.T) {
	scan := collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeRole, NativeID: "arn:c"},
			{Type: model.NodeIdentity, NativeID: "arn:a"},
			{Type: model.NodeGroup, NativeID: "arn:b"},
		},
		Links: []collect.Link{
			{SourceNativeID: "arn:a", TargetNativeID: "arn:c", Kind: model.EdgeAssumes, Conditions: map[string]string{"z": "1", "a": "2", "m": "3"}},
			{SourceNativeID: "arn:a", TargetNativeID: "arn:b", Kind: model.EdgeMemberOf},
		},
	}
	first, err := Normalize(scan, fakeKeyer{}, meta)
	if err != nil {
		t.Fatal(err)
	}
	// Entities sorted by native id: a, b, c.
	gotOrder := []string{out(first, 0), out(first, 1), out(first, 2)}
	if !sort.StringsAreSorted(gotOrder) {
		t.Errorf("entities not in native-id order: %v", gotOrder)
	}
	// Conditions on the first link sorted by key: a, m, z.
	var assumes model.Edge
	for _, e := range first.Edges {
		if e.Kind == model.EdgeAssumes {
			assumes = e
		}
	}
	if len(assumes.Conditions) != 3 || assumes.Conditions[0].Key != "a" || assumes.Conditions[2].Key != "z" {
		t.Errorf("conditions not in key order: %+v", assumes.Conditions)
	}
	// Two runs are identical.
	for i := 0; i < 5; i++ {
		again, err := Normalize(scan, fakeKeyer{}, meta)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatal("normalize is not deterministic across runs")
		}
	}
}

func out(n NormalizedScan, i int) string { return n.Entities[i].NativeID }

// TestNormalizeDoesNotImportStore keeps the ADR-0014 boundary structural: the
// analysis-side normalizer must never import the store. A mutation that adds the
// import fails here, not in review.
func TestNormalizeDoesNotImportStore(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "internal/store") {
				t.Errorf("%s imports the store (%s); the normalizer stays on the analysis side of the boundary", name, imp.Path.Value)
			}
		}
	}
}
