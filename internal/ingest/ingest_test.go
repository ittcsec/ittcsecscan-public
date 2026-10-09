package ingest

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestCompletenessMapping proves the collection status maps to the untouched
// coarse code plus the pinned reason: the three non-coverage statuses collapse
// to unknown but keep their distinct reason, so the report engine can count
// denials separately from errors.
func TestCompletenessMapping(t *testing.T) {
	cases := []struct {
		status         collect.Status
		coarse, reason string
	}{
		{collect.Complete, "complete", ""},
		{collect.Partial, "partial", ""},
		{collect.Denied, "unknown", "denied"},
		{collect.Unsupported, "unknown", "unsupported"},
		{collect.Errored, "unknown", "error"},
	}
	for _, c := range cases {
		coarse, reason := completeness(c.status)
		if coarse != c.coarse || reason != c.reason {
			t.Errorf("%s -> (%q,%q), want (%q,%q)", c.status, coarse, reason, c.coarse, c.reason)
		}
	}
}

// TestToStoreCarriesTheGraph proves the mapper carries every part of a scan into
// the store input, with the provider stamped from the run's meta.
func TestToStoreCarriesTheGraph(t *testing.T) {
	scan := collect.Scan{
		Nodes: []collect.Node{{Type: model.NodeIdentity, NativeID: "user-1", Name: "Alice"}},
		Links: []collect.Link{{SourceNativeID: "user-1", TargetNativeID: "acct-1", Kind: model.EdgeMemberOf}},
		Envelopes: []collect.Envelope{{Operation: "GetAccountAuthorizationDetails",
			Provenance: collect.Provenance{Collector: "collector:aws.iam.identities"}, Response: []byte(`{}`)}},
		Completeness: []collect.Completeness{{Service: "iam.identities", Region: "global", Scope: collect.Scope{Account: "acct-1"}, Status: collect.Denied, Collected: 0}},
	}
	in := ToStore(scan, Meta{ToolVersion: "v1", Provider: model.AWS})

	if len(in.Entities) != 1 || in.Entities[0].Provider != model.AWS || in.Entities[0].NativeID != "user-1" {
		t.Fatalf("entities = %+v", in.Entities)
	}
	if len(in.Edges) != 1 || in.Edges[0].Kind != model.EdgeMemberOf {
		t.Fatalf("edges = %+v", in.Edges)
	}
	if len(in.Evidence) != 1 || in.Evidence[0].Collector != "collector:aws.iam.identities" {
		t.Fatalf("evidence = %+v", in.Evidence)
	}
	if len(in.Scopes) != 1 || in.Scopes[0].Completeness != "unknown" || in.Scopes[0].Reason != "denied" || in.Scopes[0].Account != "acct-1" {
		t.Fatalf("scopes = %+v", in.Scopes)
	}
}
