package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestMaterializeClassificationSetsFacts proves classification is projected onto
// entity attributes as consumable facts, including an explicit sensitivity=unknown
// for a fail-closed candidate (so an unclassified asset is visible, not absent).
func TestMaterializeClassificationSetsFacts(t *testing.T) {
	g := norm(classifyScan(
		node(model.NodeDataStore, "arn:aws:s3:::a", map[string]string{"tag:data_classification": "restricted"}),
		node(model.NodeControl, "arn:aws:kms:us-east-1:1:key/k", nil),
		node(model.NodeDataStore, "arn:aws:s3:::plain", map[string]string{"region": "us-east-1"}),
	))
	res := MaterializeClassification(g)
	if len(res.Classifications) == 0 {
		t.Fatal("expected classifications")
	}
	a := entAttr(g, "arn:aws:s3:::a")
	if a["sensitivity"] != "high" || a["sensitivity_confidence"] == "" || a["sensitivity_method"] == "" {
		t.Errorf("declared restricted bucket not materialized as high: %+v", a)
	}
	k := entAttr(g, "arn:aws:kms:us-east-1:1:key/k")
	if k["sensitivity"] != "high" {
		t.Errorf("key material sensitivity = %q, want high", k["sensitivity"])
	}
	// Fail-closed: a plain data store is materialized as unknown, not left absent.
	p := entAttr(g, "arn:aws:s3:::plain")
	if p["sensitivity"] != "unknown" {
		t.Errorf("plain data store sensitivity = %q, want unknown (fail-closed, visible)", p["sensitivity"])
	}
}
