package graph

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func classificationFor(res ClassificationResult, nativeID string) (model.Classification, bool) {
	id := sid(nativeID)
	for _, c := range res.Classifications {
		if c.Entity == id {
			return c, true
		}
	}
	return model.Classification{}, false
}

func classifyScan(nodes ...collect.Node) *collect.Scan {
	return &collect.Scan{Nodes: nodes, Completeness: []collect.Completeness{
		{Service: "s3.bucketConfig", Status: collect.Complete},
		{Service: "kms.keyDetails", Status: collect.Complete},
	}}
}

// TestClassifyDeclaredTag proves a customer classification tag is authoritative and
// high-confidence, and that an unrecognized value fails closed to unknown (never a
// guessed label).
func TestClassifyDeclaredTag(t *testing.T) {
	restricted := node(model.NodeDataStore, "arn:aws:s3:::a", map[string]string{"tag:data_classification": "restricted"})
	weird := node(model.NodeDataStore, "arn:aws:s3:::b", map[string]string{"tag:classification": "level-7-eyes-only"})
	res := Classify(norm(classifyScan(restricted, weird)))

	c, ok := classificationFor(res, "arn:aws:s3:::a")
	if !ok || c.Label != string(model.SensitivityHigh) || c.Confidence < 80 {
		t.Errorf("declared restricted: got %+v, want high high-confidence", c)
	}
	if !strings.Contains(c.Method, "declared tag:data_classification=restricted") {
		t.Errorf("method not transparent: %q", c.Method)
	}
	w, _ := classificationFor(res, "arn:aws:s3:::b")
	if w.Label != string(model.SensitivityUnknown) {
		t.Errorf("unrecognized declared value must be unknown, got %s", w.Label)
	}
}

// TestClassifyKeyMaterialIsHigh proves key and secret stores are intrinsically high
// across all three clouds.
func TestClassifyKeyMaterialIsHigh(t *testing.T) {
	for _, id := range []string{
		"arn:aws:kms:us-east-1:1:key/abc",
		"//cloudkms.googleapis.com/projects/p/locations/l/keyRings/r/cryptoKeys/k",
	} {
		res := Classify(norm(classifyScan(node(model.NodeControl, id, nil))))
		c, ok := classificationFor(res, id)
		if !ok || c.Label != string(model.SensitivityHigh) {
			t.Errorf("key material %s: got %+v, want high", id, c)
		}
	}
	// Azure Key Vault is identified by azure_type.
	kv := node(model.NodeControl, "/subscriptions/s/vaults/v", map[string]string{"azure_type": "key_vault"})
	res := Classify(norm(classifyScan(kv)))
	if c, ok := classificationFor(res, "/subscriptions/s/vaults/v"); !ok || c.Label != string(model.SensitivityHigh) {
		t.Errorf("key vault: got %+v, want high", c)
	}
}

// TestClassifyDataStoreWithNameToken proves a data store with a sensitive naming
// segment is high, and that matching is on whole segments (no substring false hit).
func TestClassifyDataStoreWithNameToken(t *testing.T) {
	pii := node(model.NodeDataStore, "arn:aws:s3:::prod-customer-pii", nil)
	res := Classify(norm(classifyScan(pii)))
	c, _ := classificationFor(res, "arn:aws:s3:::prod-customer-pii")
	if c.Label != string(model.SensitivityHigh) || !strings.Contains(c.Method, "name_token=") {
		t.Errorf("data store with pii name: got %+v, want high with name_token", c)
	}
	// "dolphin" contains "phi" as a substring but is not a whole segment: must not match.
	dolphin := node(model.NodeDataStore, "arn:aws:s3:::dolphin-media", nil)
	res2 := Classify(norm(classifyScan(dolphin)))
	d, _ := classificationFor(res2, "arn:aws:s3:::dolphin-media")
	if strings.Contains(d.Method, "name_token") {
		t.Errorf("substring should not match a name token: %q", d.Method)
	}
}

// TestClassifyDataStoreFailClosed is the safety-critical guarantee: a data store with
// no classification tag and no sensitive naming signal resolves to unknown, never a
// confident label and never low (an untagged store is possibly sensitive, not safe).
func TestClassifyDataStoreFailClosed(t *testing.T) {
	bare := node(model.NodeDataStore, "arn:aws:s3:::plain-bucket", map[string]string{"region": "us-east-1"})
	res := Classify(norm(classifyScan(bare)))
	c, ok := classificationFor(res, "arn:aws:s3:::plain-bucket")
	if !ok {
		t.Fatal("a data store must be classified (as unknown), not silently omitted")
	}
	if c.Label != string(model.SensitivityUnknown) {
		t.Errorf("bare data store must be unknown, got %s (never a guess, never low)", c.Label)
	}
	if c.Label == string(model.SensitivityLow) {
		t.Error("bare data store must never be low (non-sensitive)")
	}
}

// TestClassifyNonCandidateNoRecord proves a resource this engine does not classify
// (a subnet) gets no classification record.
func TestClassifyNonCandidateNoRecord(t *testing.T) {
	net := node(model.NodeNetwork, "arn:aws:ec2:u:1:subnet/subnet-1", map[string]string{"aws_type": "subnet"})
	res := Classify(norm(classifyScan(net)))
	if _, ok := classificationFor(res, "arn:aws:ec2:u:1:subnet/subnet-1"); ok {
		t.Error("a non-candidate (subnet) must not be classified")
	}
}

// TestClassifyNeverSamplesContent proves the approved-sampling field is never set:
// classification is from metadata alone this phase.
func TestClassifyNeverSamplesContent(t *testing.T) {
	res := Classify(norm(classifyScan(
		node(model.NodeDataStore, "arn:aws:s3:::a", map[string]string{"tag:classification": "restricted"}),
		node(model.NodeControl, "arn:aws:kms:us-east-1:1:key/k", nil),
	)))
	if len(res.Classifications) == 0 {
		t.Fatal("expected classifications")
	}
	for _, c := range res.Classifications {
		if c.ApprovedSample != "" {
			t.Errorf("ApprovedSample must be empty (content sampling disabled): %q", c.ApprovedSample)
		}
	}
}

// TestClassifyHonestCompleteness proves a denied read that could carry a tag makes
// the result an explicit floor, never asserted exhaustive.
func TestClassifyHonestCompleteness(t *testing.T) {
	scan := &collect.Scan{
		Nodes:        []collect.Node{node(model.NodeDataStore, "arn:aws:s3:::a", nil)},
		Completeness: []collect.Completeness{{Service: "s3.bucketConfig", Status: collect.Denied, Reason: "denied"}},
	}
	res := Classify(norm(scan))
	if res.Complete {
		t.Error("classification reported Complete despite a denied read")
	}
	if len(res.Gaps) == 0 {
		t.Error("no gap cited for the denied read")
	}
}
