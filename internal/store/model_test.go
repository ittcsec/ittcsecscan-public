package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// The first scan now writes permissions, exposures, and classifications, each
// with its content hash, and the reservation counts their seals exactly.
func TestFirstScanWritesPermissionsExposuresClassifications(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	aws, _ := providerCodes.code("aws")
	role, _ := nodeTypeCodes.code("role")
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	ents := []entityRecord{
		{nativeID: "arn:aws:iam::111111111111:role/a", name: "a", provider: aws, nodeType: role},
		{nativeID: "arn:aws:iam::111111111111:role/b", name: "b", provider: aws, nodeType: role},
	}
	perms := []permissionRecord{
		{principal: 0, resource: 1, action: "s3:GetObject", effect: 1, condition: map[string]string{"aws:SourceIp": "10.0.0.0/8"}, inheritedFrom: -1},
	}
	exps := []exposureRecord{
		{node: 1, sourceZone: 1, protocol: 6, portFrom: 443, portTo: 443, authRequired: 1, effective: 1, trace: map[string]string{"path": "igw"}},
		{node: 0, sourceZone: 1, protocol: -1, portFrom: -1, portTo: -1, authRequired: 2, effective: 2}, // any protocol, any port, no trace
	}
	labels := []labelRecord{
		{entity: 0, label: "crown-jewel", method: "tag", confidence: 90, sample: map[string]string{"k": "v"}},
	}
	if _, err := tn.loadFirstScan(ctx, firstScan{
		toolVersion: "t", manifest: []byte("m"), started: at, completed: at,
		evidence: []evidenceRecord{{collector: "c", api: "a", observed: at}},
		entities: ents, permissions: perms, exposures: exps, labels: labels,
	}); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, tn, "permissions"); got != 1 {
		t.Errorf("permissions = %d, want 1", got)
	}
	if got := countRows(t, tn, "exposures"); got != 2 {
		t.Errorf("exposures = %d, want 2", got)
	}
	if got := countRows(t, tn, "classifications"); got != 1 {
		t.Errorf("classifications = %d, want 1", got)
	}
	// Every current-state row carries a 32-byte content hash.
	for _, tbl := range []string{"permissions", "exposures", "classifications"} {
		total := rowCount(t, tn, "SELECT count(*) FROM "+tbl)
		withHash := rowCount(t, tn, "SELECT count(*) FROM "+tbl+" WHERE length(content_hash) = 32")
		if total != withHash {
			t.Errorf("%s has %d rows, %d with a 32-byte content_hash", tbl, total, withHash)
		}
	}
	// The "any protocol, any port" exposure stored NULLs.
	if n := rowCount(t, tn, "SELECT count(*) FROM exposures WHERE protocol IS NULL AND port_from IS NULL AND port_to IS NULL"); n != 1 {
		t.Errorf("the any-protocol/any-port exposure did not store NULLs (%d)", n)
	}

	// Reservation exact: manifest 1; evidence 0 (no value); entities 2*(native+name)=4;
	// classification label+method+sample=3; permission condition 1; exposure traces 1 (one has none) = 10.
	if got := sealCountNow(t, tn); got != 10 {
		t.Errorf("first-scan seal count = %d, want 10 (manifest + entities + classification + permission + one exposure trace)", got)
	}
}

// The identity and content hashes cover the right fields: a change to any
// identity field yields a different identity, and a change to any content field
// a different content hash. These are what later-scan change detection compares.
func TestModelHashesCoverTheirFields(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	err := tn.withKeys(func(k *tenantKeys) error {
		a, b := k.stableID("a"), k.stableID("b")

		// Permission: (principal, resource, action) is identity; effect,
		// condition, inheritance are content.
		id := permissionIdentity(k, a, b, "read")
		if bytes.Equal(id, permissionIdentity(k, b, b, "read")) || bytes.Equal(id, permissionIdentity(k, a, a, "read")) || bytes.Equal(id, permissionIdentity(k, a, b, "write")) {
			t.Error("permission identity misses a field")
		}
		c := permissionContentHash(k, 1, nil, nil)
		if bytes.Equal(c, permissionContentHash(k, 2, nil, nil)) || bytes.Equal(c, permissionContentHash(k, 1, []byte(`{"x":"y"}`), nil)) || bytes.Equal(c, permissionContentHash(k, 1, nil, a)) {
			t.Error("permission content misses a field (effect, condition, or inheritance)")
		}

		// Exposure: (node, zone, protocol, ports) is identity; auth, effective,
		// trace are content.
		eid := exposureIdentity(k, a, 1, 6, 443, 443)
		if bytes.Equal(eid, exposureIdentity(k, b, 1, 6, 443, 443)) || bytes.Equal(eid, exposureIdentity(k, a, 2, 6, 443, 443)) ||
			bytes.Equal(eid, exposureIdentity(k, a, 1, 17, 443, 443)) || bytes.Equal(eid, exposureIdentity(k, a, 1, 6, 80, 443)) {
			t.Error("exposure identity misses a field")
		}
		ec := exposureContentHash(k, 1, 1, nil)
		if bytes.Equal(ec, exposureContentHash(k, 2, 1, nil)) || bytes.Equal(ec, exposureContentHash(k, 1, 2, nil)) || bytes.Equal(ec, exposureContentHash(k, 1, 1, []byte(`{"t":"1"}`))) {
			t.Error("exposure content misses a field (auth, effective, or trace)")
		}

		// Classification: (node, label, method) is identity; confidence, sample
		// are content.
		cid := classificationIdentity(k, a, "jewel", "tag")
		if bytes.Equal(cid, classificationIdentity(k, b, "jewel", "tag")) || bytes.Equal(cid, classificationIdentity(k, a, "other", "tag")) || bytes.Equal(cid, classificationIdentity(k, a, "jewel", "ml")) {
			t.Error("classification identity misses a field")
		}
		cc := classificationContentHash(k, 90, nil)
		if bytes.Equal(cc, classificationContentHash(k, 80, nil)) || bytes.Equal(cc, classificationContentHash(k, 90, []byte(`{"s":"1"}`))) {
			t.Error("classification content misses a field (confidence or sample)")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
