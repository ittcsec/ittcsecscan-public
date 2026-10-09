package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The tenant-isolation fixtures (ADR-0010 §3): three tenants of 120, 210, and
// 300 entities. Each holds every identifier below, which exists unchanged in
// every customer's estate, under the same display names. Isolation must hold
// even though the tenants' inputs overlap this much.
var sharedNativeIDs = []string{
	// AWS managed policies: identical ARNs in every AWS account.
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/ReadOnlyAccess",
	"arn:aws:iam::aws:policy/SecurityAudit",
	"arn:aws:iam::aws:policy/PowerUserAccess",
	"arn:aws:iam::aws:policy/ViewOnlyAccess",
	"arn:aws:iam::aws:policy/IAMFullAccess",
	"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
	"arn:aws:iam::aws:policy/AWSSupportAccess",
	// Azure built-in role definitions: identical IDs in every tenant.
	"/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
	"/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c", // Contributor
	"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7", // Reader
	"/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", // User Access Administrator
	// GCP basic roles.
	"roles/owner",
	"roles/editor",
	"roles/viewer",
	// One third-party account that every tenant trusts.
	"arn:aws:iam::123456789012:root",
}

var sharedNames = []string{"prod-admin", "break-glass", "ci-deployer"}

type fixtureEntity struct{ native, name string }

var fixtureSizes = []int{120, 210, 300}

// fixtureTenants returns the three fixtures. Each starts with every shared
// identifier; the rest are roles in the tenant's own account, still named from
// the shared names.
func fixtureTenants() [][]fixtureEntity {
	out := make([][]fixtureEntity, len(fixtureSizes))
	for ti, n := range fixtureSizes {
		es := make([]fixtureEntity, 0, n)
		for i, id := range sharedNativeIDs {
			es = append(es, fixtureEntity{native: id, name: sharedNames[i%len(sharedNames)]})
		}
		account := int64(222222222222) * int64(ti+1)
		for i := len(es); i < n; i++ {
			es = append(es, fixtureEntity{
				native: fmt.Sprintf("arn:aws:iam::%012d:role/app-%03d", account, i),
				name:   sharedNames[i%len(sharedNames)],
			})
		}
		out[ti] = es
	}
	return out
}

// mustCode returns name's code in l.
func mustCode(t *testing.T, l codeList, name string) int64 {
	t.Helper()
	c, ok := l.code(name)
	if !ok {
		t.Fatalf("%q is not a code", name)
	}
	return c
}

// fixtureProvider guesses a native identifier's provider from its shape.
func fixtureProvider(t *testing.T, native string) int64 {
	switch {
	case strings.HasPrefix(native, "/providers/"):
		return mustCode(t, providerCodes, "azure")
	case strings.HasPrefix(native, "roles/"):
		return mustCode(t, providerCodes, "gcp")
	default:
		return mustCode(t, providerCodes, "aws")
	}
}

type fixtureRow struct {
	tenantID, stableID string
	node               int64
	nativeSealed       []byte
	nameSealed         []byte
}

// loadFixture writes es as the tenant's first scan into the canonical
// entities table: stable IDs from the tenant's stable-ID key, native IDs and
// names sealed with its data key.
func loadFixture(t *testing.T, tn *Tenant, es []fixtureEntity) {
	t.Helper()
	at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	records := make([]entityRecord, len(es))
	for i, e := range es {
		records[i] = entityRecord{nativeID: e.native, name: e.name, provider: fixtureProvider(t, e.native), nodeType: mustCode(t, nodeTypeCodes, "role")}
	}
	_, err := tn.loadFirstScan(context.Background(), firstScan{
		toolVersion: "fixture", manifest: []byte("fixture"), started: at, completed: at,
		evidence: []evidenceRecord{{collector: "fixture", api: "fixture", observed: at}},
		entities: records,
	})
	if err != nil {
		t.Fatalf("loading fixture into %s: %v", tn.ID(), err)
	}
}

func readFixture(t *testing.T, tn *Tenant) []fixtureRow {
	t.Helper()
	ctx := context.Background()
	var out []fixtureRow
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, "SELECT tenant_id, node_id, stable_id, native_id_sealed, name_sealed FROM entities ORDER BY node_id")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r fixtureRow
			var sid []byte
			if err := rows.Scan(&r.tenantID, &r.node, &sid, &r.nativeSealed, &r.nameSealed); err != nil {
				return err
			}
			r.stableID = hex.EncodeToString(sid)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("reading fixture of %s: %v", tn.ID(), err)
	}
	return out
}

// fixtureStore creates the three fixture tenants and loads them.
func fixtureStore(t *testing.T, opts ...func(*Options)) (*Store, []TenantID, Options) {
	t.Helper()
	s, o := newTestStore(t, opts...)
	var ids []TenantID
	for _, es := range fixtureTenants() {
		id := createTenant(t, s)
		tn, release, err := s.Acquire(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		loadFixture(t, tn, es)
		release()
		ids = append(ids, id)
	}
	return s, ids, o
}

func TestFixtureShape(t *testing.T) {
	fx := fixtureTenants()
	for i, es := range fx {
		if len(es) != fixtureSizes[i] || len(es) < 100 || len(es) > 300 {
			t.Errorf("fixture %d has %d entities, want %d (100-300)", i, len(es), fixtureSizes[i])
		}
		for j, id := range sharedNativeIDs {
			if es[j].native != id {
				t.Errorf("fixture %d does not start with the shared identifiers", i)
			}
		}
	}
}
