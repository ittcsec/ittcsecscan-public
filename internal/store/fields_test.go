package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"maps"
	"regexp"
	"slices"
	"testing"
)

// Field names and hash purposes are part of the file format (ADR-0013):
// renaming one leaves every value sealed or hashed under it unreadable or
// unmatched. The lists only ever grow at the end.
var pinnedFieldNames = []string{
	"tenant.display_name", "scan.manifest", "scope.account", "scope.region",
	"evidence.redacted_value", "entity.native_id", "entity.name", "entity.tags", "entity.attributes",
	"entity_snapshot.content", "edge.conditions", "permission.condition",
	"exposure.trace", "classification.label", "classification.method",
	"classification.approved_sample", "finding.detail", "attack_path.steps",
	"cut_set.change_set", "remediation_plan.actions", "remediation_plan.preconditions",
	"remediation_plan.approvals", "remediation_plan.rollback",
	"criticality_override.actor", "criticality_override.reason",
	"remediation_receipt.prior_state", "remediation_receipt.refusal",
}

var pinnedHashPurposes = []string{
	"scan.manifest", "evidence.value", "entity.content", "edge.content",
	"classification.identity", "classification.content",
	"permission.identity", "permission.content", "exposure.identity", "exposure.content",
}

// sealedColumns maps every sealed column of the production schema to its
// field. A column may be renamed; its field never is.
var sealedColumns = map[string]Field{
	"tenant.display_name_sealed":              FieldTenantDisplayName(),
	"scans.manifest_sealed":                   FieldScanManifest(),
	"scopes.account_sealed":                   FieldScopeAccount(),
	"scopes.region_sealed":                    FieldScopeRegion(),
	"evidence.redacted_value_sealed":          FieldEvidenceValue(),
	"entities.native_id_sealed":               FieldEntityNativeID(),
	"entities.name_sealed":                    FieldEntityName(),
	"entities.tags_sealed":                    FieldEntityTags(),
	"entities.attributes_sealed":              FieldEntityAttributes(),
	"entity_snapshots.content_sealed":         FieldEntitySnapshotContent(),
	"edges.conditions_sealed":                 FieldEdgeConditions(),
	"edge_snapshots.conditions_sealed":        FieldEdgeConditions(),
	"permissions.condition_sealed":            FieldPermissionCondition(),
	"exposures.trace_sealed":                  FieldExposureTrace(),
	"classifications.label_sealed":            FieldClassificationLabel(),
	"classifications.method_sealed":           FieldClassificationMethod(),
	"classifications.approved_sample_sealed":  FieldClassificationSample(),
	"criticality_overrides.actor_sealed":      FieldOverrideActor(),
	"criticality_overrides.reason_sealed":     FieldOverrideReason(),
	"findings.detail_sealed":                  FieldFindingDetail(),
	"attack_paths.steps_sealed":               FieldAttackPathSteps(),
	"cut_sets.change_set_sealed":              FieldCutSetChangeSet(),
	"remediation_plans.actions_sealed":        FieldPlanActions(),
	"remediation_plans.preconditions_sealed":  FieldPlanPreconditions(),
	"remediation_plans.approvals_sealed":      FieldPlanApprovals(),
	"remediation_plans.rollback_sealed":       FieldPlanRollback(),
	"remediation_receipts.prior_state_sealed": FieldReceiptPriorState(),
	"remediation_receipts.refusal_sealed":     FieldReceiptRefusal(),
}

func TestFieldNamesArePinned(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z_]+\.[a-z_]+$`)
	var got []string
	for _, f := range sealedFields {
		if !shape.MatchString(f.name) || slices.Contains(got, f.name) {
			t.Errorf("field %q is malformed or repeated", f.name)
		}
		got = append(got, f.name)
	}
	if !slices.Equal(got, pinnedFieldNames) {
		t.Errorf("fields:\n%q\nwant:\n%q", got, pinnedFieldNames)
	}
	var purposes []string
	for _, p := range hashPurposes {
		purposes = append(purposes, string(p))
	}
	if !slices.Equal(purposes, pinnedHashPurposes) {
		t.Errorf("hash purposes %q, want %q", purposes, pinnedHashPurposes)
	}
}

func TestEverySealedColumnHasAField(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	var columns []string
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, `SELECT m.name || '.' || p.name FROM sqlite_schema AS m, pragma_table_xinfo(m.name) AS p
			WHERE m.type = 'table' AND p.name LIKE '%\_sealed' ESCAPE '\' ORDER BY 1`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var col string
			if err := rows.Scan(&col); err != nil {
				return err
			}
			columns = append(columns, col)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Sorted(maps.Keys(sealedColumns)); !slices.Equal(columns, want) {
		t.Errorf("sealed columns in the schema:\n%q\nwith a field:\n%q", columns, want)
	}
	for _, f := range sealedFields {
		if !slices.Contains(slices.Collect(maps.Values(sealedColumns)), f) {
			t.Errorf("field %s has no column", f)
		}
	}
}

// The maintainer's requirement for the canonical schema: renaming a column or a
// table must never break decryption (ADR-0013).
func TestSealedValuesSurviveARename(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/r", name: "payroll-admin"}})
	var sealed []byte
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		for _, stmt := range []string{
			"ALTER TABLE entities RENAME COLUMN name_sealed TO display_name_sealed",
			"ALTER TABLE entities RENAME TO graph_nodes",
		} {
			if _, err := c.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return c.QueryRowContext(ctx, "SELECT display_name_sealed FROM graph_nodes WHERE node_id = 1").Scan(&sealed)
	})
	if err != nil {
		t.Fatal(err)
	}
	if name, err := tn.OpenValue(FieldEntityName(), 1, sealed); err != nil || string(name) != "payroll-admin" {
		t.Errorf("after renaming the column and the table: %q, %v", name, err)
	}
}

func TestSealingNeedsAField(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	if _, err := tn.SealValue(Field{}, 1, []byte("x")); !errors.Is(err, errNoField) {
		t.Errorf("sealing without a field: error = %v", err)
	}
	if _, err := tn.OpenValue(Field{}, 1, []byte("x")); !errors.Is(err, errNoField) {
		t.Errorf("opening without a field: error = %v", err)
	}
}

// A row key comes from AUTOINCREMENT, so it is at least 1. A value bound to 0
// or a negative key could belong to no row, and is refused both ways.
func TestSealingNeedsAPositiveRow(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	sealed, err := tn.SealValue(FieldEntityName(), 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []int64{0, -1} {
		if _, err := tn.SealValue(FieldEntityName(), row, []byte("x")); !errors.Is(err, errNoRow) {
			t.Errorf("sealing for row %d: error = %v, want errNoRow", row, err)
		}
		if _, err := tn.OpenValue(FieldEntityName(), row, sealed); !errors.Is(err, errNoRow) {
			t.Errorf("opening for row %d: error = %v, want errNoRow", row, err)
		}
	}
	if pt, err := tn.OpenValue(FieldEntityName(), 1, sealed); err != nil || string(pt) != "x" {
		t.Errorf("row 1: %q, %v", pt, err)
	}
}

func TestKeyedHashesAreSeparated(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := acquire(t, s, createTenant(t, s)), acquire(t, s, createTenant(t, s))
	sums := func(tn *Tenant) [][]byte {
		var out [][]byte
		err := tn.withKeys(func(k *tenantKeys) error {
			for _, p := range hashPurposes {
				out = append(out, k.hash(p, "same content"))
			}
			out = append(out, k.stableID("same content"), k.hash(hashEntityContent, "same content"))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	sa, sb := sums(a), sums(b)
	if !bytes.Equal(sa[len(sa)-1], sa[slices.Index(hashPurposes, hashEntityContent)]) {
		t.Error("a keyed hash is not deterministic")
	}
	distinct := map[string]bool{}
	for _, h := range append(sa[:len(sa)-1], sb[:len(sb)-1]...) {
		if len(h) != 32 || distinct[string(h)] {
			t.Errorf("keyed hashes repeat across purposes, stable IDs, or tenants")
		}
		distinct[string(h)] = true
	}
}
