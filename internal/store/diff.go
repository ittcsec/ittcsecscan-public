package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// EntityDelta is one entity the later-scan change-detection engine recorded as changed in
// a scan: its identity, type, and the kind of change. NativeID and Name are decrypted here.
type EntityDelta struct {
	StableID model.StableID
	Type     model.NodeType
	NativeID string
	Name     string
	Change   string // "appeared", "changed", or "disappeared"
}

// EdgeDelta is one edge recorded as changed in a scan, with both endpoints' native ids
// decrypted where the endpoint entity rows are still retained.
type EdgeDelta struct {
	Kind   model.EdgeKind
	Source string
	Target string
	Change string // "appeared", "changed", or "disappeared"
}

// Diff is the set of entity and edge changes the later-scan change-detection engine
// (ADR-0011 section 1) recorded for one scan at ingest. It surfaces what was already
// detected and stored; it computes no new change and is read-only and tenant-scoped.
type Diff struct {
	ScanID   int64
	Entities []EntityDelta
	Edges    []EdgeDelta
}

// finishedStatuses are the scan statuses that have recorded change rows: a scan that
// completed or finished incomplete, never one still running.
func finishedStatuses() (completed, incomplete int64) {
	completed, _ = scanStatusCodes.code("completed")
	incomplete, _ = scanStatusCodes.code("incomplete")
	return
}

// LatestScanID returns the id of the most recent finished scan (completed or incomplete),
// or 0 if the tenant has no such scan.
func (t *Tenant) LatestScanID(ctx context.Context) (int64, error) {
	completed, incomplete := finishedStatuses()
	var id int64
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return c.QueryRowContext(ctx,
			"SELECT coalesce(max(scan_id), 0) FROM scans WHERE status IN (?, ?)", completed, incomplete).Scan(&id)
	})
	return id, err
}

// Diff returns the entity and edge changes recorded for scanID. If scanID <= 0, the latest
// finished scan is used (0 entities and edges when the tenant has no scans). Endpoints and
// names are decrypted.
func (t *Tenant) Diff(ctx context.Context, scanID int64) (Diff, error) {
	d := Diff{}
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) (err error) {
			tx, err := c.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, tx.Rollback()) }()

			if scanID <= 0 {
				completed, incomplete := finishedStatuses()
				if err = tx.QueryRowContext(ctx,
					"SELECT coalesce(max(scan_id), 0) FROM scans WHERE status IN (?, ?)", completed, incomplete).Scan(&scanID); err != nil {
					return err
				}
			}
			d.ScanID = scanID
			if scanID == 0 {
				return nil // no scans yet; an empty diff is honest, not an error
			}

			if err = diffEntities(ctx, tx, k, scanID, &d); err != nil {
				return err
			}
			return diffEdges(ctx, tx, k, scanID, &d)
		})
	})
	return d, err
}

func diffEntities(ctx context.Context, tx *sql.Tx, k *tenantKeys, scanID int64, d *Diff) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT es.node_id, es.change, e.stable_id, e.type, e.native_id_sealed, e.name_sealed
		 FROM entity_snapshots es JOIN entities e ON e.node_id = es.node_id
		 WHERE es.scan_id = ? ORDER BY es.node_id`, scanID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var node, change, typ int64
		var sid, nativeSealed, nameSealed []byte
		if err := rows.Scan(&node, &change, &sid, &typ, &nativeSealed, &nameSealed); err != nil {
			return err
		}
		changeName, ok := changeCodes.name(change)
		typeName, ok2 := nodeTypeCodes.name(typ)
		if !ok || !ok2 {
			return fmt.Errorf("%w: entity snapshot has change code %d or type code %d", ErrForeignFile, change, typ)
		}
		native, err := k.open(FieldEntityNativeID(), node, nativeSealed)
		if err != nil {
			return err
		}
		name := ""
		if nameSealed != nil {
			pt, err := k.open(FieldEntityName(), node, nameSealed)
			if err != nil {
				return err
			}
			name = string(pt)
		}
		d.Entities = append(d.Entities, EntityDelta{
			StableID: model.StableID(hex.EncodeToString(sid)),
			Type:     model.NodeType(typeName),
			NativeID: string(native),
			Name:     name,
			Change:   changeName,
		})
	}
	return rows.Err()
}

func diffEdges(ctx context.Context, tx *sql.Tx, k *tenantKeys, scanID int64, d *Diff) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT esn.change, esn.kind, esn.src, esn.dst, es.native_id_sealed, ed.native_id_sealed
		 FROM edge_snapshots esn
		 LEFT JOIN entities es ON es.node_id = esn.src
		 LEFT JOIN entities ed ON ed.node_id = esn.dst
		 WHERE esn.scan_id = ? ORDER BY esn.src, esn.kind, esn.dst`, scanID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var change, kind, src, dst int64
		var srcSealed, dstSealed []byte
		if err := rows.Scan(&change, &kind, &src, &dst, &srcSealed, &dstSealed); err != nil {
			return err
		}
		changeName, ok := changeCodes.name(change)
		kindName, ok2 := edgeKindCodes.name(kind)
		if !ok || !ok2 {
			return fmt.Errorf("%w: edge snapshot has change code %d or kind code %d", ErrForeignFile, change, kind)
		}
		srcRef, err := endpointRef(k, src, srcSealed)
		if err != nil {
			return err
		}
		dstRef, err := endpointRef(k, dst, dstSealed)
		if err != nil {
			return err
		}
		d.Edges = append(d.Edges, EdgeDelta{Kind: model.EdgeKind(kindName), Source: srcRef, Target: dstRef, Change: changeName})
	}
	return rows.Err()
}

// endpointRef decrypts an edge endpoint's native id when the endpoint's entity row is
// still retained, and otherwise reports it as not retained (never exposing the file-local
// node id).
func endpointRef(k *tenantKeys, nodeID int64, nativeSealed []byte) (string, error) {
	if nativeSealed == nil {
		return "(endpoint not retained)", nil
	}
	native, err := k.open(FieldEntityNativeID(), nodeID, nativeSealed)
	if err != nil {
		return "", err
	}
	return string(native), nil
}
