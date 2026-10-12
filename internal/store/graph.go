package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

// The queries the attack-path engine runs most (ADR-0011 §4). Tests pin
// their query plans, with and without statistics, and the scale benchmark
// checks them again at 500,000 entities.
const (
	sqlGraphEdges     = "SELECT src, kind, dst FROM edges ORDER BY src, kind, dst"
	sqlOutNeighbours  = "SELECT kind, dst FROM edges WHERE src = ?"
	sqlInNeighbours   = "SELECT kind, src FROM edges WHERE dst = ?"
	sqlNodeByStableID = "SELECT node_id FROM entities WHERE stable_id = ?"
	sqlFindingsByNode = "SELECT finding_id FROM findings WHERE node_id = ?"
	sqlLabels         = "SELECT node_id, classification_id, label_sealed FROM classifications"
)

// graph is a tenant's attack graph in compressed sparse rows (ADR-0011 §4).
// The edges out of node n are targets[offsets[n]:offsets[n+1]], with their
// kinds at the same positions in kinds. labels holds each classified node's
// decrypted labels: they mark the attack targets.
type graph struct {
	offsets []uint32
	targets []uint32
	kinds   []uint16
	labels  map[uint32][]string
}

// out returns node n's out-edges.
func (g *graph) out(n uint32) ([]uint32, []uint16) {
	if int(n)+1 >= len(g.offsets) {
		return nil, nil
	}
	lo, hi := g.offsets[n], g.offsets[n+1]
	return g.targets[lo:hi], g.kinds[lo:hi]
}

func (g *graph) edgeCount() int { return len(g.targets) }

// graphReadHook, when set, runs once inside loadGraph's read transaction,
// after the edges and before the labels. It is nil in production; tests use
// it to commit from another connection and prove the reads share one
// snapshot.
var graphReadHook func()

// querier is the part of *sql.Conn and *sql.Tx the graph reads through.
type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// loadGraph reads the tenant's graph with one ordered scan of the edges_out
// covering index, and decrypts one label per classification. All three reads
// run in one read transaction, so they see a single consistent snapshot even
// if another process commits to the file between them.
func (t *Tenant) loadGraph(ctx context.Context) (*graph, error) {
	g := &graph{labels: map[uint32][]string{}}
	err := t.withConn(ctx, func(c *sql.Conn) (err error) {
		// Non-cancellable to avoid the shared-connection rollback race; see
		// the comment on BeginTx in (*Tenant).View (repo.go).
		tx, err := c.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, tx.Rollback()) }()
		var maxNode int64
		if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(node_id), 0) FROM entities").Scan(&maxNode); err != nil {
			return err
		}
		if maxNode >= math.MaxUint32 {
			return fmt.Errorf("store: node IDs reach %d, beyond what the graph can address", maxNode)
		}
		g.offsets = make([]uint32, maxNode+2)
		if err := g.readEdges(ctx, tx, maxNode); err != nil {
			return err
		}
		if graphReadHook != nil {
			graphReadHook() // between reads; tests commit from another connection here
		}
		return t.withKeys(func(k *tenantKeys) error { return g.readLabels(ctx, tx, k, maxNode) })
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (g *graph) readEdges(ctx context.Context, c querier, maxNode int64) (err error) {
	rows, err := c.QueryContext(ctx, sqlGraphEdges)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	prev := int64(0)
	for rows.Next() {
		var src, kind, dst int64
		if err := rows.Scan(&src, &kind, &dst); err != nil {
			return err
		}
		switch {
		case src < prev:
			return errors.New("store: edges did not arrive in source order")
		case src < 1 || src > maxNode || dst < 1 || dst > maxNode:
			return fmt.Errorf("store: edge %d -> %d names a node outside 1 to %d", src, dst, maxNode)
		case kind < 1 || kind > math.MaxUint16:
			return fmt.Errorf("store: edge kind %d is out of range", kind)
		case len(g.targets) >= math.MaxUint32:
			return errors.New("store: too many edges for the graph")
		}
		prev = src
		g.offsets[src+1]++
		g.targets = append(g.targets, uint32(dst))
		g.kinds = append(g.kinds, uint16(kind))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := 1; i < len(g.offsets); i++ {
		g.offsets[i] += g.offsets[i-1]
	}
	return nil
}

func (g *graph) readLabels(ctx context.Context, c querier, k *tenantKeys, maxNode int64) (err error) {
	rows, err := c.QueryContext(ctx, sqlLabels)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var node, id int64
		var sealed []byte
		if err := rows.Scan(&node, &id, &sealed); err != nil {
			return err
		}
		if node < 1 || node > maxNode {
			return fmt.Errorf("store: a label names node %d, outside 1 to %d", node, maxNode)
		}
		label, err := k.open(FieldClassificationLabel(), id, sealed)
		if err != nil {
			return err
		}
		g.labels[uint32(node)] = append(g.labels[uint32(node)], string(label))
	}
	return rows.Err()
}
