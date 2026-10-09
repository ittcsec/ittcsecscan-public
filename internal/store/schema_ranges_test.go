package store

import (
	"context"
	"database/sql"
	"testing"
)

// A port range has both ends or neither. A CHECK that evaluates to NULL
// passes in SQLite, so the column checks alone accepted a half-open range;
// exposures has a table-level CHECK against it.
func TestExposurePortRangesAreWhole(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/r", name: "n"}})
	for _, c := range []struct {
		from, to any
		ok       bool
	}{
		{nil, nil, true},
		{80, 443, true},
		{443, 443, true},
		{nil, 443, false},
		{443, nil, false},
		{500, 100, false},
		{-1, 10, false},
		{0, 70000, false},
	} {
		err := tn.withConn(ctx, func(conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, `INSERT INTO exposures (tenant_id, exposure_hash, node_id, source_zone, protocol, port_from, port_to,
				auth_required, effective, content_hash, first_seen_scan, last_seen_scan) VALUES (?, randomblob(32), 1, 1, 6, ?, ?, 0, 1, zeroblob(32), 1, 1)`,
				tn.ID().String(), c.from, c.to)
			return err
		})
		if (err == nil) != c.ok {
			t.Errorf("ports %v to %v: error = %v, want accepted = %v", c.from, c.to, err, c.ok)
		}
	}
}
