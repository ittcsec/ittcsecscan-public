package store

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The scale benchmark of ADR-0011 §4 (decision 8). It runs only when asked:
//
//	go test -run '^TestScaleProfile$' -timeout 50m ./internal/store/ -args -scale.entities=500000
//
// CI's "scale benchmark (500k entities)" job runs it and reports; it is not a
// required check yet (owner decision, 2026-09-13).
var (
	scaleEntities = flag.Int("scale.entities", 0, "run TestScaleProfile with this many entities; 0 skips it")
	scaleBudget   = flag.Duration("scale.budget", 10*time.Second, "the budget for the median graph load (ADR-0011 §4)")
	scaleIngest   = flag.Duration("scale.ingest-budget", 90*time.Second, "the budget for the initial load (owner decision, 2026-09-13)")
	scaleLater    = flag.Duration("scale.later-ingest-budget", 35*time.Second, "the provisional later-scan ingest budget (B-4, owner 2026-09-16); reported, not enforced")
	scaleSummary  = flag.String("scale.summary", "", "append the results, in Markdown, to this file")
)

// scaleChurn is the fraction of the estate a measured later scan changes: one
// entity in scaleChurn is renamed and one edge in scaleChurn has its content
// changed (B-4's "up to 5%").
const scaleChurn = 20

const (
	scaleEdgesPerEntity = 10 // ADR-0010's estate profiles
	scaleLabelEvery     = 10 // one entity in ten is classified
)

func TestScaleProfile(t *testing.T) {
	n := *scaleEntities
	if n == 0 {
		t.Skip("the scale benchmark runs with -args -scale.entities=500000")
	}
	ctx := context.Background()
	s, _ := newTestStore(t)
	id := createTenant(t, s)
	tn := acquire(t, s, id)
	scan := syntheticScan(t, n, scaleEdgesPerEntity, scaleLabelEvery, 1)

	start := time.Now()
	if _, err := tn.loadFirstScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	ingest := time.Since(start)

	var analyze time.Duration
	var problems []string
	var fks int
	var size int64
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		start := time.Now()
		if _, err := c.ExecContext(ctx, "ANALYZE"); err != nil {
			return err
		}
		analyze = time.Since(start)
		var err error
		if problems, fks, err = planProblems(ctx, c); err != nil {
			return err
		}
		_, err = c.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dbPath(tenantDir(t, s, id))); err == nil {
		size = fi.Size()
	}

	var loads []time.Duration
	var g *graph
	for range 3 {
		start := time.Now()
		if g, err = tn.loadGraph(ctx); err != nil {
			t.Fatal(err)
		}
		loads = append(loads, time.Since(start))
	}
	median := slices.Sorted(slices.Values(loads))[1]
	labelled := 0
	for _, l := range g.labels {
		labelled += len(l)
	}

	// A later scan changing about 5% of the estate, measured against the
	// provisional B-4 budget. Reported, not enforced, until the maintainer confirms
	// the budget from a real number. The phase breakdown shows where the time
	// goes, so an over-budget number can be diagnosed rather than guessed.
	later := syntheticLaterScan(scan, n)
	var phases []string
	scanPhase = func(name string, d time.Duration) {
		phases = append(phases, fmt.Sprintf("%s %s", name, d.Round(time.Millisecond)))
	}
	beforeSeals := sealCountNow(t, tn)
	start = time.Now()
	if _, err := tn.ingestScan(ctx, later); err != nil {
		t.Fatal(err)
	}
	laterIngest := time.Since(start)
	scanPhase = nil
	laterSeals := sealCountNow(t, tn) - beforeSeals

	report := fmt.Sprintf(`## Scale benchmark: %d entities, %d edges

| Measure | Result |
|---|---|
| Initial load, one transaction, then ANALYZE (%d MiB page cache) | **%s** (budget %s) |
| ANALYZE alone | %s |
| Graph load, median of three (runs %s) | **%s** (budget %s) |
| Later scan, ~%d%% churn, one atomic transaction | **%s** (B-4 budget %s, reported not enforced) |
| Later scan phases | %s |
| Encryptions the later scan reserved and drew | %d |
| Labels decrypted per graph load | %d |
| File size | %.0f MB |
| Query plans | %d hot queries pinned, %d foreign-key lookups indexed, %d problems |

> The fixture is a **uniform-random** graph: every node has about the same
> number of edges. Real estates are hub-heavy (one admin role reachable from
> thousands), which changes cache and memory behaviour. These timings are
> indicative, not a guarantee for hub-heavy graphs; the pinned query plans,
> though, hold regardless of shape.
`, n, g.edgeCount(), bulkLoadCacheKiB/1024, ingest.Round(time.Millisecond), *scaleIngest, analyze.Round(time.Millisecond),
		fmt.Sprint(loads), median.Round(time.Millisecond), *scaleBudget,
		100/scaleChurn, laterIngest.Round(time.Millisecond), *scaleLater, strings.Join(phases, ", "), laterSeals, labelled,
		float64(size)/1e6, len(pinnedPlans), fks, len(problems))
	t.Log("\n" + report)
	if *scaleSummary != "" {
		f, err := os.OpenFile(*scaleSummary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, werr := f.WriteString(report)
		if err := f.Close(); err != nil || werr != nil {
			t.Fatal(err, werr)
		}
	}

	if want := n * scaleEdgesPerEntity; g.edgeCount() != want {
		t.Errorf("graph has %d edges, want %d", g.edgeCount(), want)
	}
	if want := (n + scaleLabelEvery - 1) / scaleLabelEvery; labelled != want {
		t.Errorf("%d labels decrypted, want %d", labelled, want)
	}
	for _, p := range problems {
		t.Errorf("query plan at scale: %s", p)
	}
	if median > *scaleBudget {
		t.Errorf("the median graph load took %s, over the %s budget", median, *scaleBudget)
	}
	if ingest > *scaleIngest {
		t.Errorf("the initial load took %s, over the %s budget", ingest, *scaleIngest)
	}
	// The later-scan budget is B-4, still provisional: report it, do not fail on
	// it, until the maintainer confirms a number from this measurement.
	if laterIngest > *scaleLater {
		t.Logf("later-scan ingest took %s, over the provisional %s B-4 budget (reported, not enforced)", laterIngest, *scaleLater)
	}
}

// syntheticLaterScan turns a first scan into a later scan that changes about
// 100/scaleChurn percent of the estate: one entity in scaleChurn is renamed and
// one edge in scaleChurn has its confidence changed. Everything else is
// observed unchanged, so the diff runs over the whole estate while the apply
// touches only churn, which is the B-4 case.
func syntheticLaterScan(base firstScan, n int) laterScan {
	ents := make([]entityRecord, n)
	copy(ents, base.entities)
	for i := 0; i < n; i += scaleChurn {
		ents[i].name += "-v2"
	}
	var edges []edgeRecord
	j := 0
	for e := range base.edges {
		if j%scaleChurn == 0 {
			e.confidence = 81
		}
		edges = append(edges, e)
		j++
	}
	return laterScan{
		toolVersion: "synthetic-later", manifest: []byte("synthetic later"),
		started: base.started, completed: base.completed,
		evidence: base.evidence, entities: ents, edges: edges,
	}
}
