package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

var diffSpec = commandSpec{
	name:     "diff",
	synopsis: "ittcsecscan diff --tenant <id> [--scan <id>] [--json] [runtime flags]",
	description: "Show what changed between scans for a tenant: the entities and edges the\n" +
		"later-scan change-detection engine (ADR-0011 section 1) recorded as appeared,\n" +
		"changed, or disappeared. It reads the stored scan history and does not collect.\n" +
		"With no --scan, the latest finished scan is shown. A baseline first scan has no\n" +
		"prior state, so its diff is empty by design.",
}

func runDiff(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(diffSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	tenant := fs.String("tenant", "", "the `id` of the tenant to diff")
	scanID := fs.Int64("scan", 0, "the scan `id` to show (default: the latest finished scan)")
	asJSON := fs.Bool("json", false, "print JSON")
	if done, err := parse(fs, inv, diffSpec, args); done {
		return err
	}
	if *tenant == "" {
		return exitcode.Errorf(exitcode.Usage, "diff: --tenant is required")
	}
	id, err := store.ParseTenantID(*tenant)
	if err != nil {
		return exitcode.Errorf(exitcode.Usage, "diff: invalid tenant id: %v", err)
	}
	st, err := openStore(inv, rf)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	tn, release, err := st.Acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()

	d, err := tn.Diff(ctx, *scanID)
	if err != nil {
		return err
	}
	return writeDiff(inv.out, *asJSON, id, d)
}

func writeDiff(w io.Writer, asJSON bool, id store.TenantID, d store.Diff) error {
	if asJSON {
		return writeJSON(w, diffJSON(id, d))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Changes for tenant %s", id)
	if d.ScanID == 0 {
		b.WriteString(": no scans recorded\n")
		return writeText(w, b.String())
	}
	fmt.Fprintf(&b, " (scan %d)\n", d.ScanID)
	if len(d.Entities) == 0 && len(d.Edges) == 0 {
		b.WriteString("no changes recorded (a baseline first scan has no prior state, or nothing changed)\n")
		return writeText(w, b.String())
	}
	for _, e := range d.Entities {
		line := fmt.Sprintf("  %s: %s %s", e.Change, e.Type, e.NativeID)
		if e.Name != "" {
			line += " (" + e.Name + ")"
		}
		b.WriteString(line + "\n")
	}
	for _, e := range d.Edges {
		fmt.Fprintf(&b, "  %s: edge %s -%s-> %s\n", e.Change, e.Source, e.Kind, e.Target)
	}
	return writeText(w, b.String())
}

type diffOut struct {
	Tenant   string          `json:"tenant"`
	ScanID   int64           `json:"scan_id"`
	Entities []diffEntityOut `json:"entities"`
	Edges    []diffEdgeOut   `json:"edges"`
}

type diffEntityOut struct {
	Change string `json:"change"`
	Type   string `json:"type"`
	Entity string `json:"entity"`
	Name   string `json:"name,omitempty"`
}

type diffEdgeOut struct {
	Change string `json:"change"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target"`
}

func diffJSON(id store.TenantID, d store.Diff) diffOut {
	out := diffOut{
		Tenant: id.String(), ScanID: d.ScanID,
		Entities: make([]diffEntityOut, 0, len(d.Entities)), Edges: make([]diffEdgeOut, 0, len(d.Edges)),
	}
	for _, e := range d.Entities {
		out.Entities = append(out.Entities, diffEntityOut{
			Change: e.Change, Type: string(e.Type), Entity: redact.String(e.NativeID), Name: redact.String(e.Name),
		})
	}
	for _, e := range d.Edges {
		out.Edges = append(out.Edges, diffEdgeOut{
			Change: e.Change, Kind: string(e.Kind), Source: redact.String(e.Source), Target: redact.String(e.Target),
		})
	}
	return out
}
