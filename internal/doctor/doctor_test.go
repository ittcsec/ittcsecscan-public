package doctor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/logging"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

func fixed(s Status) func(context.Context) Outcome {
	return func(context.Context) Outcome { return Outcome{Status: s, Detail: string(s) + " detail"} }
}

func run(t *testing.T, strict bool, checks ...Check) Report {
	t.Helper()
	rep, err := Run(context.Background(), checks, strict, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateValue(schema.Doctor, rep); err != nil {
		t.Fatalf("report violates doctor schema: %v", err)
	}
	return rep
}

func TestAggregation(t *testing.T) {
	checks := []Check{
		{ID: "a.pass", Title: "A", Run: fixed(Pass)},
		{ID: "b.warn", Title: "B", Run: fixed(Warn)},
		{ID: "c.unknown", Title: "C", Run: fixed(Unknown)},
	}
	rep := run(t, false, checks...)
	if rep.Overall != Warn || rep.Summary != (Summary{Pass: 1, Warn: 1, Unknown: 1}) || !rep.Passed() {
		t.Errorf("non-strict: %+v passed=%v", rep, rep.Passed())
	}
	for i, id := range []string{"a.pass", "b.warn", "c.unknown"} {
		if rep.Checks[i].ID != id {
			t.Errorf("order not preserved: %v", rep.Checks)
		}
	}
	if strict := run(t, true, checks...); strict.Passed() {
		t.Error("strict mode passed with warnings and unknowns")
	}
	failing := run(t, false, append(checks, Check{ID: "d.fail", Title: "D", Run: fixed(Fail)})...)
	if failing.Overall != Fail || failing.Passed() {
		t.Errorf("failure not reflected: %+v", failing)
	}
}

func TestUnknownIsNeverPass(t *testing.T) {
	rep := run(t, false, Check{ID: "a.unknown", Title: "A", Run: fixed(Unknown)})
	if rep.Overall == Pass {
		t.Fatal("an unknown check produced an overall pass")
	}
	if all := run(t, false, Check{ID: "a.pass", Title: "A", Run: fixed(Pass)}); all.Overall != Pass {
		t.Errorf("all-pass overall = %s", all.Overall)
	}
}

func TestCancellationStopsRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checks := []Check{
		{ID: "a.cancel", Title: "A", Run: func(context.Context) Outcome { cancel(); return Outcome{Status: Pass} }},
		{ID: "b.never", Title: "B", Run: func(context.Context) Outcome { t.Error("check ran after cancellation"); return Outcome{Status: Pass} }},
	}
	if _, err := Run(ctx, checks, false, logging.Discard()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestMisbehavingChecksFail(t *testing.T) {
	rep := run(t, false,
		Check{ID: "a.panic", Title: "A", Run: func(context.Context) Outcome { panic("boom") }},
		Check{ID: "b.invalid", Title: "B", Run: func(context.Context) Outcome { return Outcome{Status: "great"} }},
	)
	for _, r := range rep.Checks {
		if r.Status != Fail {
			t.Errorf("%s status = %s, want fail", r.ID, r.Status)
		}
	}
}

func TestDetailsAreRedacted(t *testing.T) {
	rep := run(t, false, Check{ID: "a.leak", Title: "A", Run: func(context.Context) Outcome {
		return Outcome{Status: Warn, Detail: "password=leak-canary", Remediation: "token=fix-canary"}
	}})
	if strings.Contains(rep.Checks[0].Detail+rep.Checks[0].Remediation, "canary") {
		t.Errorf("secret reached the report: %+v", rep.Checks[0])
	}
}

func TestWriteTextSanitises(t *testing.T) {
	rep := run(t, true, Check{ID: "a.evil", Title: "A", Run: func(context.Context) Outcome {
		return Outcome{Status: Warn, Detail: "name \x1b[2J\nPASS forged", Remediation: "\x07bell"}
	}})
	var buf bytes.Buffer
	if err := WriteText(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsAny(out, "\x1b\x07") || strings.Contains(out, "\nPASS forged") {
		t.Errorf("control characters or forged lines reached the terminal: %q", out)
	}
	if !strings.Contains(out, "Overall: WARN") || !strings.Contains(out, "strict") || !strings.Contains(out, "fix:") {
		t.Errorf("missing summary: %q", out)
	}
}
