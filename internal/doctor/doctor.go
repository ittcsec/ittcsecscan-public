// Package doctor runs read-only health checks on the local environment.
//
// Doctor never modifies anything: it does not create directories, write files,
// or contact the network. A check that cannot be evaluated reports Unknown; it
// is never counted as a pass (see schemas/cli/v1/doctor.schema.json).
package doctor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
)

// SchemaVersion is the version of the JSON report (schemas/cli/v1/doctor.schema.json).
const SchemaVersion = 1

// Status is the outcome of one check.
type Status string

// Check statuses.
const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

// Outcome is what a check function returns.
type Outcome struct {
	Status      Status
	Detail      string
	Remediation string
}

// Check is one named health check. IDs are stable and never renamed once
// released.
type Check struct {
	ID    string
	Title string
	Run   func(ctx context.Context) Outcome
}

// Result is one check's entry in the report.
type Result struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      Status `json:"status"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

// Summary counts results by status.
type Summary struct {
	Pass    int `json:"pass"`
	Warn    int `json:"warn"`
	Fail    int `json:"fail"`
	Unknown int `json:"unknown"`
}

// Report is the full doctor result.
type Report struct {
	SchemaVersion int      `json:"schema_version"`
	Overall       Status   `json:"overall"`
	Strict        bool     `json:"strict"`
	Summary       Summary  `json:"summary"`
	Checks        []Result `json:"checks"`
}

// Passed reports whether the command should exit successfully. Any failure
// fails; in strict mode warnings and unknowns fail too.
func (r Report) Passed() bool {
	if r.Summary.Fail > 0 {
		return false
	}
	if r.Strict && (r.Summary.Warn > 0 || r.Summary.Unknown > 0) {
		return false
	}
	return true
}

// Run executes checks in order. It stops and returns the context error if the
// context is cancelled; a partial report is never returned as complete.
func Run(ctx context.Context, checks []Check, strict bool, log *slog.Logger) (Report, error) {
	rep := Report{
		SchemaVersion: SchemaVersion,
		Strict:        strict,
		Checks:        make([]Result, 0, len(checks)),
	}
	for _, c := range checks {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		out := runOne(ctx, c)
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		log.Debug("doctor check finished", "check", c.ID, "status", string(out.Status))
		rep.Checks = append(rep.Checks, Result{
			ID:          c.ID,
			Title:       c.Title,
			Status:      out.Status,
			Detail:      redact.String(out.Detail),
			Remediation: redact.String(out.Remediation),
		})
		switch out.Status {
		case Pass:
			rep.Summary.Pass++
		case Warn:
			rep.Summary.Warn++
		case Fail:
			rep.Summary.Fail++
		case Unknown:
			rep.Summary.Unknown++
		}
	}
	rep.Overall = overall(rep.Summary)
	return rep, nil
}

func runOne(ctx context.Context, c Check) (out Outcome) {
	defer func() {
		if recover() != nil {
			out = Outcome{Status: Fail, Detail: "internal error: the check panicked", Remediation: "report this as a bug"}
		}
	}()
	out = c.Run(ctx)
	switch out.Status {
	case Pass, Warn, Fail, Unknown:
		return out
	}
	return Outcome{Status: Fail, Detail: fmt.Sprintf("internal error: the check returned invalid status %q", out.Status)}
}

// overall never yields Pass while anything is unknown.
func overall(s Summary) Status {
	switch {
	case s.Fail > 0:
		return Fail
	case s.Warn > 0 || s.Unknown > 0:
		return Warn
	}
	return Pass
}

// WriteText renders the report for a terminal. Every free-text field is
// escaped so check details cannot inject terminal control sequences.
func WriteText(w io.Writer, r Report) error {
	var b strings.Builder
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "%-7s %-20s %s\n", strings.ToUpper(string(c.Status)), c.ID, termsafe.Line(c.Detail))
		if c.Remediation != "" && c.Status != Pass {
			fmt.Fprintf(&b, "%-7s %-20s fix: %s\n", "", "", termsafe.Line(c.Remediation))
		}
	}
	mode := ""
	if r.Strict {
		mode = ", strict"
	}
	fmt.Fprintf(&b, "\nOverall: %s (%d passed, %d warnings, %d unknown, %d failed%s)\n",
		strings.ToUpper(string(r.Overall)), r.Summary.Pass, r.Summary.Warn, r.Summary.Unknown, r.Summary.Fail, mode)
	_, err := io.WriteString(w, b.String())
	return err
}
