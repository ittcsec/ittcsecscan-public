package report

import (
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
)

// sanitize makes a string safe for customer-facing report output (ADR-0028 section 5):
// it redacts secret patterns (internal/redact), removes em and en dashes, which the
// product-output rule forbids in report content, and neutralizes control
// and bidirectional-formatting characters (internal/termsafe) so an attacker-influenced
// resource name cannot carry an ANSI escape, a "Trojan Source" bidi override, or invalid
// UTF-8 into any rendered format (T-02, T-03). Dashes are replaced with a comma and
// space so text stays readable; layout characters (newline, tab) are kept. It is applied
// to every customer-facing string in every format, so no renderer can forget it.
// Per-format structural escaping (HTML, XML, PDF) is applied additionally by each
// renderer on top of this.
func sanitize(s string) string {
	return termsafe.String(replaceDashes(redact.String(s)))
}

// sanitizeAll sanitizes every string in a slice.
func sanitizeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = sanitize(s)
	}
	return out
}

const (
	emDash = "—"
	enDash = "–"
)

func replaceDashes(s string) string {
	s = strings.ReplaceAll(s, emDash, ", ")
	s = strings.ReplaceAll(s, enDash, ", ")
	return s
}

// containsForbiddenDash reports whether a rendered string still carries an em or en
// dash. The honesty gate test asserts no rendered customer-facing output contains one.
func containsForbiddenDash(s string) bool {
	return strings.Contains(s, emDash) || strings.Contains(s, enDash)
}

// RemediationStatus is the report's tenant-level note about remediation. Per-finding
// guidance now follows each finding (real steps for a verified remediation, or an
// honest named gap otherwise); this states that and that no placeholder is shown.
// Remediation content (portal steps, CLI fix, IaC fix, side effects, verification,
// rollback) has no producer yet, so a report states that plainly as a named
// gap and never renders guidance-shaped placeholder text (ADR-0028 section 4, RP-1).
const RemediationStatus = "Remediation guidance is generated per finding below. A finding with a verified remediation shows the portal, CLI, and IaC steps, prerequisites, required privilege, side effects, verification, and rollback. A finding whose type has no verified remediation yet names the tracked gap instead of showing placeholder guidance."
