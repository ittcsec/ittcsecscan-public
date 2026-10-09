// Package egress is the zero-egress audit sink (item 6): it writes one visible,
// human-readable line per outbound connection attempt a scan makes, so a user can
// independently confirm that nothing left their machine except calls to the cloud
// provider being scanned.
//
// It is observational only. It never blocks, delays, or alters a connection; it records
// what the shared HTTP clients dialed. It sees only the destination host:port (the dial
// layer has no credential, header, or body), and it redacts the line it writes as a final
// defence before anything reaches the file.
package egress

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// Auditor appends one line per dial attempt to a file. It is safe for concurrent use:
// the shared HTTP clients dial from many goroutines during a scan.
type Auditor struct {
	mu    sync.Mutex
	w     io.WriteCloser
	count int
}

// NewAuditor opens path for the audit log (created or truncated, owner-only 0600, like
// the report files) and writes a header describing what the file is. The caller installs
// Observe as the dial observer and calls Close when the scan ends.
func NewAuditor(path, tenant, toolVersion string) (*Auditor, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: path is the operator-chosen audit file from the --offline-audit flag
	if err != nil {
		return nil, err
	}
	a := &Auditor{w: f}
	a.writeLine("# ittcsecscan egress audit")
	a.writeLine("# tenant " + redact.String(tenant) + "   tool " + redact.String(toolVersion))
	a.writeLine("# started " + time.Now().UTC().Format(time.RFC3339))
	a.writeLine("# one line per outbound connection attempt: <time> <network> <address> <outcome>")
	a.writeLine("# observational only; confirm every address is the cloud provider being scanned")
	return a, nil
}

// Observe records one dial attempt. It matches the signature collect.SetDialObserver
// wants, so the scan wires it straight in.
func (a *Auditor) Observe(e collect.DialEvent) {
	outcome := "dialed"
	if e.Err != "" {
		outcome = "error: " + e.Err
	}
	at := e.At
	if at.IsZero() {
		at = time.Now()
	}
	line := at.UTC().Format(time.RFC3339) + " " + nonEmpty(e.Network, "tcp") + " " + e.Address + " " + outcome
	a.mu.Lock()
	a.count++
	a.mu.Unlock()
	a.writeLine(redact.String(line))
}

// writeLine writes one sanitized line under the lock. A write error is dropped: the audit
// is best-effort output, and failing a scan because its audit file could not be appended
// to would be a worse outcome than a short log. (NewAuditor already proved the file opens.)
func (a *Auditor) writeLine(s string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.w == nil {
		return
	}
	_, _ = io.WriteString(a.w, s+"\n")
}

// Count reports how many dial attempts were recorded.
func (a *Auditor) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count
}

// Close writes a trailing summary and closes the file, returning the number of attempts
// recorded.
func (a *Auditor) Close() (int, error) {
	n := a.Count()
	a.writeLine("# ended " + time.Now().UTC().Format(time.RFC3339) + "   " + fmt.Sprintf("%d connection attempts recorded", n))
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.w == nil {
		return n, nil
	}
	err := a.w.Close()
	a.w = nil
	return n, err
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
