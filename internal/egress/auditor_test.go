package egress

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads a file it just wrote
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestAuditorWritesHeaderAndLines proves the auditor writes a header, one line per dial
// attempt with the destination and outcome, and a closing summary with the count.
func TestAuditorWritesHeaderAndLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress.log")
	a, err := NewAuditor(path, "tenant-1", "v-test")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a.Observe(collect.DialEvent{Network: "tcp", Address: "sts.amazonaws.com:443", At: at})
	a.Observe(collect.DialEvent{Network: "tcp", Address: "bad.example:443", At: at, Err: "connection refused"})
	if a.Count() != 2 {
		t.Errorf("count = %d, want 2", a.Count())
	}
	n, err := a.Close()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("close count = %d, want 2", n)
	}
	out := readFile(t, path)
	for _, want := range []string{
		"# ittcsecscan egress audit",
		"tenant tenant-1",
		"2026-01-02T03:04:05Z tcp sts.amazonaws.com:443 dialed",
		"2026-01-02T03:04:05Z tcp bad.example:443 error: connection refused",
		"2 connection attempts recorded",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("audit file missing %q\n---\n%s", want, out)
		}
	}
}

// TestAuditorFileIsOwnerOnly proves the audit file is created 0600 (it can carry the set
// of endpoints a scan contacted), matching the report files. Mode bits are only meaningful
// on non-Windows filesystems.
func TestAuditorFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "egress.log")
	a, err := NewAuditor(path, "t", "v")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = a.Close() }()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestAuditorConcurrent proves Observe is safe under concurrent calls (the shared clients
// dial from many goroutines) and records every one.
func TestAuditorConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress.log")
	a, err := NewAuditor(path, "t", "v")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Observe(collect.DialEvent{Network: "tcp", Address: "host:443", At: time.Now()})
		}()
	}
	wg.Wait()
	if a.Count() != 50 {
		t.Errorf("count = %d, want 50", a.Count())
	}
	if _, err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(readFile(t, path), "host:443"); got != 50 {
		t.Errorf("recorded %d lines, want 50", got)
	}
}

// TestNewAuditorRejectsBadPath proves a path that cannot be created is a loud error, so a
// user who asked for an audit is never silently given none.
func TestNewAuditorRejectsBadPath(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "no-such-dir", "egress.log")
	if _, err := NewAuditor(bad, "t", "v"); err == nil {
		t.Error("expected an error opening an audit file in a nonexistent directory")
	}
}
