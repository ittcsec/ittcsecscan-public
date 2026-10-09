package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/schema"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// canonicalTenantID is the all-zero tenant id: 26 canonical base32 characters,
// so it parses without needing to generate one.
const canonicalTenantID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestScanRequiresTenantOrCreate(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "scan")
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
	if !strings.Contains(r.err, "--tenant or --create") {
		t.Errorf("stderr = %q, want the one-required message", r.err)
	}
}

func TestScanRejectsBothTenantAndCreate(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "scan", "--create", "--tenant", canonicalTenantID)
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
	if !strings.Contains(r.err, "not both") {
		t.Errorf("stderr = %q, want the not-both message", r.err)
	}
}

func TestScanRejectsInvalidTenantID(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "scan", "--tenant", "not-a-valid-id")
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
}

func TestScanRejectsUnknownProvider(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "scan", "--create", "--provider", "nimbus")
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
	if !strings.Contains(r.err, "scannable providers") {
		t.Errorf("stderr = %q, want the scannable-providers message", r.err)
	}
}

// TestScanFailsClosedWithNoMasterKey is the guarantee the maintainer required proven
// here specifically: a scan with no reachable master key refuses cleanly, never
// proceeds, and never creates a tenant, even though a valid passphrase is on
// hand. The refusal is the store's fail-closed key resolution, exercised through
// the first user-facing command that touches the master key.
func TestScanFailsClosedWithNoMasterKey(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	keyFile := filepath.Join(root, "nonexistent.key") // never created

	// A valid passphrase is available, so a refusal cannot be blamed on an
	// unreadable passphrase: the missing key alone must fail the scan closed.
	read := queuedSecrets("correct horse battery staple")
	r := invokeSecrets(hermetic(t, nil), read,
		"scan", "--create", "--data-dir", dataDir, "--master-key-file", keyFile)

	if r.code == exitcode.OK {
		t.Fatalf("scan with no master key exited OK; it must refuse. stderr=%q", r.err)
	}
	if r.code == exitcode.AuthFailed {
		t.Fatalf("scan reported provider auth-failed (%s); it must refuse before scanning, at the key. stderr=%q", r.code, r.err)
	}

	// No key file was created: fail-closed never fabricates one.
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("master-key file exists after a failed scan (err=%v); a scan must never create a key", err)
	}
	// No tenant was created: the tenants root is empty (or absent).
	tenantsRoot := filepath.Join(dataDir, "tenants")
	if entries, err := os.ReadDir(tenantsRoot); err == nil {
		if len(entries) != 0 {
			t.Errorf("a tenant was created despite the key refusal: %d entries under %s", len(entries), tenantsRoot)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading tenants root: %v", err)
	}
}

// TestScanJSONOutputMatchesSchema proves the three outcome shapes (complete,
// incomplete, auth-failed) each satisfy the published scan schema.
func TestScanJSONOutputMatchesSchema(t *testing.T) {
	id, err := store.ParseTenantID(canonicalTenantID)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]scan.Report{
		"complete": {
			Authenticated: 1, ScanID: 5,
			Providers: []scan.ProviderResult{{
				Provider: model.AWS, Account: "acct-1",
				Completeness: []collect.Completeness{{Service: "iam", Region: collect.Global, Scope: collect.Scope{Account: "acct-1"}, Status: collect.Complete, Collected: 3}},
			}},
		},
		"incomplete": {
			Authenticated: 1, ScanID: 6, DroppedEdges: 2,
			Providers: []scan.ProviderResult{
				{Provider: model.Azure, AuthError: errors.New("azure: no credentials")},
				{Provider: model.AWS, Account: "acct-1",
					Completeness: []collect.Completeness{{Service: "iam", Region: collect.Global, Scope: collect.Scope{Account: "acct-1"}, Status: collect.Denied, Collected: 0, Reason: "access denied"}}},
			},
		},
		"auth-failed": {
			Authenticated: 0,
			Providers:     []scan.ProviderResult{{Provider: model.AWS, AuthError: errors.New("aws: expired token")}},
		},
	}
	for name, rep := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeScanReport(&buf, true, id, rep); err != nil {
				t.Fatalf("writeScanReport: %v", err)
			}
			if err := schema.ValidateJSON(schema.Scan, buf.Bytes()); err != nil {
				t.Fatalf("output violates scan schema: %v\n%s", err, buf.String())
			}
			if got := scanOutcome(rep); !strings.Contains(buf.String(), got) {
				t.Errorf("JSON does not carry outcome %q: %s", got, buf.String())
			}
		})
	}
}

// TestScanBudget proves the --budget flag maps to the scan's shared cap: 0 or
// less is unlimited (nil), a positive value is a budget of that many calls.
func TestScanBudget(t *testing.T) {
	if scanBudget(0) != nil {
		t.Error("budget 0 must be unlimited (nil)")
	}
	if scanBudget(-3) != nil {
		t.Error("a negative budget must be unlimited (nil)")
	}
	b := scanBudget(4)
	if b == nil || b.Remaining() != 4 {
		t.Errorf("budget 4 = %v, want a cap of 4", b)
	}
}

// TestScanTextOutputReportsOutcome checks the human form names the outcome and
// the tenant, so the terminal view agrees with the exit code.
func TestScanTextOutputReportsOutcome(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	rep := scan.Report{Authenticated: 0, Providers: []scan.ProviderResult{{Provider: model.AWS, AuthError: errors.New("aws: expired token")}}}
	var buf bytes.Buffer
	if err := writeScanReport(&buf, false, id, rep); err != nil {
		t.Fatalf("writeScanReport: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "auth-failed") || !strings.Contains(out, canonicalTenantID) {
		t.Errorf("text output missing outcome or tenant: %q", out)
	}
}
