//go:build windows

package fsperm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reported(reps []Report, dir string) bool {
	for _, r := range reps {
		if strings.EqualFold(filepath.Clean(r.Path), filepath.Clean(dir)) {
			return true
		}
	}
	return false
}

func TestInspectAncestorsWindows(t *testing.T) {
	me := currentUserSID(t)
	root := t.TempDir()
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	// Authenticated Users may delete entries inside "open" (FILE_DELETE_CHILD)
	// but have no inheritable access, so everything created inside stays
	// private to the current user.
	setDACL(t, open, "D:P(A;OICI;FA;;;"+me+")(A;;DT;;;AU)")
	inner := filepath.Join(open, "inner")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(inner, "config.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	reps, err := InspectAncestors(target)
	if err != nil {
		t.Fatal(err)
	}
	if !reported(reps, open) {
		t.Errorf("ancestor where Authenticated Users can delete entries not reported: %+v", reps)
	}
	if reported(reps, inner) {
		t.Errorf("private parent reported: %+v", reps)
	}
	if rep, err := Inspect(target); err != nil || rep.OthersCanWrite() {
		t.Errorf("target should be private: %+v %v", rep, err)
	}

	// Read-only access for others does not allow replacing anything.
	setDACL(t, open, "D:P(A;OICI;FA;;;"+me+")(A;;FR;;;AU)")
	if reps, err = InspectAncestors(target); err != nil || reported(reps, open) {
		t.Errorf("read-only ancestor reported as replaceable: %+v %v", reps, err)
	}
}

func TestInspectWindowsInheritedAccess(t *testing.T) {
	me := currentUserSID(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Like a folder under a drive root: private itself, but new children
	// inherit modify access for Authenticated Users.
	setDACL(t, dir, "D:P(A;OICI;FA;;;"+me+")(A;OICIIO;SDGXGWGR;;;AU)")
	rep, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OthersCanRead() || rep.OthersCanWrite() {
		t.Errorf("inherit-only entry counted as direct access: %s", rep.Describe())
	}
	if rep.DescribeInherited() != "Authenticated Users (read, write)" {
		t.Errorf("DescribeInherited() = %q", rep.DescribeInherited())
	}
	if rep.Incomplete != "" {
		t.Errorf("Windows DACLs are fully evaluated, but Incomplete = %q", rep.Incomplete)
	}
}
