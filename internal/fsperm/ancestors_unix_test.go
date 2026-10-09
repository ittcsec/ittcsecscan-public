//go:build unix

package fsperm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// reportedDirs returns the reported directories, in both written and
// symlink-resolved form, so assertions work where the temp dir is behind a
// symlink (macOS /var -> /private/var).
func reportedDirs(t *testing.T, reps []Report) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, r := range reps {
		out[r.Path] = true
		if real, err := filepath.EvalSymlinks(r.Path); err == nil {
			out[real] = true
		}
	}
	return out
}

func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInspectAncestorsUnix(t *testing.T) {
	root := t.TempDir()
	open := filepath.Join(root, "open")
	inner := filepath.Join(open, "inner")
	for _, d := range []string{open, inner} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(inner, "config.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: the test needs a folder others can write
		t.Fatal(err)
	}

	reps, err := InspectAncestors(target)
	if err != nil {
		t.Fatal(err)
	}
	dirs := reportedDirs(t, reps)
	if !dirs[realPath(t, open)] {
		t.Errorf("world-writable ancestor %s not reported: %v", open, dirs)
	}
	if dirs[realPath(t, inner)] {
		t.Errorf("private parent %s reported", inner)
	}

	// A path that does not exist yet is judged by the folders that do.
	reps, err = InspectAncestors(filepath.Join(inner, "not", "yet", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if !reportedDirs(t, reps)[realPath(t, open)] {
		t.Error("ancestor of a missing path not reported")
	}

	// With the sticky bit, others can add entries but not replace ours.
	if err := os.Chmod(open, 0o777|os.ModeSticky); err != nil { // sticky and world-writable, like /tmp
		t.Fatal(err)
	}
	reps, err = InspectAncestors(target)
	if err != nil {
		t.Fatal(err)
	}
	if reportedDirs(t, reps)[realPath(t, open)] {
		t.Errorf("sticky ancestor %s reported as replaceable", open)
	}
}

func TestIncompleteOnlyWhereACLsAreNotRead(t *testing.T) {
	rep, err := Inspect(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "linux":
		if rep.Incomplete != "" {
			t.Errorf("Linux ACLs are inspected, but Incomplete = %q", rep.Incomplete)
		}
	default:
		if rep.Incomplete == "" {
			t.Errorf("%s: ACLs are not inspected, so the report must say it is incomplete", runtime.GOOS)
		}
	}
}
