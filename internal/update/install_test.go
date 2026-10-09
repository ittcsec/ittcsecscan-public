package update

import (
	"bytes"
	"testing"
)

func TestInstallAtomicAndRollback(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v1 := []byte("component v1")
	v2 := []byte("component v2")

	if err := s.Install("pack:core-p0", "1.0.0", v1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Current("pack:core-p0"); !bytes.Equal(got, v1) {
		t.Fatal("current is not v1 after first install")
	}
	installed, _ := s.Installed()
	if installed["pack:core-p0"].Version != "1.0.0" || installed["pack:core-p0"].HasPrevious {
		t.Errorf("unexpected state after first install: %+v", installed["pack:core-p0"])
	}

	if err := s.Install("pack:core-p0", "2.0.0", v2); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Current("pack:core-p0"); !bytes.Equal(got, v2) {
		t.Fatal("current is not v2 after upgrade")
	}
	installed, _ = s.Installed()
	if installed["pack:core-p0"].Version != "2.0.0" || installed["pack:core-p0"].PreviousVersion != "1.0.0" {
		t.Errorf("unexpected state after upgrade: %+v", installed["pack:core-p0"])
	}

	// Rollback restores the last-known-good (v1).
	info, err := s.Rollback("pack:core-p0")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "1.0.0" {
		t.Errorf("rollback reported version %q, want 1.0.0", info.Version)
	}
	if got, _ := s.Current("pack:core-p0"); !bytes.Equal(got, v1) {
		t.Fatal("current is not v1 after rollback")
	}
}

func TestRollbackWithoutPreviousFails(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Install("schemas", "1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback("schemas"); err == nil {
		t.Error("rollback with no previous version must fail, not silently no-op")
	}
}

// safeName keeps an artifact name from escaping the store directory: no path
// separators survive.
func TestSafeNameConfinesPath(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", "a/b", "pack:core-p0", "..\\..\\x"} {
		if got := safeName(in); bytes.ContainsAny([]byte(got), "/\\:") {
			t.Errorf("safeName(%q)=%q still contains a path separator", in, got)
		}
	}
}
