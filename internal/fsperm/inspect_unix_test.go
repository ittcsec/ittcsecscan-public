//go:build unix

package fsperm

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectUnixModes(t *testing.T) {
	tests := []struct {
		mode      fs.FileMode
		dir       bool
		read      bool
		write     bool
		describes string
	}{
		{mode: 0o700, dir: true},
		{mode: 0o600},
		{mode: 0o711, dir: true}, // traverse-only bits are not read access
		{mode: 0o750, dir: true, read: true},
		{mode: 0o770, dir: true, read: true, write: true},
		{mode: 0o755, dir: true, read: true},
		{mode: 0o777, dir: true, read: true, write: true},
		{mode: 0o644, read: true},
		// Group bits clear, so Describe names only "others".
		{mode: 0o707, dir: true, read: true, write: true, describes: "others (read, write)"},
		{mode: 0o604, read: true, describes: "others (read)"},
		{mode: 0o602, write: true, describes: "others (write)"},
	}
	for _, tt := range tests {
		p := filepath.Join(t.TempDir(), "entry")
		if tt.dir {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, tt.mode); err != nil { // chmod is not subject to umask
			t.Fatal(err)
		}
		rep, err := Inspect(p)
		if err != nil {
			t.Fatal(err)
		}
		if rep.OthersCanRead() != tt.read || rep.OthersCanWrite() != tt.write {
			t.Errorf("mode %04o: read=%v write=%v, want read=%v write=%v (%s)",
				tt.mode, rep.OthersCanRead(), rep.OthersCanWrite(), tt.read, tt.write, rep.Describe())
		}
		if tt.describes != "" && rep.Describe() != tt.describes {
			t.Errorf("mode %04o: Describe() = %q, want %q", tt.mode, rep.Describe(), tt.describes)
		}
	}
}

func TestInspectMissing(t *testing.T) {
	if _, err := Inspect(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}
