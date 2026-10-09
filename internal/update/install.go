package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store is the on-disk location where verified component artifacts are installed.
// Each component keeps its current file and one retained last-known-good previous
// file, plus a small state file recording the installed version. Installation is
// atomic (write to a temp file, then rename into place), so a crash mid-install never
// leaves a half-written current file, and rollback restores the previous version.
type Store struct {
	dir string
}

// NewStore opens (creating if needed) an install store rooted at dir.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("update: install store directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("update: create install store: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Installed reports the currently installed version of each component.
func (s *Store) Installed() (map[string]InstalledInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := map[string]InstalledInfo{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := s.readState(e.Name())
		if err != nil || info.Component == "" {
			continue
		}
		out[info.Component] = info
	}
	return out, nil
}

// InstalledInfo is the recorded state of one installed component.
type InstalledInfo struct {
	Component       string `json:"component"`
	Version         string `json:"version"`
	PreviousVersion string `json:"previous_version,omitempty"`
	HasPrevious     bool   `json:"has_previous"`
}

// Install atomically installs data as the current artifact for a component, rotating
// the existing current file to previous (the retained last-known-good). The version
// is recorded so status and rollback can report it.
func (s *Store) Install(component, version string, data []byte) error {
	cdir := filepath.Join(s.dir, safeName(component))
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		return err
	}
	cur := filepath.Join(cdir, "current")
	prev := filepath.Join(cdir, "previous")

	tmp := filepath.Join(cdir, "current.tmp")
	if err := writeFileSync(tmp, data); err != nil {
		return err
	}

	state, _ := s.readState(safeName(component))
	if fileExists(cur) {
		if err := os.Rename(cur, prev); err != nil {
			return err
		}
		state.PreviousVersion = state.Version
		state.HasPrevious = true
	}
	if err := os.Rename(tmp, cur); err != nil {
		return err
	}
	state.Component = component
	state.Version = version
	return s.writeState(safeName(component), state)
}

// Rollback restores a component's retained previous version as current. It fails if
// there is no previous version to restore, so a rollback never silently no-ops.
func (s *Store) Rollback(component string) (InstalledInfo, error) {
	cdir := filepath.Join(s.dir, safeName(component))
	cur := filepath.Join(cdir, "current")
	prev := filepath.Join(cdir, "previous")
	state, err := s.readState(safeName(component))
	if err != nil {
		return InstalledInfo{}, err
	}
	if !fileExists(prev) || !state.HasPrevious {
		return InstalledInfo{}, fmt.Errorf("update: no previous version to roll back to for %q", component)
	}
	// Swap current and previous through a temp name so both survive a crash.
	tmp := filepath.Join(cdir, "swap.tmp")
	if err := os.Rename(cur, tmp); err != nil {
		return InstalledInfo{}, err
	}
	if err := os.Rename(prev, cur); err != nil {
		return InstalledInfo{}, err
	}
	if err := os.Rename(tmp, prev); err != nil {
		return InstalledInfo{}, err
	}
	state.Version, state.PreviousVersion = state.PreviousVersion, state.Version
	if err := s.writeState(safeName(component), state); err != nil {
		return InstalledInfo{}, err
	}
	return state, nil
}

// Current returns the installed artifact bytes for a component.
func (s *Store) Current(component string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, safeName(component), "current"))
}

func (s *Store) readState(dirName string) (InstalledInfo, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, dirName, "state.json")) //nolint:gosec // G304: fixed name under the store dir
	if err != nil {
		if os.IsNotExist(err) {
			return InstalledInfo{}, nil
		}
		return InstalledInfo{}, err
	}
	var info InstalledInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return InstalledInfo{}, err
	}
	return info, nil
}

func (s *Store) writeState(dirName string, info InstalledInfo) error {
	raw, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSync(filepath.Join(s.dir, dirName, "state.json"), raw)
}

// writeFileSync writes data to path with 0o600 and fsyncs it before returning, so an
// installed artifact is durable.
func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is under the store dir, component name sanitized
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// safeName maps a component name (which may contain ':' or '/') to a safe directory
// name, so an artifact name can never escape the store directory.
func safeName(component string) string {
	var b strings.Builder
	for _, r := range component {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}
