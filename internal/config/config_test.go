package config

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/schema"
)

// hermeticEnv points every directory variable at a fresh temporary tree so no
// test reads or writes the real user profile.
func hermeticEnv(t *testing.T, extra map[string]string) (LookupEnv, map[string]string) {
	t.Helper()
	root := t.TempDir()
	env := map[string]string{
		"APPDATA":         filepath.Join(root, "appdata"),
		"LOCALAPPDATA":    filepath.Join(root, "localappdata"),
		"HOME":            filepath.Join(root, "home"),
		"XDG_CONFIG_HOME": filepath.Join(root, "xdgconfig"),
		"XDG_DATA_HOME":   filepath.Join(root, "xdgdata"),
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }, env
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsWithoutFile(t *testing.T) {
	lookup, _ := hermeticEnv(t, nil)
	cfg, src, err := Load(Overrides{}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if src.File != "" || src.Explicit {
		t.Errorf("source = %+v, want none", src)
	}
	if cfg.SchemaVersion != 1 || cfg.Log.Level != "info" || cfg.Log.Format != "text" {
		t.Errorf("defaults = %+v", cfg)
	}
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		t.Errorf("default data dir %q is not absolute", cfg.DataDir)
	}
	if err := schema.ValidateValue(schema.Config, cfg); err != nil {
		t.Errorf("defaults violate the schema: %v", err)
	}
}

func TestDefaultLocationIsUsed(t *testing.T) {
	lookup, _ := hermeticEnv(t, nil)
	configDir, _, err := platformDirs(runtime.GOOS, lookup)
	if err != nil {
		t.Fatal(err)
	}
	p := writeFile(t, configDir, FileName, `{"schema_version":1,"log":{"level":"warn"}}`)
	cfg, src, err := Load(Overrides{}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if src.File != p || src.Explicit {
		t.Errorf("source = %+v, want default file %s", src, p)
	}
	if cfg.Log.Level != "warn" || cfg.Log.Format != "text" {
		t.Errorf("file values not merged over defaults: %+v", cfg.Log)
	}
}

func TestExplicitMissingFileIsAnError(t *testing.T) {
	lookup, _ := hermeticEnv(t, nil)
	missing := filepath.Join(t.TempDir(), "nope.json")
	if _, _, err := Load(Overrides{ConfigPath: missing}, lookup); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("want error naming %s, got %v", missing, err)
	}
	lookup, _ = hermeticEnv(t, map[string]string{EnvConfig: missing})
	if _, _, err := Load(Overrides{}, lookup); err == nil {
		t.Error("missing file named by environment accepted")
	}
}

func TestFixtures(t *testing.T) {
	tests := []struct {
		file    string
		wantErr string // empty means valid
		check   func(t *testing.T, c Config)
	}{
		{file: "valid_minimal.json"},
		{file: "valid_full.json", check: func(t *testing.T, c Config) {
			if c.Log.Level != "debug" || c.Log.Format != "json" {
				t.Errorf("log = %+v", c.Log)
			}
		}},
		{file: "invalid_unknown_key.json", wantErr: "not allowed"},
		{file: "invalid_level.json", wantErr: "/log/level"},
		{file: "invalid_version.json", wantErr: "/schema_version"},
		{file: "invalid_version_type.json", wantErr: "/schema_version"},
		{file: "invalid_missing_version.json", wantErr: "schema_version"},
		{file: "invalid_duplicate_key.json", wantErr: "duplicate key \"level\""},
		{file: "invalid_trailing_data.json", wantErr: "after the top-level value"},
		{file: "invalid_syntax.json", wantErr: "invalid JSON"},
		{file: "invalid_not_object.json", wantErr: "object"},
		{file: "invalid_empty_data_dir.json", wantErr: "/data_dir"},
		{file: "invalid_relative_data_dir.json", wantErr: "absolute"},
		{file: "invalid_deep_nesting.json", wantErr: "nested deeper"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			lookup, _ := hermeticEnv(t, nil)
			p := filepath.Join("testdata", tt.file)
			cfg, src, err := Load(Overrides{ConfigPath: p}, lookup)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("valid fixture rejected: %v", err)
				}
				if src.File != p || !src.Explicit {
					t.Errorf("source = %+v", src)
				}
				if tt.check != nil {
					tt.check(t, cfg)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid fixture accepted: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), p) {
				t.Errorf("error %q does not name the file", err)
			}
		})
	}
}

func TestUnknownKeyErrorDoesNotEchoValue(t *testing.T) {
	lookup, _ := hermeticEnv(t, nil)
	_, _, err := Load(Overrides{ConfigPath: filepath.Join("testdata", "invalid_unknown_key.json")}, lookup)
	if err == nil || strings.Contains(err.Error(), "not-a-real-secret") {
		t.Errorf("error must name the key, not its value: %v", err)
	}
}

func TestPrecedence(t *testing.T) {
	envDataDir := t.TempDir()
	flagDataDir := t.TempDir()
	file := writeFile(t, t.TempDir(), "c.json", `{"schema_version":1,"log":{"level":"warn","format":"json"}}`)
	lookup, _ := hermeticEnv(t, map[string]string{
		EnvLogLevel: "error",
		EnvDataDir:  envDataDir,
	})

	cfg, _, err := Load(Overrides{ConfigPath: file}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Level != "error" || cfg.Log.Format != "json" || cfg.DataDir != envDataDir {
		t.Errorf("env did not override file: %+v", cfg)
	}

	cfg, _, err = Load(Overrides{ConfigPath: file, LogLevel: "debug", DataDir: flagDataDir}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Level != "debug" || cfg.Log.Format != "json" || cfg.DataDir != flagDataDir {
		t.Errorf("flags did not override env: %+v", cfg)
	}
}

func TestInvalidLayersAreAttributed(t *testing.T) {
	lookup, _ := hermeticEnv(t, map[string]string{EnvLogFormat: "xml"})
	if _, _, err := Load(Overrides{}, lookup); err == nil || !strings.Contains(err.Error(), "environment variables") {
		t.Errorf("want environment error, got %v", err)
	}
	lookup, _ = hermeticEnv(t, nil)
	if _, _, err := Load(Overrides{LogLevel: "loud"}, lookup); err == nil || !strings.Contains(err.Error(), "command-line flags") {
		t.Errorf("want flag error, got %v", err)
	}
	if _, _, err := Load(Overrides{DataDir: "relative"}, lookup); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("want absolute-path error, got %v", err)
	}
}

func TestFileHandling(t *testing.T) {
	lookup, _ := hermeticEnv(t, nil)
	dir := t.TempDir()

	if _, _, err := Load(Overrides{ConfigPath: dir}, lookup); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory as config: %v", err)
	}

	big := writeFile(t, dir, "big.json", `{"schema_version":1}`+strings.Repeat(" ", MaxFileSize))
	if _, _, err := Load(Overrides{ConfigPath: big}, lookup); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized config: %v", err)
	}

	bom := writeFile(t, dir, "bom.json", "\xef\xbb\xbf"+`{"schema_version":1}`)
	if _, _, err := Load(Overrides{ConfigPath: bom}, lookup); err != nil {
		t.Errorf("config with UTF-8 BOM rejected: %v", err)
	}
}

func TestPlatformDirs(t *testing.T) {
	env := func(m map[string]string) LookupEnv {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}

	c, d, err := platformDirs("windows", env(map[string]string{"APPDATA": `C:\Users\u\AppData\Roaming`, "LOCALAPPDATA": `C:\Users\u\AppData\Local`}))
	if err != nil || c != filepath.Join(`C:\Users\u\AppData\Roaming`, appName) || d != filepath.Join(`C:\Users\u\AppData\Local`, appName) {
		t.Errorf("windows = %q %q %v", c, d, err)
	}
	if _, _, err := platformDirs("windows", env(nil)); err == nil {
		t.Error("windows without APPDATA accepted")
	}

	c, d, err = platformDirs("darwin", env(map[string]string{"HOME": "/Users/u"}))
	want := path.Join("/Users/u", "Library", "Application Support", appName)
	if err != nil || c != want || d != want {
		t.Errorf("darwin = %q %q %v", c, d, err)
	}

	c, d, err = platformDirs("linux", env(map[string]string{"HOME": "/home/u", "XDG_CONFIG_HOME": "/cfg", "XDG_DATA_HOME": "relative/ignored"}))
	if err != nil || c != "/cfg/"+appName || d != "/home/u/.local/share/"+appName {
		t.Errorf("linux = %q %q %v", c, d, err)
	}
	if _, _, err := platformDirs("linux", env(nil)); err == nil {
		t.Error("linux without HOME accepted")
	}
}

func TestSourceString(t *testing.T) {
	if !strings.Contains(Source{}.String(), "defaults") || (Source{File: "/x"}).String() != "/x" {
		t.Error("unexpected Source.String")
	}
}

func FuzzDecode(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := Config{SchemaVersion: SchemaVersion, Log: Log{Level: "info", Format: "text"}}
		if err := decode(data, &cfg); err != nil {
			return
		}
		if err := schema.ValidateValue(schema.Config, cfg); err != nil {
			t.Fatalf("decode accepted %q but result violates the schema: %v", data, err)
		}
	})
}

func TestMasterKeyFileValidation(t *testing.T) {
	none := func(string) (string, bool) { return "", false }
	dataDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "master.key")

	if _, _, err := Load(Overrides{MasterKeyFile: "relative/key"}, none); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative master_key_file: want an absolute-path error, got %v", err)
	}
	if _, _, err := Load(Overrides{DataDir: dataDir, MasterKeyFile: filepath.Join(dataDir, "k")}, none); err == nil || !strings.Contains(err.Error(), "outside data_dir") {
		t.Errorf("master_key_file inside data_dir: want an outside error, got %v", err)
	}
	cfg, _, err := Load(Overrides{DataDir: dataDir, MasterKeyFile: outside}, none)
	if err != nil || cfg.MasterKeyFile != outside {
		t.Errorf("valid master_key_file: err=%v path=%q", err, cfg.MasterKeyFile)
	}
}
