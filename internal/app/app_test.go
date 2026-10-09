package app

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

func hermetic(t *testing.T, extra map[string]string) config.LookupEnv {
	t.Helper()
	root := t.TempDir()
	env := map[string]string{
		"APPDATA":      filepath.Join(root, "appdata"),
		"LOCALAPPDATA": filepath.Join(root, "localappdata"),
		"HOME":         filepath.Join(root, "home"),
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

func badConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNew(t *testing.T) {
	var logs bytes.Buffer
	a, err := New(Options{Overrides: config.Overrides{LogLevel: "debug", LogFormat: "json"}, LookupEnv: hermetic(t, nil), Stderr: &logs})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug level not applied")
	}
	a.Logger.Debug("probe", "password", "x")
	if !bytes.Contains(logs.Bytes(), []byte(`"password":"[REDACTED]"`)) {
		t.Errorf("logger is not the redacting JSON logger: %s", logs.String())
	}
	if a.Build.Version == "" {
		t.Error("build identity missing")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	_, err := New(Options{Overrides: config.Overrides{ConfigPath: badConfig(t)}, LookupEnv: hermetic(t, nil), Stderr: &bytes.Buffer{}})
	if exitcode.From(err) != exitcode.Config {
		t.Fatalf("exit code = %v, want config (err %v)", exitcode.From(err), err)
	}
}

func TestNewLenientFallsBackToDefaults(t *testing.T) {
	a := NewLenient(Options{Overrides: config.Overrides{ConfigPath: badConfig(t)}, LookupEnv: hermetic(t, nil), Stderr: &bytes.Buffer{}})
	if a.ConfigErr == nil {
		t.Fatal("configuration error was not recorded")
	}
	if a.Config.Log.Level != "info" || a.ConfigSource.File == "" || a.Logger == nil {
		t.Errorf("want defaults plus the attempted file in ConfigSource: %+v %+v", a.Config, a.ConfigSource)
	}
}
