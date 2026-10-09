package config

import (
	"path/filepath"
	"testing"
)

// Doctor inspects the permissions of a configuration file even when it fails
// to load, so Load must say which file it attempted.
func TestLoadErrorKeepsAttemptedSource(t *testing.T) {
	lookup, _ := hermeticEnv(t, nil)
	p := filepath.Join("testdata", "invalid_level.json")
	_, src, err := Load(Overrides{ConfigPath: p}, lookup)
	if err == nil {
		t.Fatal("invalid fixture accepted")
	}
	if src.File != p || !src.Explicit {
		t.Errorf("source = %+v, want the attempted file %s", src, p)
	}

	lookup, _ = hermeticEnv(t, map[string]string{EnvLogLevel: "loud"})
	_, src, err = Load(Overrides{ConfigPath: filepath.Join("testdata", "valid_minimal.json")}, lookup)
	if err == nil || src.File == "" {
		t.Errorf("environment error lost the source: src=%+v err=%v", src, err)
	}
}
