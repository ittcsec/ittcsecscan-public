package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

// keysEnv gives a hermetic environment with a master-key file path configured.
func keysEnv(t *testing.T) (string, config.LookupEnv) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "master.key")
	return keyPath, hermetic(t, map[string]string{config.EnvMasterKeyFile: keyPath})
}

// keys init creates a key, warns about the loss consequence, and keys check
// then unwraps it with the same passphrase.
func TestKeysInitThenCheck(t *testing.T) {
	_, env := keysEnv(t)
	const pass = "a-strong-passphrase"

	r := invokeSecrets(env, queuedSecrets(pass, pass), "keys", "init")
	if r.code != exitcode.OK {
		t.Fatalf("keys init: code=%d err=%q", r.code, r.err)
	}
	if !strings.Contains(r.err, "no backdoor and no recovery") {
		t.Error("keys init did not print the key-loss warning")
	}
	if !strings.Contains(r.out, "Created the master key (generation 1)") {
		t.Errorf("keys init out = %q", r.out)
	}

	c := invokeSecrets(env, queuedSecrets(pass), "keys", "check")
	if c.code != exitcode.OK || !strings.Contains(c.out, "generation 1") {
		t.Fatalf("keys check: code=%d out=%q err=%q", c.code, c.out, c.err)
	}
}

// A second init never overwrites an existing key.
func TestKeysInitRefusesOverwrite(t *testing.T) {
	_, env := keysEnv(t)
	const pass = "a-strong-passphrase"
	if r := invokeSecrets(env, queuedSecrets(pass, pass), "keys", "init"); r.code != exitcode.OK {
		t.Fatalf("first init: %d %s", r.code, r.err)
	}
	r := invokeSecrets(env, queuedSecrets(pass, pass), "keys", "init")
	if r.code == exitcode.OK {
		t.Error("a second keys init overwrote the existing key")
	}
	if !strings.Contains(r.err, "refusing to overwrite") {
		t.Errorf("overwrite error = %q", r.err)
	}
}

// An empty passphrase generates a strong one, shown once; check then unwraps
// with the generated passphrase.
func TestKeysInitGeneratesPassphrase(t *testing.T) {
	_, env := keysEnv(t)
	r := invokeSecrets(env, queuedSecrets(""), "keys", "init")
	if r.code != exitcode.OK {
		t.Fatalf("keys init: code=%d err=%q", r.code, r.err)
	}
	m := regexp.MustCompile(`(?m)^    ([A-Za-z0-9_-]{22})$`).FindStringSubmatch(r.err)
	if m == nil {
		t.Fatalf("no generated passphrase shown: %q", r.err)
	}
	c := invokeSecrets(env, queuedSecrets(m[1]), "keys", "check")
	if c.code != exitcode.OK {
		t.Fatalf("check with the generated passphrase: code=%d err=%q", c.code, c.err)
	}
}

func TestKeysInitRejectsWeakInput(t *testing.T) {
	_, env := keysEnv(t)
	t.Run("too short", func(t *testing.T) {
		r := invokeSecrets(env, queuedSecrets("short"), "keys", "init")
		if r.code != exitcode.Usage || !strings.Contains(r.err, "at least 12") {
			t.Errorf("short passphrase: code=%d err=%q", r.code, r.err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		r := invokeSecrets(env, queuedSecrets("aaaaaaaaaaaa", "bbbbbbbbbbbb"), "keys", "init")
		if r.code != exitcode.Usage || !strings.Contains(r.err, "do not match") {
			t.Errorf("mismatch: code=%d err=%q", r.code, r.err)
		}
	})
}

// keys check fails closed on the wrong passphrase, and never reports success.
func TestKeysCheckWrongPassphraseFailsClosed(t *testing.T) {
	_, env := keysEnv(t)
	const pass = "a-strong-passphrase"
	if r := invokeSecrets(env, queuedSecrets(pass, pass), "keys", "init"); r.code != exitcode.OK {
		t.Fatalf("init: %d %s", r.code, r.err)
	}
	c := invokeSecrets(env, queuedSecrets("the-wrong-passphrase"), "keys", "check")
	if c.code == exitcode.OK {
		t.Error("keys check accepted a wrong passphrase")
	}
	if strings.Contains(c.out, "OK") {
		t.Errorf("keys check reported success on a wrong passphrase: %q", c.out)
	}
}

func TestKeysNoFileConfigured(t *testing.T) {
	env := hermetic(t, nil)
	r := invokeSecrets(env, queuedSecrets("a-strong-passphrase"), "keys", "init")
	if r.code != exitcode.Usage || !strings.Contains(r.err, "no master-key file configured") {
		t.Errorf("no key file: code=%d err=%q", r.code, r.err)
	}
}

// A key file inside the data directory is refused by configuration validation.
func TestKeysFileInsideDataDirRejected(t *testing.T) {
	dataDir := t.TempDir()
	inside := filepath.Join(dataDir, "master.key")
	env := hermetic(t, map[string]string{config.EnvDataDir: dataDir, config.EnvMasterKeyFile: inside})
	r := invokeSecrets(env, noSecret, "keys", "check")
	if r.code != exitcode.Config || !strings.Contains(r.err, "outside data_dir") {
		t.Errorf("key inside data dir: code=%d err=%q", r.code, r.err)
	}
}

func TestKeysUsage(t *testing.T) {
	env := hermetic(t, nil)
	if r := invokeSecrets(env, noSecret, "keys"); r.code != exitcode.Usage {
		t.Errorf("keys with no subcommand: code=%d", r.code)
	}
	if r := invokeSecrets(env, noSecret, "keys", "bogus"); r.code != exitcode.Usage {
		t.Errorf("keys with an unknown subcommand: code=%d", r.code)
	}
}
