package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ittcsec/ittcsecscan/internal/app"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
)

// minPassphraseLen is the floor for an operator-supplied passphrase (ADR-0015).
// It is a floor, not a guarantee; keys init offers a generated passphrase, which
// is stronger.
const minPassphraseLen = 12

var keysSpec = commandSpec{
	name:     "keys",
	synopsis: "ittcsecscan keys <init|check> [runtime flags]",
	description: "Manage the operator master key that protects all tenant data (ADR-0015).\n\n" +
		"  init   Create the master key and write it, passphrase-wrapped, to the\n" +
		"         master-key file. Refuses to overwrite an existing key.\n" +
		"  check  Read the master key and confirm the passphrase unwraps it.\n\n" +
		"The master-key file is set by --master-key-file or master_key_file in the\n" +
		"configuration, and holds the path only, never the key. There is no recovery:\n" +
		"if the key file or its passphrase is lost, every tenant encrypted under it is\n" +
		"permanently unreadable.",
}

// keysHelpFlags returns a flag set with the runtime flags registered, so keys
// help lists them.
func keysHelpFlags() *flag.FlagSet {
	fs := newFlagSet(keysSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	return fs
}

func runKeys(ctx context.Context, inv *invocation, args []string) error {
	if len(args) == 0 {
		writeCommandHelp(inv.out, keysHelpFlags(), keysSpec)
		return exitcode.Errorf(exitcode.Usage, "keys: a subcommand is required (init or check)")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		writeCommandHelp(inv.out, keysHelpFlags(), keysSpec)
		return nil
	case "init":
		return runKeysInit(ctx, inv, args[1:])
	case "check":
		return runKeysCheck(ctx, inv, args[1:])
	default:
		return exitcode.Errorf(exitcode.Usage, "keys: unknown subcommand %q (init or check)", args[0])
	}
}

// masterKeyPath loads configuration and returns the configured master-key file
// path, or an error the operator can act on.
func masterKeyPath(inv *invocation, rf runtimeFlags) (string, error) {
	a, err := app.New(app.Options{Overrides: rf.overrides(), LookupEnv: inv.lookupEnv, Stderr: inv.err})
	if err != nil {
		return "", err
	}
	if a.Config.MasterKeyFile == "" {
		return "", exitcode.Errorf(exitcode.Usage,
			"no master-key file configured; set --master-key-file or master_key_file in the configuration")
	}
	return a.Config.MasterKeyFile, nil
}

func runKeysInit(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet("keys init")
	var rf runtimeFlags
	rf.register(fs)
	spec := commandSpec{name: "keys init", synopsis: "ittcsecscan keys init [runtime flags]",
		description: "Create the master key and write it, passphrase-wrapped, to the master-key file."}
	if done, err := parse(fs, inv, spec, args); done {
		return err
	}
	path, err := masterKeyPath(inv, rf)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return exitcode.Errorf(exitcode.Config, "a master key already exists at %s; refusing to overwrite it", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking %s: %w", path, err)
	}

	warnKeyLoss(inv.err)
	pass, err := newPassphrase(inv)
	if err != nil {
		return err
	}
	defer clear(pass)
	if err := store.InitMasterKey(path, 1, pass); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(inv.out, "Created the master key (generation 1) at %s\n", path)
	return nil
}

func runKeysCheck(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet("keys check")
	var rf runtimeFlags
	rf.register(fs)
	spec := commandSpec{name: "keys check", synopsis: "ittcsecscan keys check [runtime flags]",
		description: "Read the master key and confirm the passphrase unwraps it."}
	if done, err := parse(fs, inv, spec, args); done {
		return err
	}
	path, err := masterKeyPath(inv, rf)
	if err != nil {
		return err
	}
	if inv.readSecret == nil {
		return errors.New("cannot read a passphrase")
	}
	keys := store.NewFileMasterKeys(path, func() ([]byte, error) {
		return inv.readSecret("Enter the master-key passphrase: ")
	})
	m, err := keys.Current(ctx)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(inv.out, "Master key OK: generation %d, from %s\n", m.Generation(), path)
	return nil
}

// warnKeyLoss prints the no-recovery warning (ADR-0015) before a key is created.
func warnKeyLoss(w io.Writer) {
	_, _ = io.WriteString(w, termsafe.String(
		"WARNING: there is no backdoor and no recovery.\n"+
			"If you lose this key file or forget its passphrase, every tenant encrypted\n"+
			"under it becomes permanently unreadable. Store the passphrase in a password\n"+
			"manager and back up the key file.\n\n"))
}

// newPassphrase obtains the passphrase for a new key: an operator passphrase of
// at least minPassphraseLen characters, confirmed by re-entry, or a generated
// high-entropy one shown once when the operator leaves it empty (ADR-0015).
func newPassphrase(inv *invocation) ([]byte, error) {
	if inv.readSecret == nil {
		return nil, errors.New("cannot read a passphrase")
	}
	pass, err := inv.readSecret("Enter a passphrase for the master key (empty to generate one): ")
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		gen, err := generatePassphrase()
		if err != nil {
			return nil, err
		}
		_, _ = fmt.Fprintf(inv.err, "Generated passphrase (store it now; it cannot be recovered):\n\n    %s\n\n", gen)
		return gen, nil
	}
	if len(pass) < minPassphraseLen {
		clear(pass)
		return nil, exitcode.Errorf(exitcode.Usage, "the passphrase must be at least %d characters", minPassphraseLen)
	}
	confirm, err := inv.readSecret("Confirm the passphrase: ")
	if err != nil {
		clear(pass)
		return nil, err
	}
	defer clear(confirm)
	if !bytes.Equal(pass, confirm) {
		clear(pass)
		return nil, exitcode.Errorf(exitcode.Usage, "the passphrases do not match")
	}
	return pass, nil
}

// generatePassphrase returns a fresh 128-bit passphrase, URL-safe base64.
func generatePassphrase() ([]byte, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(out, raw)
	return out, nil
}
