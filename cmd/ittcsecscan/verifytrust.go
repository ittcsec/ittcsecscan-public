package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/internal/sshsig"
	"github.com/ittcsec/ittcsecscan/packs"
)

var verifyTrustSpec = commandSpec{
	name:     "verify-trust",
	synopsis: "ittcsecscan verify-trust [--signature <file> --over <file> --key <pubkey> --namespace <ns>]",
	description: "Verify signatures with the same in-process verifier the engine uses (ADR-0009,\n" +
		"ADR-0021), fail-closed. It only reads public keys and signatures; it never handles a\n" +
		"private key.\n\n" +
		"With no flags, it verifies the built-in detection packs against the embedded trust\n" +
		"root: when a pack key is embedded it checks every pack's signature and rule digests;\n" +
		"otherwise it reports the packs are trusted by the binary's release signature.\n\n" +
		"With --signature, --over, --key, and --namespace it verifies a detached OpenSSH\n" +
		"signature over a file against a public key in a namespace (for example a release\n" +
		"SHA256SUMS.sig in ittcsecscan-release, or a pack manifest.json.sig in ittcsecscan-pack).\n" +
		"A bad signature, a wrong key, or a wrong namespace fails with a non-zero exit; a bad\n" +
		"signature is never reported as trusted.",
}

func runVerifyTrust(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(verifyTrustSpec.name)
	sigPath := fs.String("signature", "", "detached OpenSSH signature `file` to verify")
	overPath := fs.String("over", "", "the signed `file` the signature is over")
	keyPath := fs.String("key", "", "OpenSSH public key `file` (ssh-ed25519) to trust")
	namespace := fs.String("namespace", "", "sshsig `namespace` (e.g. ittcsecscan-release, ittcsecscan-pack)")
	if done, err := parse(fs, inv, verifyTrustSpec, args); done {
		return err
	}
	if *sigPath == "" && *overPath == "" && *keyPath == "" && *namespace == "" {
		return verifyBuiltinTrust(inv.out)
	}
	if *sigPath == "" || *overPath == "" || *keyPath == "" || *namespace == "" {
		return exitcode.Errorf(exitcode.Usage, "verify-trust: --signature, --over, --key, and --namespace are all required together")
	}
	return verifyDetachedFiles(inv.out, *sigPath, *overPath, *keyPath, *namespace)
}

// verifyBuiltinTrust verifies the embedded built-in pack trust using the same loader the
// engine uses. With a pack key embedded, a tampered or unsigned pack fails closed.
func verifyBuiltinTrust(w io.Writer) error {
	trusted, err := pack.TrustedBuiltinKeys(packs.AllowedSigners())
	if err != nil {
		return exitcode.Errorf(exitcode.Internal, "verify-trust: the embedded pack trust root is malformed: %v", err)
	}
	if _, err := pack.LoadBuiltinAll(packs.FS, trusted); err != nil {
		return exitcode.Errorf(exitcode.Internal, "verify-trust: built-in pack trust FAILED (fail-closed): %v", err)
	}
	if len(trusted) > 0 {
		return writeText(w, fmt.Sprintf("built-in packs: VERIFIED against %d embedded pack key(s); signatures and rule digests check\n", len(trusted)))
	}
	return writeText(w, "built-in packs: loaded; trusted by the binary's release signature (no pack key embedded yet, so per-pack signatures are not required)\n")
}

func verifyDetachedFiles(w io.Writer, sigPath, overPath, keyPath, namespace string) error {
	sig, err := os.ReadFile(sigPath) //nolint:gosec // G304: operator-supplied signature path
	if err != nil {
		return exitcode.Wrap(exitcode.Usage, err)
	}
	signed, err := os.ReadFile(overPath) //nolint:gosec // G304: operator-supplied signed-file path
	if err != nil {
		return exitcode.Wrap(exitcode.Usage, err)
	}
	keyData, err := os.ReadFile(keyPath) //nolint:gosec // G304: operator-supplied public-key path
	if err != nil {
		return exitcode.Wrap(exitcode.Usage, err)
	}
	if err := verifyDetached(string(keyData), namespace, signed, sig); err != nil {
		return exitcode.Errorf(exitcode.Internal, "verify-trust: signature verification FAILED (fail-closed): %v", err)
	}
	return writeText(w, fmt.Sprintf("signature VERIFIED: %s is a good %s signature over %s\n", sigPath, namespace, overPath))
}

// verifyDetached parses one OpenSSH public-key line and verifies an armored detached
// signature over signed in namespace, using the shared in-process verifier. Any failure
// (bad signature, wrong key, wrong namespace, or malformed key) is returned, never ignored.
func verifyDetached(pubKeyLine, namespace string, signed, sig []byte) error {
	key, err := sshsig.ParseAuthorizedKey(firstKeyLine(pubKeyLine))
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	_, err = sshsig.Verify([]ed25519.PublicKey{key}, namespace, signed, sig)
	return err
}

// firstKeyLine returns the first ssh-ed25519 line from a public-key file's contents, or
// the trimmed input when none is marked (so a bare key line also works).
func firstKeyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "ssh-ed25519 ") {
			return ln
		}
	}
	return strings.TrimSpace(s)
}
