package pack

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ittcsec/ittcsecscan/packs"
)

// authorizedLine renders an ed25519 public key as an "ssh-ed25519 <base64>" field, the form
// used inside an allowed_signers entry.
func authorizedLine(pub ed25519.PublicKey) string {
	var blob []byte
	appendStr := func(s []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s))) //nolint:gosec // G115: test-only helper; lengths are tiny constants
		blob = append(blob, l[:]...)
		blob = append(blob, s...)
	}
	appendStr([]byte("ssh-ed25519"))
	appendStr(pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
}

func trustRootLine(pub ed25519.PublicKey) string {
	return BuiltinPrincipal + ` namespaces="` + PackNamespace + `" ` + authorizedLine(pub) + " ittcsecscan pack signing key\n"
}

// When the trust root names a key, a correctly signed built-in pack loads.
func TestLoadBuiltinAllVerifiesSignedPack(t *testing.T) {
	priv, pub := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	rs, err := LoadBuiltinAll(fsys, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("a correctly signed built-in pack was rejected: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs))
	}
}

// With a trusted key configured, an unsigned built-in pack is refused, not silently loaded.
func TestLoadBuiltinAllRejectsUnsignedWhenTrusted(t *testing.T) {
	priv, pub := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	delete(fsys, "p/manifest.json.sig")
	if _, err := LoadBuiltinAll(fsys, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("an unsigned built-in pack loaded while a trusted key was configured")
	}
}

// With a trusted key configured, a pack whose rule was tampered after signing is refused
// (the manifest signature covers the pinned rule digest).
func TestLoadBuiltinAllRejectsTamperedWhenTrusted(t *testing.T) {
	priv, pub := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	tampered := strings.Replace(string(sampleRuleJSON()), "iam_all_users_roles", "harmless_fact", 1)
	fsys["p/rules/r1.json"] = &fstest.MapFile{Data: []byte(tampered)}
	if _, err := LoadBuiltinAll(fsys, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("a tampered built-in pack loaded while a trusted key was configured")
	}
}

// With a trusted key configured, a pack signed by a different key is refused.
func TestLoadBuiltinAllRejectsWrongKeyWhenTrusted(t *testing.T) {
	priv, _ := genKey(t)
	_, other := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	if _, err := LoadBuiltinAll(fsys, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("a built-in pack signed by an untrusted key loaded")
	}
}

// The interim path (no trusted key embedded yet) loads built-in packs trusted-by-embedding,
// without reading a signature. This is the documented state before the maintainer signing
// ceremony; built-in integrity is covered by the binary's release signature (ADR-0009).
func TestLoadBuiltinAllInterimLoadsWithoutTrustedKeys(t *testing.T) {
	priv, _ := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	delete(fsys, "p/manifest.json.sig") // the interim path never reads a signature
	rs, err := LoadBuiltinAll(fsys, nil)
	if err != nil {
		t.Fatalf("interim built-in load failed: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs))
	}
}

// TrustedBuiltinKeys parses a well-formed, correctly namespaced entry and ignores comments
// and blank lines.
func TestTrustedBuiltinKeysParsesEntry(t *testing.T) {
	_, pub := genKey(t)
	root := "# header comment\n\n" + trustRootLine(pub)
	keys, err := TrustedBuiltinKeys([]byte(root))
	if err != nil {
		t.Fatalf("parsing a valid trust root: %v", err)
	}
	if len(keys) != 1 || !keys[0].Equal(pub) {
		t.Fatalf("got %d keys; key match=%v", len(keys), len(keys) == 1 && keys[0].Equal(pub))
	}
}

// A key restricted to a different namespace is refused: a release key can never be trusted to
// sign a pack.
func TestTrustedBuiltinKeysRejectsWrongNamespace(t *testing.T) {
	_, pub := genKey(t)
	line := BuiltinPrincipal + ` namespaces="ittcsecscan-release" ` + authorizedLine(pub) + "\n"
	if _, err := TrustedBuiltinKeys([]byte(line)); err == nil {
		t.Fatal("a wrong-namespace trust-root entry was accepted")
	}
}

// A garbled non-comment line fails closed rather than silently yielding fewer keys.
func TestTrustedBuiltinKeysRejectsGarbledLine(t *testing.T) {
	if _, err := TrustedBuiltinKeys([]byte("this is not a valid entry\n")); err == nil {
		t.Fatal("a garbled trust-root line was accepted")
	}
}

// An all-comment trust root yields no keys and no error: the interim state.
func TestTrustedBuiltinKeysEmptyIsInterim(t *testing.T) {
	keys, err := TrustedBuiltinKeys([]byte("# only comments\n\n"))
	if err != nil {
		t.Fatalf("all-comment trust root: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no keys, got %d", len(keys))
	}
}

// The shipped trust root parses, and the shipped built-in packs load under it. The trust root
// now names the pack key, so this exercises the fail-closed verification path; if a key is
// listed without the corresponding signatures committed, this test fails, which is the intended
// fail-closed signal that the signing ceremony must be completed.
func TestShippedTrustRootAndBuiltinsLoad(t *testing.T) {
	keys, err := TrustedBuiltinKeys(packs.AllowedSigners())
	if err != nil {
		t.Fatalf("the shipped pack trust root does not parse: %v", err)
	}
	if _, err := LoadBuiltinAll(packs.FS, keys); err != nil {
		t.Fatalf("shipped built-in packs do not load under the shipped trust root: %v", err)
	}
}

// copyEmbeddedPack copies one pack subtree out of the embedded packs.FS into a mutable
// in-memory FS, so a test can remove or tamper a file and re-run Load against the real
// shipped bytes.
func copyEmbeddedPack(t *testing.T, dir string) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	err := fs.WalkDir(packs.FS, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, rerr := fs.ReadFile(packs.FS, p)
		if rerr != nil {
			return rerr
		}
		out[p] = &fstest.MapFile{Data: b}
		return nil
	})
	if err != nil {
		t.Fatalf("copying embedded pack %s: %v", dir, err)
	}
	return out
}

// TestEmbeddedPacksAreSignedAndVerify proves that the two activated packs (identity-hygiene
// and ai-guard) are embedded in packs.FS and ship a valid signature under the shipped trust
// root, and that every embedded pack verifies. It fails if the trust root names no key (so
// signature enforcement would be the interim no-op path rather than fail-closed), if either
// pack is not embedded, if a pack is unsigned, or if a pack's signature does not verify. The
// per-pack negative checks (remove the signature, flip one manifest byte) prove the
// enforcement is real rather than vacuous: an unsigned or tampered pack is refused.
func TestEmbeddedPacksAreSignedAndVerify(t *testing.T) {
	keys, err := TrustedBuiltinKeys(packs.AllowedSigners())
	if err != nil {
		t.Fatalf("shipped pack trust root does not parse: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("shipped trust root names no key: built-in pack signatures are not enforced (interim path). The pack key must be embedded in packs/keys/allowed_signers so verification is fail-closed.")
	}

	// Every embedded pack directory must verify under the shipped key, through the same
	// fail-closed path (Load) that production uses.
	dirs, err := fs.ReadDir(packs.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	embedded := map[string]bool{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		embedded[d.Name()] = true
		if _, err := Load(keys, packs.FS, d.Name()); err != nil {
			t.Errorf("embedded pack %q does not verify under the shipped trust root: %v", d.Name(), err)
		}
	}

	for _, name := range []string{"identity-hygiene", "ai-guard"} {
		if !embedded[name] {
			t.Errorf("pack %q is not embedded in packs.FS", name)
			continue
		}
		// Unsigned: with the committed signature removed, Load must refuse the pack.
		noSig := copyEmbeddedPack(t, name)
		delete(noSig, name+"/manifest.json.sig")
		if _, err := Load(keys, noSig, name); err == nil {
			t.Errorf("pack %q loaded with its signature removed; an unsigned embedded pack must be refused", name)
		}
		// Tampered: flipping a single manifest byte must fail signature verification (Verify
		// runs over the exact manifest bytes before anything is parsed).
		tampered := copyEmbeddedPack(t, name)
		mf := tampered[name+"/manifest.json"]
		b := append([]byte(nil), mf.Data...)
		b[len(b)/2] ^= 0x01
		tampered[name+"/manifest.json"] = &fstest.MapFile{Data: b}
		if _, err := Load(keys, tampered, name); err == nil {
			t.Errorf("pack %q loaded after its manifest was tampered; a pack whose signature does not verify must be refused", name)
		}
	}
}
