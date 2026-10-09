package pack

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/rules"
)

// BuiltinPrincipal is the allowed_signers principal for the built-in pack trust root. Every
// entry in the trust root (packs/keys/allowed_signers) uses this principal and is limited to
// the ittcsecscan-pack namespace, mirroring release/keys/allowed_signers (ADR-0009,
// ADR-0021 section 2).
const BuiltinPrincipal = "ittcsecscan-pack"

// TrustedBuiltinKeys parses a built-in pack trust root (an allowed_signers file, e.g. the
// embedded packs/keys/allowed_signers) into the Ed25519 keys authorized to sign built-in
// packs. It accepts only entries of the exact form
//
//	ittcsecscan-pack namespaces="ittcsecscan-pack" ssh-ed25519 <base64> [comment]
//
// mirroring release/lib.sh's release_keys. Blank lines and #-comments are ignored. A
// non-comment line that is not a well-formed, correctly namespaced ed25519 entry is an error:
// a garbled trust root fails closed rather than silently trusting fewer keys. An all-comment
// file yields no keys and no error, which is the interim state before the maintainer embeds a
// key (see LoadBuiltinAll).
func TrustedBuiltinKeys(allowedSigners []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for i, raw := range strings.Split(string(allowedSigners), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != BuiltinPrincipal ||
			fields[1] != `namespaces="`+PackNamespace+`"` || fields[2] != "ssh-ed25519" {
			return nil, fmt.Errorf("pack trust root line %d: expected %s namespaces=%q ssh-ed25519 <key>", i+1, BuiltinPrincipal, PackNamespace)
		}
		key, err := ParseAuthorizedKey(fields[2] + " " + fields[3])
		if err != nil {
			return nil, fmt.Errorf("pack trust root line %d: %w", i+1, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// LoadBuiltin loads a built-in pack rooted at dir within fsys without a signature
// check. Built-in packs are embedded in the binary and are therefore trusted through
// the binary's own release signature (ADR-0009): they are part of the signed artifact.
// The signature path (Load) is for external packs delivered out of band. LoadBuiltin
// still parses and validates every rule and enforces engine compatibility, so a
// malformed built-in pack is a build-time test failure, never a silent bad rule.
func LoadBuiltin(fsys fs.FS, dir string) (*Pack, error) {
	manifestBytes, err := fs.ReadFile(fsys, path.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("builtin pack %s: reading manifest: %w", dir, err)
	}
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("builtin pack %s: decoding manifest: %w", dir, err)
	}
	if m.PackID == "" || m.Version == "" {
		return nil, fmt.Errorf("builtin pack %s: manifest has no id or version", dir)
	}
	if engineVersion < m.EngineMin || (m.EngineMax != 0 && engineVersion > m.EngineMax) {
		return nil, fmt.Errorf("builtin pack %s: engine %d outside supported range [%d,%d]", m.PackID, engineVersion, m.EngineMin, m.EngineMax)
	}

	entries := append([]RuleEntry(nil), m.Rules...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].File < entries[j].File })

	loaded := make([]rules.Rule, 0, len(entries))
	for _, e := range entries {
		b, err := fs.ReadFile(fsys, path.Join(dir, e.File))
		if err != nil {
			return nil, fmt.Errorf("builtin pack %s: reading rule %s: %w", m.PackID, e.File, err)
		}
		var r rules.Rule
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("builtin pack %s: decoding rule %s: %w", m.PackID, e.File, err)
		}
		if r.PackID == "" {
			r.PackID = m.PackID
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("builtin pack %s: %w", m.PackID, err)
		}
		loaded = append(loaded, r)
	}
	return &Pack{Manifest: m, Rules: loaded}, nil
}

// LoadBuiltinAll loads every built-in pack directory in fsys (a directory whose entries are
// pack folders) and returns their rules concatenated, sorted by pack and rule id.
//
// Trust model (ADR-0021 section 2). If trusted is non-empty, every built-in pack MUST carry a
// valid manifest.json.sig by one of those keys in the ittcsecscan-pack namespace, and every
// rule digest must match the signed manifest; a pack that is unsigned, tampered, signed by
// another key, or in the wrong namespace is refused (fail closed), exactly like an external
// pack loaded through Load. If trusted is empty, the built-in packs are loaded
// trusted-by-embedding: they are part of the release-signed binary (ADR-0009), which is their
// integrity guarantee until the maintainer completes the pack-signing ceremony (embeds a key
// in packs/keys/allowed_signers and commits each pack's signature; see packs/README.md). That
// interim path is deliberate and explicit, never a silent unsigned load once a key exists: the
// moment the embedded trust root names a key, verification is mandatory for every built-in
// pack. Callers pass pack.TrustedBuiltinKeys(packs.AllowedSigners()).
func LoadBuiltinAll(fsys fs.FS, trusted []ed25519.PublicKey) ([]rules.Rule, error) {
	dirs, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d.IsDir() {
			names = append(names, d.Name())
		}
	}
	sort.Strings(names)

	var all []rules.Rule
	for _, name := range names {
		var pk *Pack
		var err error
		if len(trusted) > 0 {
			pk, err = Load(trusted, fsys, name)
		} else {
			pk, err = LoadBuiltin(fsys, name)
		}
		if err != nil {
			return nil, err
		}
		all = append(all, pk.Rules...)
	}
	return all, nil
}
