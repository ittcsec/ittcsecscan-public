// Package pack loads and verifies signed detection packs, then hands the engine
// (internal/rules) the validated rule data. It is deliberately separate from the
// evaluation package: signature verification legitimately uses crypto, so it lives
// outside the deterministic evaluation gate, and it performs no finding decision.
//
// Signatures are OpenSSH signatures (PROTOCOL.sshsig), Ed25519, in the
// ittcsecscan-pack namespace, verified in process by the shared internal/sshsig
// primitive with the standard library and no new dependency (ADR-0009). The signing
// key is an offline maintainer key; this package only verifies.
package pack

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/rules"
)

// Manifest is a detection pack's declaration (ADR-0021 §1): its identity and version,
// the engine and provider/domain compatibility, and the rule index that pins every
// rule file by digest. The signature is over the manifest bytes, so pinning the digests
// here makes the one signature authenticate the whole pack (the ADR-0009 SHA256SUMS
// pattern).
type Manifest struct {
	SchemaVersion int              `json:"schema_version"`
	PackID        string           `json:"pack_id"`
	Version       string           `json:"version"`
	EngineMin     int              `json:"engine_min"`
	EngineMax     int              `json:"engine_max"`
	Providers     []model.Provider `json:"providers"`
	Domains       []string         `json:"domains"`
	Rules         []RuleEntry      `json:"rules"`
}

// RuleEntry indexes one rule file with its SHA-256 digest (lowercase hex over the file
// bytes) so the manifest signature transitively covers the rule.
type RuleEntry struct {
	ID     string `json:"id"`
	File   string `json:"file"`
	Digest string `json:"digest"`
}

// Pack is a loaded, verified pack: its manifest and its validated rules.
type Pack struct {
	Manifest Manifest
	Rules    []rules.Rule
}

// engineVersion is the evaluation-semantics version this build implements. A pack whose
// [EngineMin, EngineMax] range excludes it is refused rather than guessed.
const engineVersion = 1

// Load reads a pack rooted at dir within fsys, verifies its signature against the
// trusted keys, checks every rule file's digest against the signed manifest, and parses
// and validates each rule. It fails closed (ADR-0021 §2): an unsigned pack, a tampered
// manifest or rule, a wrong key or namespace, an engine-incompatible pack, or an
// invalid rule causes Load to return an error and no partial pack. Nothing is evaluated
// until Load has succeeded.
func Load(trusted []ed25519.PublicKey, fsys fs.FS, dir string) (*Pack, error) {
	manifestBytes, err := fs.ReadFile(fsys, path.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("pack %s: reading manifest: %w", dir, err)
	}
	sig, err := fs.ReadFile(fsys, path.Join(dir, "manifest.json.sig"))
	if err != nil {
		return nil, fmt.Errorf("pack %s: reading signature: %w", dir, err)
	}
	if _, err := Verify(trusted, PackNamespace, manifestBytes, sig); err != nil {
		return nil, fmt.Errorf("pack %s: %w", dir, err)
	}

	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("pack %s: decoding manifest: %w", dir, err)
	}
	if m.PackID == "" || m.Version == "" {
		return nil, fmt.Errorf("pack %s: manifest has no id or version", dir)
	}
	if engineVersion < m.EngineMin || (m.EngineMax != 0 && engineVersion > m.EngineMax) {
		return nil, fmt.Errorf("pack %s: engine %d outside supported range [%d,%d]", m.PackID, engineVersion, m.EngineMin, m.EngineMax)
	}

	entries := append([]RuleEntry(nil), m.Rules...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].File < entries[j].File })

	loaded := make([]rules.Rule, 0, len(entries))
	for _, e := range entries {
		ruleBytes, err := fs.ReadFile(fsys, path.Join(dir, e.File))
		if err != nil {
			return nil, fmt.Errorf("pack %s: reading rule %s: %w", m.PackID, e.File, err)
		}
		sum := sha256.Sum256(ruleBytes)
		if got := hex.EncodeToString(sum[:]); got != e.Digest {
			return nil, fmt.Errorf("pack %s: rule %s digest %s does not match the signed manifest %s", m.PackID, e.File, got, e.Digest)
		}
		var r rules.Rule
		if err := json.Unmarshal(ruleBytes, &r); err != nil {
			return nil, fmt.Errorf("pack %s: decoding rule %s: %w", m.PackID, e.File, err)
		}
		if r.PackID == "" {
			r.PackID = m.PackID
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("pack %s: %w", m.PackID, err)
		}
		loaded = append(loaded, r)
	}
	return &Pack{Manifest: m, Rules: loaded}, nil
}
