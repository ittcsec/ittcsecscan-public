package update

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// KeyIDForAuthorizedKey returns the trust key id (lowercase hex SHA-256 of the raw Ed25519
// key) for an OpenSSH "ssh-ed25519 <base64> [comment]" line, the id the root's key table and
// the signatures use. The release tool derives each role key's id from its public line with
// this, so the id it writes always matches what the verifier recomputes.
func KeyIDForAuthorizedKey(line string) (string, error) {
	pub, err := sshsig.ParseAuthorizedKey(line)
	if err != nil {
		return "", err
	}
	return keyID(pub), nil
}

// This file is the release-time counterpart of verify.go: it builds the signed metadata
// set that the client verifies (UP-1, ADR-0030). It signs nothing itself. Signing is an
// injected Signer, so the private keys never enter this package: tests sign with an
// in-memory key, and the release tool drives the maintainer's offline, passphrase
// protected keys through ssh-keygen. The generator and the verifier agree on one rule,
// stated in metadata.go: sign and verify operate on the exact stored "signed" bytes.

// Signer produces the armored sshsig over a role's exact signed body bytes, in the update
// namespace. It returns only the signature; the key id comes from the configured role key,
// so the root's key table and the signatures cannot disagree.
type Signer func(signed []byte) (sig string, err error)

// GenKey is one role's public key as it appears in the root: its OpenSSH authorized line
// and the trust key id derived from it (lowercase hex SHA-256 of the raw Ed25519 key).
type GenKey struct {
	Public string
	KeyID  string
}

// GenTarget is one release artifact listed in the targets role: the name a client fetches
// it by, its length and SHA-256, and the component identity it belongs to.
type GenTarget struct {
	Name      string
	Length    int
	SHA256    string
	Component string
	Version   string
	Channel   string
}

// GenConfig is everything the generator needs that is not a signature: the clock, the
// targets, the public key and monotonic version per role, and each role's validity window.
type GenConfig struct {
	Now      time.Time
	Targets  []GenTarget
	RoleKeys map[string]GenKey        // keyed by RoleRoot/RoleTargets/RoleSnapshot/RoleTimestamp
	Versions map[string]int           // per role
	Expiry   map[string]time.Duration // per role, from Now
}

// Generate builds and signs the four metadata files in dependency order: targets, then
// snapshot pinning the signed targets file, then timestamp pinning the signed snapshot
// file, then a self-signed root that lists every role's key. It returns each file's bytes
// keyed by its client-facing name. The pins are over the full signed files (length and
// hash), exactly what the client's fetchPinned checks, so a set produced here verifies.
func Generate(cfg GenConfig, sign map[string]Signer) (map[string][]byte, error) {
	for _, role := range []string{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp} {
		if _, ok := cfg.RoleKeys[role]; !ok {
			return nil, fmt.Errorf("generate: missing key for role %s", role)
		}
		if sign[role] == nil {
			return nil, fmt.Errorf("generate: missing signer for role %s", role)
		}
	}

	// targets
	tgts := Targets{header: cfg.head(RoleTargets), Targets: map[string]Target{}}
	for _, t := range cfg.Targets {
		if t.Name == "" {
			return nil, fmt.Errorf("generate: a target has no name")
		}
		tgts.Targets[t.Name] = Target{Length: t.Length, SHA256: t.SHA256, Custom: TargetCustom{Component: t.Component, Version: t.Version, Channel: t.Channel}}
	}
	targetsFile, err := cfg.signed(RoleTargets, tgts, sign)
	if err != nil {
		return nil, err
	}

	// snapshot pins the signed targets file
	snap := Snapshot{header: cfg.head(RoleSnapshot), Meta: map[string]MetaRef{
		"targets.json": metaRefOf(targetsFile, cfg.Versions[RoleTargets]),
	}}
	snapshotFile, err := cfg.signed(RoleSnapshot, snap, sign)
	if err != nil {
		return nil, err
	}

	// timestamp pins the signed snapshot file
	ts := Timestamp{header: cfg.head(RoleTimestamp), Meta: map[string]MetaRef{
		"snapshot.json": metaRefOf(snapshotFile, cfg.Versions[RoleSnapshot]),
	}}
	timestampFile, err := cfg.signed(RoleTimestamp, ts, sign)
	if err != nil {
		return nil, err
	}

	// root lists every role's key and threshold, and is signed by the root key
	root := Root{header: cfg.head(RoleRoot), Keys: map[string]Key{}, Roles: map[string]RoleKeys{}}
	for _, role := range []string{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp} {
		k := cfg.RoleKeys[role]
		root.Keys[k.KeyID] = Key{Type: "ssh-ed25519", Public: k.Public}
		root.Roles[role] = RoleKeys{KeyIDs: []string{k.KeyID}, Threshold: 1}
	}
	rootFile, err := cfg.signed(RoleRoot, root, sign)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		"root.json":      rootFile,
		"targets.json":   targetsFile,
		"snapshot.json":  snapshotFile,
		"timestamp.json": timestampFile,
	}, nil
}

// head builds a role's header with the spec, type, version, and expiry from the config.
func (cfg GenConfig) head(role string) header {
	return header{Spec: Spec, Type: role, Version: cfg.Versions[role], Expires: cfg.Now.Add(cfg.Expiry[role]).UTC()}
}

// signed marshals a role body to compact bytes, has the role's signer sign those exact
// bytes, and wraps them with the signature into a Metadata file. The stored "signed"
// bytes are the bytes that were signed, so there is no canonicalization gap.
func (cfg GenConfig) signed(role string, body any, sign map[string]Signer) ([]byte, error) {
	signedBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("generate: marshal %s body: %w", role, err)
	}
	sig, err := sign[role](signedBody)
	if err != nil {
		return nil, fmt.Errorf("generate: sign %s: %w", role, err)
	}
	md := Metadata{Signed: json.RawMessage(signedBody), Signatures: []Signature{{KeyID: cfg.RoleKeys[role].KeyID, Sig: sig}}}
	file, err := json.Marshal(md)
	if err != nil {
		return nil, fmt.Errorf("generate: marshal %s file: %w", role, err)
	}
	return file, nil
}

// metaRefOf pins a full signed metadata file by version, length, and hash.
func metaRefOf(file []byte, version int) MetaRef {
	return MetaRef{Version: version, Length: len(file), SHA256: hashHex(file)}
}
