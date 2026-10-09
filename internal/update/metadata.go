package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// Namespace is the sshsig namespace for update metadata. It is distinct from the
// pack and release namespaces (ADR-0009, ADR-0030), so an update signature can never
// validate a pack or a release and vice versa.
const Namespace = "ittcsecscan-update"

// Spec is the metadata spec version this client understands.
const Spec = "ittcsecscan-tuf/1"

// Role names.
const (
	RoleRoot      = "root"
	RoleTimestamp = "timestamp"
	RoleSnapshot  = "snapshot"
	RoleTargets   = "targets"
)

// Metadata is a signed metadata file: the exact signed bytes and the signatures over
// them. Signing and verification operate on Signed as stored (sign the bytes), so
// there is no canonicalization ambiguity between signer and verifier.
type Metadata struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

// Signature is one signature over the signed bytes: the key id (sha256 of the
// Ed25519 public key) and the armored sshsig.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// header is the common preamble of every role body.
type header struct {
	Spec    string    `json:"spec"`
	Type    string    `json:"type"`
	Version int       `json:"version"`
	Expires time.Time `json:"expires"`
}

// Root lists the trusted keys and, per role, the authorized key ids and the signing
// threshold. It is the trust anchor; every other role's keys come from here.
type Root struct {
	header
	Keys  map[string]Key      `json:"keys"`
	Roles map[string]RoleKeys `json:"roles"`
}

// Key is one trusted public key: its type and its OpenSSH authorized-signers line.
type Key struct {
	Type   string `json:"type"`
	Public string `json:"public"`
}

// RoleKeys names the key ids authorized for a role and how many valid signatures the
// role requires (its threshold).
type RoleKeys struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

// Timestamp pins the current snapshot. It has a short expiry and provides freshness.
type Timestamp struct {
	header
	Meta map[string]MetaRef `json:"meta"`
}

// Snapshot pins the targets metadata, providing consistency (mix-and-match
// protection).
type Snapshot struct {
	header
	Meta map[string]MetaRef `json:"meta"`
}

// MetaRef pins another metadata file by version, length, and hash.
type MetaRef struct {
	Version int    `json:"version"`
	Length  int    `json:"length"`
	SHA256  string `json:"sha256"`
}

// Targets lists each updatable component as a target.
type Targets struct {
	header
	Targets map[string]Target `json:"targets"`
}

// Target pins one component artifact by length and hash, with the component name,
// version, and channel it belongs to.
type Target struct {
	Length int          `json:"length"`
	SHA256 string       `json:"sha256"`
	Custom TargetCustom `json:"custom"`
}

// TargetCustom carries the component identity a target belongs to.
type TargetCustom struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Channel   string `json:"channel"`
}

// keyID is the trust key id of an Ed25519 public key: the lowercase hex SHA-256 of
// the raw key bytes.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// parseKeys parses a root's key table into verified public keys, checking that each
// map key equals the key id derived from its public key (so a key cannot be
// mislabeled to impersonate another key id).
func parseKeys(keys map[string]Key) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		if k.Type != "ssh-ed25519" {
			return nil, fmt.Errorf("key %s: unsupported type %q", id, k.Type)
		}
		pub, err := sshsig.ParseAuthorizedKey(k.Public)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", id, err)
		}
		if got := keyID(pub); got != id {
			return nil, fmt.Errorf("key id %s does not match its public key (%s)", id, got)
		}
		out[id] = pub
	}
	return out, nil
}

// parseRoot parses and shallow-validates a root body.
func parseRoot(signed []byte) (*Root, error) {
	var r Root
	if err := json.Unmarshal(signed, &r); err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}
	if r.Spec != Spec {
		return nil, fmt.Errorf("root: unsupported spec %q", r.Spec)
	}
	if r.Type != RoleRoot {
		return nil, fmt.Errorf("root: type is %q", r.Type)
	}
	return &r, nil
}
