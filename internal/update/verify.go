package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// Verification errors. Every one is fail-closed; none is ever converted to success.
var (
	ErrBadMetadata   = errors.New("update: metadata is invalid")
	ErrThreshold     = errors.New("update: not enough valid signatures for the role")
	ErrExpired       = errors.New("update: metadata has expired")
	ErrRollback      = errors.New("update: metadata version is older than the trusted version")
	ErrTarget        = errors.New("update: target does not match the signed metadata")
	ErrUnknownTarget = errors.New("update: target is not listed in the signed metadata")
)

// Fetcher retrieves a metadata or target file by name. It is the seam between the
// trust engine (which is offline and testable) and the transport (HTTP, or an offline
// bundle). It never carries request bodies, inventory, or credentials.
type Fetcher interface {
	Fetch(name string) ([]byte, error)
}

// Client is a TUF-principled update client anchored to a pinned root. It holds the
// trusted root, the trusted public keys, the last-trusted version per role (for
// rollback protection), and an injected clock (for expiry checks and testability).
type Client struct {
	root     *Root
	keys     map[string]ed25519.PublicKey
	versions map[string]int
	now      func() time.Time
}

// NewClient anchors trust to a pinned root metadata document, verifying the root is
// correctly self-signed by a threshold of its own root keys before trusting it. now
// may be nil (defaults to time.Now).
func NewClient(rootMetadata []byte, now func() time.Time) (*Client, error) {
	if now == nil {
		now = time.Now
	}
	var md Metadata
	if err := json.Unmarshal(rootMetadata, &md); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMetadata, err)
	}
	root, err := parseRoot(md.Signed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMetadata, err)
	}
	keys, err := parseKeys(root.Keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMetadata, err)
	}
	rk, ok := root.Roles[RoleRoot]
	if !ok {
		return nil, fmt.Errorf("%w: root role missing", ErrBadMetadata)
	}
	if err := verifySignatures(md.Signed, md.Signatures, keys, rk); err != nil {
		return nil, err
	}
	c := &Client{root: root, keys: keys, versions: map[string]int{}, now: now}
	if c.now().After(root.Expires) {
		return nil, fmt.Errorf("%w: root expired %s", ErrExpired, root.Expires)
	}
	c.versions[RoleRoot] = root.Version
	return c, nil
}

// UpdateRoot rotates the trusted root: the new root must be signed by a threshold of
// the CURRENTLY trusted root keys and by a threshold of its OWN root keys, and its
// version must not go backwards. This steps trust forward without ever trusting an
// unanchored root.
func (c *Client) UpdateRoot(newRootMetadata []byte) error {
	var md Metadata
	if err := json.Unmarshal(newRootMetadata, &md); err != nil {
		return fmt.Errorf("%w: %w", ErrBadMetadata, err)
	}
	newRoot, err := parseRoot(md.Signed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadMetadata, err)
	}
	if newRoot.Version < c.root.Version {
		return fmt.Errorf("%w: root %d < %d", ErrRollback, newRoot.Version, c.root.Version)
	}
	newKeys, err := parseKeys(newRoot.Keys)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadMetadata, err)
	}
	// Signed by the currently trusted root threshold...
	if err := verifySignatures(md.Signed, md.Signatures, c.keys, c.root.Roles[RoleRoot]); err != nil {
		return fmt.Errorf("current root: %w", err)
	}
	// ...and by the new root's own threshold.
	newRK, ok := newRoot.Roles[RoleRoot]
	if !ok {
		return fmt.Errorf("%w: new root role missing", ErrBadMetadata)
	}
	if err := verifySignatures(md.Signed, md.Signatures, newKeys, newRK); err != nil {
		return fmt.Errorf("new root: %w", err)
	}
	if c.now().After(newRoot.Expires) {
		return fmt.Errorf("%w: new root expired %s", ErrExpired, newRoot.Expires)
	}
	c.root, c.keys = newRoot, newKeys
	c.versions[RoleRoot] = newRoot.Version
	return nil
}

// VerifyChain verifies timestamp, then snapshot (pinned by timestamp), then targets
// (pinned by snapshot), and returns the verified targets. It commits the new role
// versions only after every step succeeds, so a partial failure never advances the
// rollback baseline.
func (c *Client) VerifyChain(f Fetcher) (*Targets, error) {
	tsBody, tsHdr, err := c.verifyRoleFile(f, "timestamp.json", RoleTimestamp)
	if err != nil {
		return nil, err
	}
	var ts Timestamp
	if err := json.Unmarshal(tsBody, &ts); err != nil {
		return nil, fmt.Errorf("%w: timestamp: %w", ErrBadMetadata, err)
	}
	snapRef, ok := ts.Meta["snapshot.json"]
	if !ok {
		return nil, fmt.Errorf("%w: timestamp does not pin snapshot", ErrBadMetadata)
	}
	snapRaw, err := fetchPinned(f, "snapshot.json", snapRef)
	if err != nil {
		return nil, err
	}
	snapBody, snapHdr, err := c.verifyRoleBytes(snapRaw, RoleSnapshot)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(snapBody, &snap); err != nil {
		return nil, fmt.Errorf("%w: snapshot: %w", ErrBadMetadata, err)
	}
	tgtRef, ok := snap.Meta["targets.json"]
	if !ok {
		return nil, fmt.Errorf("%w: snapshot does not pin targets", ErrBadMetadata)
	}
	tgtRaw, err := fetchPinned(f, "targets.json", tgtRef)
	if err != nil {
		return nil, err
	}
	tgtBody, tgtHdr, err := c.verifyRoleBytes(tgtRaw, RoleTargets)
	if err != nil {
		return nil, err
	}
	var tgts Targets
	if err := json.Unmarshal(tgtBody, &tgts); err != nil {
		return nil, fmt.Errorf("%w: targets: %w", ErrBadMetadata, err)
	}
	// All verified: advance the rollback baseline.
	c.versions[RoleTimestamp] = tsHdr.Version
	c.versions[RoleSnapshot] = snapHdr.Version
	c.versions[RoleTargets] = tgtHdr.Version
	return &tgts, nil
}

// VerifyTarget checks a downloaded target's bytes against the signed targets metadata:
// it must be listed, and its length and hash must match exactly.
func (c *Client) VerifyTarget(t *Targets, name string, data []byte) (Target, error) {
	tgt, ok := t.Targets[name]
	if !ok {
		return Target{}, fmt.Errorf("%w: %s", ErrUnknownTarget, name)
	}
	if len(data) != tgt.Length {
		return Target{}, fmt.Errorf("%w: %s length %d, want %d", ErrTarget, name, len(data), tgt.Length)
	}
	if h := hashHex(data); h != tgt.SHA256 {
		return Target{}, fmt.Errorf("%w: %s hash mismatch", ErrTarget, name)
	}
	return tgt, nil
}

// verifyRoleFile fetches a role file and verifies it. verifyRoleBytes verifies
// already-fetched bytes (used when the file was pinned by a parent role).
func (c *Client) verifyRoleFile(f Fetcher, name, role string) ([]byte, header, error) {
	raw, err := f.Fetch(name)
	if err != nil {
		return nil, header{}, fmt.Errorf("fetch %s: %w", name, err)
	}
	return c.verifyRoleBytes(raw, role)
}

func (c *Client) verifyRoleBytes(raw []byte, role string) ([]byte, header, error) {
	var md Metadata
	if err := json.Unmarshal(raw, &md); err != nil {
		return nil, header{}, fmt.Errorf("%w: %s: %w", ErrBadMetadata, role, err)
	}
	rk, ok := c.root.Roles[role]
	if !ok {
		return nil, header{}, fmt.Errorf("%w: root does not define role %s", ErrBadMetadata, role)
	}
	if err := verifySignatures(md.Signed, md.Signatures, c.keys, rk); err != nil {
		return nil, header{}, err
	}
	var h header
	if err := json.Unmarshal(md.Signed, &h); err != nil {
		return nil, header{}, fmt.Errorf("%w: %s header: %w", ErrBadMetadata, role, err)
	}
	if h.Spec != Spec {
		return nil, header{}, fmt.Errorf("%w: %s spec %q", ErrBadMetadata, role, h.Spec)
	}
	if h.Type != role {
		return nil, header{}, fmt.Errorf("%w: type %q, want %q", ErrBadMetadata, h.Type, role)
	}
	if c.now().After(h.Expires) {
		return nil, header{}, fmt.Errorf("%w: %s expired %s", ErrExpired, role, h.Expires)
	}
	if h.Version < c.versions[role] {
		return nil, header{}, fmt.Errorf("%w: %s version %d < %d", ErrRollback, role, h.Version, c.versions[role])
	}
	return md.Signed, h, nil
}

// verifySignatures counts distinct valid signatures from authorized keys and requires
// at least the role's threshold. An unauthorized key, a duplicate, or a bad signature
// simply does not count; too few and it fails closed.
func verifySignatures(signed []byte, sigs []Signature, keys map[string]ed25519.PublicKey, rk RoleKeys) error {
	if rk.Threshold <= 0 {
		return fmt.Errorf("%w: role threshold must be positive", ErrBadMetadata)
	}
	authorized := make(map[string]bool, len(rk.KeyIDs))
	for _, id := range rk.KeyIDs {
		authorized[id] = true
	}
	seen := make(map[string]bool, len(sigs))
	valid := 0
	for _, s := range sigs {
		if !authorized[s.KeyID] || seen[s.KeyID] {
			continue
		}
		pub, ok := keys[s.KeyID]
		if !ok {
			continue
		}
		if _, err := sshsig.Verify([]ed25519.PublicKey{pub}, Namespace, signed, []byte(s.Sig)); err != nil {
			continue
		}
		seen[s.KeyID] = true
		valid++
	}
	if valid < rk.Threshold {
		return fmt.Errorf("%w: %d of %d", ErrThreshold, valid, rk.Threshold)
	}
	return nil
}

// fetchPinned fetches a file and checks it against a parent role's pin (length + hash)
// before it is parsed, so a substituted or truncated file is rejected up front.
func fetchPinned(f Fetcher, name string, ref MetaRef) ([]byte, error) {
	raw, err := f.Fetch(name)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	if len(raw) != ref.Length {
		return nil, fmt.Errorf("%w: %s length %d, want %d", ErrTarget, name, len(raw), ref.Length)
	}
	if h := hashHex(raw); h != ref.SHA256 {
		return nil, fmt.Errorf("%w: %s hash mismatch", ErrTarget, name)
	}
	return raw, nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TrustedVersions reports the last trusted version per role (for status output).
func (c *Client) TrustedVersions() map[string]int {
	out := make(map[string]int, len(c.versions))
	for k, v := range c.versions {
		out[k] = v
	}
	return out
}

// RootKeyIDs reports the trusted root key ids (for status output).
func (c *Client) RootKeyIDs() []string { return c.root.Roles[RoleRoot].KeyIDs }
