package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/ittcsec/ittcsecscan/internal/redact"
)

const (
	keyLen = 32

	kekInfoPrefix   = "ittcsecscan/v1/tenant-kek/"
	wrapLabel       = "ittcsecscan/v1/wrap"
	valueLabel      = "ittcsecscan/v1/sealed-field" // tenant, logical field, row (ADR-0013)
	stableIDLabel   = "ittcsecscan/v1/stable-id"
	keyedHashLabel  = "ittcsecscan/v1/keyed-hash"
	purposeData     = "data-key"
	purposeStableID = "stable-id-key"
)

// MasterKey is one generation of the operator's master key, the root of every
// tenant key (ADR-0010 §2). It never renders: formatting, logging, and
// marshalling print a placeholder.
type MasterKey struct {
	gen uint32
	key [keyLen]byte
}

// NewMasterKey returns generation gen of a 256-bit master key.
func NewMasterKey(gen uint32, key []byte) (MasterKey, error) {
	if gen == 0 {
		return MasterKey{}, errors.New("store: master key generations start at 1")
	}
	if len(key) != keyLen {
		return MasterKey{}, fmt.Errorf("store: a master key is %d bytes", keyLen)
	}
	m := MasterKey{gen: gen}
	copy(m.key[:], key)
	return m, nil
}

// Generation returns the key's generation.
func (m MasterKey) Generation() uint32 { return m.gen }

// String implements fmt.Stringer without revealing the key.
func (MasterKey) String() string { return redact.Placeholder }

// GoString implements fmt.GoStringer without revealing the key.
func (MasterKey) GoString() string { return redact.Placeholder }

// Format implements fmt.Formatter so that every verb prints the placeholder.
func (MasterKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redact.Placeholder) }

// MarshalJSON never reveals the key.
func (MasterKey) MarshalJSON() ([]byte, error) { return []byte(`"` + redact.Placeholder + `"`), nil }

// MarshalText never reveals the key.
func (MasterKey) MarshalText() ([]byte, error) { return []byte(redact.Placeholder), nil }

// LogValue never reveals the key.
func (MasterKey) LogValue() slog.Value { return slog.StringValue(redact.Placeholder) }

// MasterKeys supplies generations of the master key. Sources backed by the OS
// keystore or an operator-supplied key file come with the key-management code
// (ADR-0010 §2); StaticMasterKeys serves tests and embedding callers.
type MasterKeys interface {
	// Current returns the generation new tenants are wrapped under.
	Current(ctx context.Context) (MasterKey, error)
	// Generation returns a specific generation, or an error if it is gone.
	Generation(ctx context.Context, gen uint32) (MasterKey, error)
}

// ErrNoMasterKey reports a master-key generation that is not available.
var ErrNoMasterKey = errors.New("store: master key generation not available")

// StaticMasterKeys holds master keys in memory.
type StaticMasterKeys struct {
	current uint32
	keys    map[uint32]MasterKey
}

// NewStaticMasterKeys holds keys; the highest generation is current.
func NewStaticMasterKeys(keys ...MasterKey) (*StaticMasterKeys, error) {
	if len(keys) == 0 {
		return nil, errors.New("store: no master key")
	}
	s := &StaticMasterKeys{keys: make(map[uint32]MasterKey, len(keys))}
	for _, k := range keys {
		if k.gen == 0 {
			return nil, errors.New("store: master key is not initialised")
		}
		if _, dup := s.keys[k.gen]; dup {
			return nil, fmt.Errorf("store: master key generation %d given twice", k.gen)
		}
		s.keys[k.gen] = k
		s.current = max(s.current, k.gen)
	}
	return s, nil
}

// Current implements MasterKeys.
func (s *StaticMasterKeys) Current(ctx context.Context) (MasterKey, error) {
	return s.Generation(ctx, s.current)
}

// Generation implements MasterKeys.
func (s *StaticMasterKeys) Generation(_ context.Context, gen uint32) (MasterKey, error) {
	k, ok := s.keys[gen]
	if !ok {
		return MasterKey{}, fmt.Errorf("%w: generation %d", ErrNoMasterKey, gen)
	}
	return k, nil
}

// encodeFields encodes a label and fields unambiguously, each as a 4-byte
// big-endian length followed by its bytes, for use as HMAC input or AEAD
// associated data.
func encodeFields(label string, fields ...string) []byte {
	n := 4 + len(label)
	for _, f := range fields {
		n += 4 + len(f)
	}
	b := make([]byte, 0, n)
	for _, f := range append([]string{label}, fields...) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f))) //nolint:gosec // G115: fields are short labels and IDs, far below 4 GiB
		b = append(b, f...)
	}
	return b
}

// kekInfo is the HKDF context for a tenant's key-encryption key: the tenant ID
// and the master-key generation (ADR-0010 §2).
func kekInfo(gen uint32, id TenantID) string {
	return kekInfoPrefix + strconv.FormatUint(uint64(gen), 10) + "/" + id.String()
}

// deriveKEK derives the key-encryption key of tenant id under master key m:
// HKDF-SHA-256 with an empty salt, since the master key is uniformly random.
func deriveKEK(m MasterKey, id TenantID) ([]byte, error) {
	return hkdf.Key(sha256.New, m.key[:], nil, kekInfo(m.gen, id), keyLen)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func wrapAAD(id TenantID, gen uint32, purpose string) []byte {
	return encodeFields(wrapLabel, id.String(), strconv.FormatUint(uint64(gen), 10), purpose)
}

// wrapKey encrypts a tenant key under its key-encryption key, bound to the
// tenant, the generation, and the key's purpose.
func wrapKey(kek, key []byte, id TenantID, gen uint32, purpose string) ([]byte, error) {
	a, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nil, key, wrapAAD(id, gen, purpose)), nil
}

// unwrapKey reverses wrapKey. Any mismatch, of key, tenant, generation,
// purpose, or content, is ErrKeyMismatch.
func unwrapKey(kek, wrapped []byte, id TenantID, gen uint32, purpose string) ([]byte, error) {
	a, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	key, err := a.Open(nil, nil, wrapped, wrapAAD(id, gen, purpose))
	if err != nil || len(key) != keyLen {
		return nil, ErrKeyMismatch
	}
	return key, nil
}

func randomKey(r io.Reader) ([]byte, error) {
	k := make([]byte, keyLen)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, fmt.Errorf("store: generating key: %w", err)
	}
	return k, nil
}
