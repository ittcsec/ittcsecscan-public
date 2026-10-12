package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// TestSealUsesRandomNoncePerCall proves the property that justifies the
// //nolint:gosec G407 suppressions at the two Seal call sites (wrapKey in
// keys.go and (*tenantKeys).seal in tenant.go): the AEAD is
// cipher.NewGCMWithRandomNonce (newAEAD), so the nil nonce argument does not
// mean a static nonce. A fresh random nonce is drawn inside every Seal and
// prepended to the ciphertext.
//
// For each call site it seals the same plaintext twice with the same key and
// checks that
//   - the two ciphertexts differ (a per-call random nonce; a static nonce
//     would make GCM deterministic and the two equal), and
//   - the ciphertext length is exactly the plaintext length plus the AEAD tag
//     overhead plus the prepended nonce, and
//   - the first ciphertext still decrypts back to the plaintext, so the
//     prepended nonce is recovered correctly and the length is accounted for.
func TestSealUsesRandomNoncePerCall(t *testing.T) {
	// Reference sizes read from a standard AES-GCM, not hardcoded: the random
	// nonce GCM prepends NonceSize() bytes and adds Overhead() (the tag) bytes.
	gcmSizes := func(t *testing.T, key []byte) (nonce, tag int) {
		t.Helper()
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return ref.NonceSize(), ref.Overhead()
	}

	// Key-wrap call site (keys.go): seal under a tenant KEK via wrapKey, open
	// via unwrapKey. The wrapped plaintext is a tenant key (keyLen bytes).
	m := kat(t)
	id, err := ParseTenantID("aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	kek, err := deriveKEK(m, id)
	if err != nil {
		t.Fatal(err)
	}
	wrapPT := bytes.Repeat([]byte{0x11}, keyLen)

	// Tenant value-encryption call site (tenant.go): seal via (*tenantKeys).seal,
	// open via (*tenantKeys).open, under a tenant data key.
	dataKey := bytes.Repeat([]byte{0x2a}, keyLen)
	aead, err := newAEAD(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	k := &tenantKeys{id: id.String(), aead: aead}
	valuePT := []byte("the same tenant value, sealed twice")

	cases := []struct {
		name string
		key  []byte
		pt   []byte
		seal func(pt []byte) ([]byte, error)
		open func(ct []byte) ([]byte, error)
	}{
		{
			name: "key wrap (keys.go)",
			key:  kek,
			pt:   wrapPT,
			seal: func(pt []byte) ([]byte, error) { return wrapKey(kek, pt, id, 1, purposeData) },
			open: func(ct []byte) ([]byte, error) { return unwrapKey(kek, ct, id, 1, purposeData) },
		},
		{
			name: "tenant value (tenant.go)",
			key:  dataKey,
			pt:   valuePT,
			seal: func(pt []byte) ([]byte, error) { return k.seal(FieldTenantDisplayName(), 1, pt) },
			open: func(ct []byte) ([]byte, error) { return k.open(FieldTenantDisplayName(), 1, ct) },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct1, err := c.seal(c.pt)
			if err != nil {
				t.Fatalf("first seal: %v", err)
			}
			ct2, err := c.seal(c.pt)
			if err != nil {
				t.Fatalf("second seal: %v", err)
			}
			if bytes.Equal(ct1, ct2) {
				t.Fatal("sealing the same plaintext twice produced identical ciphertext: the nonce is not random")
			}

			nonce, tag := gcmSizes(t, c.key)
			want := len(c.pt) + nonce + tag
			if len(ct1) != want {
				t.Errorf("ciphertext length = %d, want plaintext(%d) + nonce(%d) + tag(%d) = %d",
					len(ct1), len(c.pt), nonce, tag, want)
			}

			got, err := c.open(ct1)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(got, c.pt) {
				t.Errorf("round trip = %x, want %x", got, c.pt)
			}
		})
	}
}
