package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var testPassphrase = []byte("correct horse battery staple")

// A wrapped key round-trips: the same passphrase opens it, and the generation
// survives.
func TestKeyFileRoundTrip(t *testing.T) {
	var key [keyLen]byte
	for i := range key {
		key[i] = byte(i)
	}
	data, err := wrapMasterKey(key, 7, testPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != keyFileLen {
		t.Fatalf("wrapped file is %d bytes, want %d", len(data), keyFileLen)
	}
	m, err := unwrapMasterKey(data, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if m.gen != 7 || !bytes.Equal(m.key[:], key[:]) {
		t.Errorf("round-trip changed the key or generation (gen %d)", m.gen)
	}
}

// The wrong passphrase never opens the file, and never yields a key.
func TestKeyFileWrongPassphrase(t *testing.T) {
	data, err := wrapMasterKey([keyLen]byte{1, 2, 3}, 1, testPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unwrapMasterKey(data, []byte("wrong passphrase entirely")); !errors.Is(err, ErrKeyFile) {
		t.Errorf("wrong passphrase = %v, want ErrKeyFile", err)
	}
}

// Tampering with any region of the file is caught, either as a bad header or as
// a failed authentication; it never opens.
func TestKeyFileTamperIsRejected(t *testing.T) {
	base, err := wrapMasterKey([keyLen]byte{9}, 3, testPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{0, 9, 12, 25, 40, keyFileLen - 1} { // magic, gen, params, salt, nonce, sealed
		data := bytes.Clone(base)
		data[at] ^= 0xff
		if _, err := unwrapMasterKey(data, testPassphrase); !errors.Is(err, ErrKeyFile) {
			t.Errorf("a byte flipped at %d still opened, want ErrKeyFile", at)
		}
	}
	// Wrong length is rejected before anything else.
	if _, err := unwrapMasterKey(base[:keyFileLen-1], testPassphrase); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a truncated file = %v, want ErrKeyFile", err)
	}
	if _, err := unwrapMasterKey(append(bytes.Clone(base), 0), testPassphrase); !errors.Is(err, ErrKeyFile) {
		t.Errorf("an over-long file = %v, want ErrKeyFile", err)
	}
}

// initMasterKey writes a readable key and refuses to overwrite an existing one.
func TestInitMasterKeyWritesAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := initMasterKey(path, 1, testPassphrase, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != keyFileLen {
		t.Errorf("key file is %d bytes, want %d", info.Size(), keyFileLen)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-created temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unwrapMasterKey(data, testPassphrase); err != nil {
		t.Errorf("the created key does not open: %v", err)
	}
	// A second init must not overwrite the first.
	if err := initMasterKey(path, 1, testPassphrase, nil); err == nil {
		t.Error("initMasterKey overwrote an existing key file")
	}
	// The original is intact.
	after, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-created temp file
	if err != nil || !bytes.Equal(after, data) {
		t.Error("the key file changed after a refused overwrite")
	}
}
