package store

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

// A passphrase-wrapped master-key file (ADR-0015 §3). ittcsecscan never writes a
// plaintext key to disk: a key it creates is sealed here with AES-256-GCM under
// a key derived from the operator's passphrase by scrypt. The file is
// self-describing so a later parameter increase still opens old files, and the
// generation lives in the header so the current generation can be read without
// the passphrase.
//
// Layout (all integers big-endian), total 97 bytes:
//
//	magic   8   "ITTCMK01"
//	gen     4   key generation, >= 1
//	logN    1   scrypt N = 1 << logN
//	r       4   scrypt block size
//	p       4   scrypt parallelism
//	salt    16  scrypt salt
//	nonce   12  AES-256-GCM nonce
//	sealed  48  AES-256-GCM of the 32-byte key (32 + 16 tag)
const (
	keyFileMagic = "ITTCMK01"
	keyFileLen   = 8 + 4 + 1 + 4 + 4 + 16 + 12 + 48

	// scrypt parameters (ADR-0015 §3): N = 2^17, r = 8, p = 1, about 128 MiB,
	// meeting the current OWASP Password Storage Cheat Sheet minimum for scrypt.
	kdfLogN = 17
	kdfR    = 8
	kdfP    = 1

	kdfSaltLen = 16
)

// ErrKeyFile reports a master-key file that cannot be read as one: wrong magic,
// wrong length, or a passphrase or contents that do not authenticate. It never
// means "no key here" — a missing file is a distinct os error — so it always
// stops resolution rather than falling through (ADR-0015 §2).
var ErrKeyFile = errors.New("store: the master-key file is unreadable or the passphrase is wrong")

// deriveWrapKey runs scrypt over the passphrase and salt with the given
// parameters, returning a 32-byte key. The caller zeroes it after use.
func deriveWrapKey(passphrase, salt []byte, logN int, r, p int) ([]byte, error) {
	if logN < 1 || logN > 31 || r < 1 || p < 1 {
		return nil, fmt.Errorf("%w: bad scrypt parameters", ErrKeyFile)
	}
	return scrypt.Key(passphrase, salt, 1<<logN, r, p, keyLen)
}

// wrapMasterKey seals a 32-byte key under passphrase, returning the file bytes.
func wrapMasterKey(key [keyLen]byte, gen uint32, passphrase []byte, randr io.Reader) ([]byte, error) {
	if gen == 0 {
		return nil, errors.New("store: master key generations start at 1")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("store: a passphrase is required to wrap a master key")
	}
	randr = randReader(randr)
	salt := make([]byte, kdfSaltLen)
	if _, err := io.ReadFull(randr, salt); err != nil {
		return nil, err
	}
	wrapKey, err := deriveWrapKey(passphrase, salt, kdfLogN, kdfR, kdfP)
	if err != nil {
		return nil, err
	}
	defer clear(wrapKey)
	gcm, err := newAEAD(wrapKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randr, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, key[:], keyFileAAD(gen))

	out := make([]byte, 0, keyFileLen)
	out = append(out, keyFileMagic...)
	out = binary.BigEndian.AppendUint32(out, gen)
	out = append(out, kdfLogN)
	out = binary.BigEndian.AppendUint32(out, kdfR)
	out = binary.BigEndian.AppendUint32(out, kdfP)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// keyFileAAD binds the generation into the sealed key's associated data, so the
// header's generation cannot be swapped without failing authentication.
func keyFileAAD(gen uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte(keyFileMagic), gen)
}

// keyFileGeneration reads the generation from file bytes without the passphrase.
// It validates the magic and length, so a corrupt file is caught here.
func keyFileGeneration(data []byte) (uint32, error) {
	if len(data) != keyFileLen || string(data[:8]) != keyFileMagic {
		return 0, fmt.Errorf("%w: not a master-key file", ErrKeyFile)
	}
	gen := binary.BigEndian.Uint32(data[8:12])
	if gen == 0 {
		return 0, fmt.Errorf("%w: generation is zero", ErrKeyFile)
	}
	return gen, nil
}

// unwrapMasterKey opens file bytes with passphrase. Any mismatch — magic,
// length, parameters, or authentication — is ErrKeyFile, never a fresh key.
func unwrapMasterKey(data, passphrase []byte) (MasterKey, error) {
	gen, err := keyFileGeneration(data)
	if err != nil {
		return MasterKey{}, err
	}
	logN := int(data[12])
	r := int(binary.BigEndian.Uint32(data[13:17]))
	p := int(binary.BigEndian.Uint32(data[17:21]))
	salt := data[21 : 21+kdfSaltLen]
	nonceStart := 21 + kdfSaltLen
	wrapKey, err := deriveWrapKey(passphrase, salt, logN, r, p)
	if err != nil {
		return MasterKey{}, err
	}
	defer clear(wrapKey)
	gcm, err := newAEAD(wrapKey)
	if err != nil {
		return MasterKey{}, err
	}
	nonce := data[nonceStart : nonceStart+gcm.NonceSize()]
	sealed := data[nonceStart+gcm.NonceSize():]
	key, err := gcm.Open(nil, nonce, sealed, keyFileAAD(gen))
	if err != nil {
		return MasterKey{}, fmt.Errorf("%w: contents did not authenticate", ErrKeyFile)
	}
	defer clear(key)
	return NewMasterKey(gen, key)
}

// InitMasterKey creates a new master key of generation gen and writes it,
// passphrase-wrapped, to path (ADR-0015). It never overwrites an existing key.
// It is the operator bootstrap (keys init); nothing on the store-open path can
// reach it, so opening a store can never create a key.
func InitMasterKey(path string, gen uint32, passphrase []byte) error {
	return initMasterKey(path, gen, passphrase, nil)
}

// initMasterKey generates a new master key of generation gen and writes it,
// passphrase-wrapped, to path. It creates the file exclusively (O_EXCL), so it
// never overwrites an existing key, and owner-only (0600). It is the only
// function that creates a master key; nothing on the store-open path can reach
// it (ADR-0015 §2).
func initMasterKey(path string, gen uint32, passphrase []byte, randr io.Reader) error {
	randr = randReader(randr)
	var key [keyLen]byte
	if _, err := io.ReadFull(randr, key[:]); err != nil {
		return err
	}
	defer clear(key[:])
	wrapped, err := wrapMasterKey(key, gen, passphrase, randr)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path is the operator-supplied master-key file, outside the data directory (ADR-0015)
	if err != nil {
		return fmt.Errorf("store: creating the master-key file: %w", err)
	}
	if _, err := f.Write(wrapped); err != nil {
		return errors.Join(fmt.Errorf("store: writing the master-key file: %w", err), f.Close())
	}
	return f.Close()
}

// randReader is crypto/rand unless a test overrides it.
func randReader(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}
