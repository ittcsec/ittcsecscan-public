// Package sshsig verifies OpenSSH signatures (PROTOCOL.sshsig), Ed25519, in
// process with the standard library (crypto/ed25519, crypto/sha256, crypto/sha512)
// and no new dependency, exactly the approach ADR-0009 named for the in-process
// verifier. It only verifies; signing keys are offline maintainer keys (ADR-0009
// custody).
//
// It is a shared primitive: the detection-pack loader (internal/rules/pack) and
// the secure updater (internal/update) both verify signatures with it, each in its
// own namespace, so a signature made for one purpose can never validate another.
package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// sshsigMagic is the 6-byte preamble of both the signature blob and the signed data
// (PROTOCOL.sshsig, verified 2026-09-22).
const sshsigMagic = "SSHSIG"

// ErrBadSignature is returned for any verification failure: a malformed armor or blob,
// a wrong namespace, an untrusted key, or a signature that does not verify. Callers
// treat every one the same way: refuse (fail closed).
var ErrBadSignature = errors.New("signature verification failed")

// ParseAuthorizedKey extracts the Ed25519 public key from one OpenSSH public-key line
// ("ssh-ed25519 <base64> [comment]"), the form used in an allowed_signers trust root.
// A non-Ed25519 or malformed line is an error.
func ParseAuthorizedKey(line string) (ed25519.PublicKey, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return nil, fmt.Errorf("not an ssh-ed25519 public key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("public key base64: %w", err)
	}
	r := &sshReader{buf: blob}
	if r.readString() != "ssh-ed25519" {
		return nil, fmt.Errorf("public key is not ssh-ed25519")
	}
	key := r.readBytes()
	if r.err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("malformed ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

// Verify checks an armored sshsig over message against a set of trusted Ed25519 keys and
// the expected namespace. It returns the key that verified, or ErrBadSignature. It
// verifies fully in process with the standard library and never shells out.
func Verify(trusted []ed25519.PublicKey, namespace string, message, armoredSig []byte) (ed25519.PublicKey, error) {
	blob, err := dearmor(armoredSig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	r := &sshReader{buf: blob}
	if magic := r.readFixed(len(sshsigMagic)); string(magic) != sshsigMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrBadSignature)
	}
	if ver := r.readUint32(); ver != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrBadSignature, ver)
	}
	pubBlob := r.readBytes()
	ns := r.readString()
	_ = r.readString() // reserved
	hashAlg := r.readString()
	sigBlob := r.readBytes()
	if r.err != nil {
		return nil, fmt.Errorf("%w: malformed blob: %w", ErrBadSignature, r.err)
	}

	if ns != namespace {
		return nil, fmt.Errorf("%w: namespace %q, want %q", ErrBadSignature, ns, namespace)
	}
	sigKey, err := parseEd25519FromBlob(pubBlob)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	sig, err := parseEd25519Signature(sigBlob)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}

	// The signer must be one of the trusted keys (constant-time comparison so an
	// untrusted key is not distinguishable by timing).
	var matched ed25519.PublicKey
	for _, t := range trusted {
		if len(t) == len(sigKey) && ed25519Equal(t, sigKey) {
			matched = t
			break
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("%w: signer key is not trusted", ErrBadSignature)
	}

	mh, err := hashMessage(hashAlg, message)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	signed := signedData(namespace, hashAlg, mh)
	if !ed25519.Verify(matched, signed, sig) {
		return nil, fmt.Errorf("%w: signature does not verify", ErrBadSignature)
	}
	return matched, nil
}

// Sign produces an armored sshsig over message in the given namespace and hash
// algorithm ("sha256" or "sha512"), the same wire form ssh-keygen -Y sign emits.
// It exists so signed metadata and test fixtures can be produced in process;
// production release and pack signing are done offline with an offline key
// (ADR-0009). Verify is the inverse.
func Sign(priv ed25519.PrivateKey, namespace, hashAlg string, message []byte) ([]byte, error) {
	mh, err := hashMessage(hashAlg, message)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signedData(namespace, hashAlg, mh))

	var sw sshWriter
	sw.writeString("ssh-ed25519")
	sw.writeBytes(sig)

	var pw sshWriter
	pw.writeString("ssh-ed25519")
	pw.writeBytes(priv.Public().(ed25519.PublicKey))

	var bw sshWriter
	bw.buf = append(bw.buf, sshsigMagic...)
	bw.writeUint32(1)
	bw.writeBytes(pw.buf)
	bw.writeString(namespace)
	bw.writeString("")
	bw.writeString(hashAlg)
	bw.writeBytes(sw.buf)
	return armor(bw.buf), nil
}

// armor wraps a raw sshsig blob in the SSH SIGNATURE PEM-like armor.
func armor(blob []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var lines []string
	for len(b64) > 70 {
		lines = append(lines, b64[:70])
		b64 = b64[70:]
	}
	lines = append(lines, b64)
	return []byte("-----BEGIN SSH SIGNATURE-----\n" + strings.Join(lines, "\n") + "\n-----END SSH SIGNATURE-----\n")
}

// signedData builds the blob that is actually signed: MAGIC + string(namespace) +
// string(reserved="") + string(hashAlg) + string(H(message)) (PROTOCOL.sshsig).
func signedData(namespace, hashAlg string, messageHash []byte) []byte {
	var w sshWriter
	w.buf = append(w.buf, sshsigMagic...)
	w.writeString(namespace)
	w.writeString("")
	w.writeString(hashAlg)
	w.writeBytes(messageHash)
	return w.buf
}

func hashMessage(alg string, message []byte) ([]byte, error) {
	switch alg {
	case "sha512":
		h := sha512.Sum512(message)
		return h[:], nil
	case "sha256":
		h := sha256.Sum256(message)
		return h[:], nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm %q", alg)
}

func parseEd25519FromBlob(blob []byte) (ed25519.PublicKey, error) {
	r := &sshReader{buf: blob}
	if r.readString() != "ssh-ed25519" {
		return nil, fmt.Errorf("public key is not ssh-ed25519")
	}
	key := r.readBytes()
	if r.err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("malformed ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

func parseEd25519Signature(blob []byte) ([]byte, error) {
	r := &sshReader{buf: blob}
	if r.readString() != "ssh-ed25519" {
		return nil, fmt.Errorf("signature is not ssh-ed25519")
	}
	sig := r.readBytes()
	if r.err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("malformed ed25519 signature")
	}
	return sig, nil
}

// dearmor strips the SSH SIGNATURE armor and returns the decoded blob.
func dearmor(armored []byte) ([]byte, error) {
	const begin = "-----BEGIN SSH SIGNATURE-----"
	const end = "-----END SSH SIGNATURE-----"
	s := string(armored)
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 || j < i {
		return nil, fmt.Errorf("missing SSH SIGNATURE armor")
	}
	body := s[i+len(begin) : j]
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		b.WriteString(strings.TrimSpace(line))
	}
	return base64.StdEncoding.DecodeString(b.String())
}

func ed25519Equal(a, b ed25519.PublicKey) bool { return bytes.Equal(a, b) }

// sshReader reads SSH wire types from a buffer: uint32 big-endian lengths and the bytes
// they prefix. On any short read err is set and subsequent reads yield zero values.
type sshReader struct {
	buf []byte
	err error
}

func (r *sshReader) readFixed(n int) []byte {
	if r.err != nil || len(r.buf) < n {
		r.err = fmt.Errorf("short read")
		return nil
	}
	out := r.buf[:n]
	r.buf = r.buf[n:]
	return out
}

func (r *sshReader) readUint32() uint32 {
	b := r.readFixed(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *sshReader) readBytes() []byte {
	n := r.readUint32()
	if r.err != nil {
		return nil
	}
	return r.readFixed(int(n))
}

func (r *sshReader) readString() string { return string(r.readBytes()) }

type sshWriter struct{ buf []byte }

func (w *sshWriter) writeBytes(b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b))) //nolint:gosec // G115: SSH string lengths are bounded by in-memory buffer sizes
	w.buf = append(w.buf, l[:]...)
	w.buf = append(w.buf, b...)
}

func (w *sshWriter) writeString(s string) { w.writeBytes([]byte(s)) }

func (w *sshWriter) writeUint32(n uint32) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], n)
	w.buf = append(w.buf, l[:]...)
}
