package pack

import (
	"crypto/ed25519"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// PackNamespace is the sshsig namespace for detection packs. It is distinct from the
// release and update namespaces (ADR-0009), so a signature made for one purpose can
// never validate a pack and a pack signature can never validate a release, an update,
// or a git object.
const PackNamespace = "ittcsecscan-pack"

// ErrBadSignature is returned for any pack-signature verification failure; callers
// treat every one the same way: refuse the pack (fail closed). It aliases the shared
// primitive's error so errors.Is keeps working across the extraction.
var ErrBadSignature = sshsig.ErrBadSignature

// Verify checks an armored sshsig over message against trusted Ed25519 keys in the
// pack namespace. It is the shared in-process verifier (internal/sshsig).
func Verify(trusted []ed25519.PublicKey, namespace string, message, armoredSig []byte) (ed25519.PublicKey, error) {
	return sshsig.Verify(trusted, namespace, message, armoredSig)
}

// ParseAuthorizedKey extracts the Ed25519 public key from one OpenSSH public-key line,
// the form used in an allowed_signers trust root.
func ParseAuthorizedKey(line string) (ed25519.PublicKey, error) {
	return sshsig.ParseAuthorizedKey(line)
}
