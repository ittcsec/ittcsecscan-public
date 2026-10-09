package pack

import (
	"crypto/ed25519"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// Test helpers for the pack loader's signature tests. The sshsig wire mechanics are
// tested in internal/sshsig; here we only need to mint keys and signatures.

func genKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// signArmored mints an armored sshsig via the shared primitive, for the pack tests.
func signArmored(t *testing.T, priv ed25519.PrivateKey, namespace, hashAlg string, message []byte) []byte {
	t.Helper()
	sig, err := sshsig.Sign(priv, namespace, hashAlg, message)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
