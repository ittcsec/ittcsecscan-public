package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"path"
	"testing"

	"github.com/ittcsec/ittcsecscan/packs"
)

// Every shipped built-in manifest must pin each rule by a digest that matches the rule file.
// The verifying load path (Load, used once a pack-signing key is embedded) checks these digests,
// so a missing or wrong digest would make a signed built-in pack fail to load. This guards the
// manifest so it stays signable and verifiable.
func TestShippedManifestDigestsMatchRuleFiles(t *testing.T) {
	entries, err := fs.ReadDir(packs.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	packsChecked, rulesChecked := 0, 0
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		mb, err := fs.ReadFile(packs.FS, path.Join(d.Name(), "manifest.json"))
		if err != nil {
			t.Fatalf("%s: reading manifest: %v", d.Name(), err)
		}
		var m Manifest
		if err := json.Unmarshal(mb, &m); err != nil {
			t.Fatalf("%s: decoding manifest: %v", d.Name(), err)
		}
		if len(m.Rules) == 0 {
			t.Errorf("%s: manifest pins no rules", d.Name())
		}
		for _, e := range m.Rules {
			if e.Digest == "" {
				t.Errorf("%s: rule %s has no digest in the manifest", d.Name(), e.File)
				continue
			}
			rb, err := fs.ReadFile(packs.FS, path.Join(d.Name(), e.File))
			if err != nil {
				t.Errorf("%s: reading rule %s: %v", d.Name(), e.File, err)
				continue
			}
			sum := sha256.Sum256(rb)
			if got := hex.EncodeToString(sum[:]); got != e.Digest {
				t.Errorf("%s: rule %s digest %s does not match the file %s", d.Name(), e.File, e.Digest, got)
			}
			rulesChecked++
		}
		packsChecked++
	}
	if packsChecked == 0 || rulesChecked == 0 {
		t.Fatalf("checked %d packs and %d rules; expected at least one of each", packsChecked, rulesChecked)
	}
}
