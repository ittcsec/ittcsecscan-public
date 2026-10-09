package remediate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// CurrentStateHash is a deterministic fingerprint of an entity's current
// configuration state: its provider, type, and the sorted collected attributes
// and tags the rules read. A plan captures this at plan time; the executor
// recomputes it against freshly re-read state immediately before any apply, and
// any difference is drift that stops execution (ADR-0029 section 4). Identity
// (the native id) is deliberately excluded: it is stable and is not the config
// that a remediation changes.
func CurrentStateHash(e model.Entity) string {
	var b strings.Builder
	b.WriteString("provider\x00")
	b.WriteString(string(e.Provider))
	b.WriteString("\ntype\x00")
	b.WriteString(string(e.Type))
	b.WriteByte('\n')
	writeSortedMap(&b, "attr", e.Attributes)
	writeSortedMap(&b, "tag", e.Tags)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func writeSortedMap(b *strings.Builder, prefix string, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(prefix)
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
}

// planHash is the content hash of the canonical plan content: the value an
// approval binds to. json.Marshal is deterministic here (struct field order is
// fixed and the plan carries no maps), so identical plans hash alike.
func planHash(p model.RemediationPlan) string {
	raw, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
