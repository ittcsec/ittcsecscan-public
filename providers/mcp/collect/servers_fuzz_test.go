package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// FuzzMCPConfigParsing drives arbitrary bytes through the MCP config collector. A malformed
// or hostile config must never panic (it becomes a represented Errored gap), and no secret
// (an env value or an authorization header) must ever reach a node or evidence, whatever the
// input shape (T-16, T-31).
func FuzzMCPConfigParsing(f *testing.F) {
	f.Add(`{"mcpServers":{"a":{"command":"npx","env":{"K":"sek"}}}}`)
	f.Add(`{"mcpServers":{"r":{"type":"http","url":"https://h/p?token=sek","headers":{"Authorization":"Bearer sek"}}}}`)
	f.Add(`{"mcpServers":{}}`)
	f.Add(`{`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, cfg string) {
		read := func(string) ([]byte, error) { return []byte(cfg), nil }
		c := NewServersCollector("/x", read, nil)
		var sink collect.Scan
		if err := c.Collect(context.Background(), &sink); err != nil {
			t.Fatalf("Collect returned a hard error (should be a represented gap) for %q: %v", cfg, err)
		}
		// The collector's config struct only reads type/command/url, so env values and
		// authorization headers are structurally unreadable. The remaining secret carrier is a
		// URL query string (e.g. ?token=...), which sanitizeURL strips: no emitted url may
		// contain one, for any input.
		for _, n := range sink.Nodes {
			if u := n.Attributes["url"]; strings.Contains(u, "?") {
				t.Fatalf("node %s emitted a url with a query string %q from config %q", n.NativeID, u, cfg)
			}
		}
	})
}
