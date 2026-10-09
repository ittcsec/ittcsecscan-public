package collect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func findNode(nodes []collect.Node, id string) (collect.Node, bool) {
	for _, n := range nodes {
		if n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

// The collector emits one mcp_server node per configured server, with transport and command
// but never the secret env or headers, and evidence carries only a sanitized summary.
func TestServersEmitsNodesWithoutSecrets(t *testing.T) {
	cfg := `{"mcpServers":{
		"local":{"command":"npx","args":["-y","srv"],"env":{"API_KEY":"sk-supersecret-value"}},
		"remote":{"type":"http","url":"https://mcp.example.com/api?token=leaked-token-value","headers":{"Authorization":"Bearer leaked-bearer"}}
	}}`
	read := func(string) ([]byte, error) { return []byte(cfg), nil }
	c := NewServersCollector("/home/u/.mcp.json", read, nil)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	local, ok := findNode(sink.Nodes, "mcp:server:local")
	if !ok || local.Type != model.NodeMCPServer || local.Attributes["transport"] != "stdio" || local.Attributes["command"] != "npx" {
		t.Fatalf("local server node wrong: %+v", local)
	}
	remote, ok := findNode(sink.Nodes, "mcp:server:remote")
	if !ok || remote.Attributes["transport"] != "http" || remote.Attributes["remote"] != "true" {
		t.Fatalf("remote server node wrong: %+v", remote)
	}
	// The remote URL must be sanitized: host/path kept, query (with the token) dropped.
	if got := remote.Attributes["url"]; got != "https://mcp.example.com/api" {
		t.Errorf("url not sanitized: %q", got)
	}
	// No secret material anywhere in the emitted nodes or evidence.
	for _, secret := range []string{"sk-supersecret-value", "leaked-token-value", "leaked-bearer"} {
		for _, n := range sink.Nodes {
			for k, v := range n.Attributes {
				if strings.Contains(v, secret) {
					t.Errorf("node %s attr %s leaked secret %q", n.NativeID, k, secret)
				}
			}
		}
		for _, e := range sink.Envelopes {
			if strings.Contains(string(e.Response), secret) {
				t.Errorf("evidence leaked secret %q: %s", secret, e.Response)
			}
		}
	}
	if len(sink.Completeness) != 1 || !sink.Completeness[0].Done() || sink.Completeness[0].Collected != 2 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

// A read failure is a represented Errored gap, not a silent empty and not a hard error.
func TestServersReadFailureIsGap(t *testing.T) {
	read := func(string) ([]byte, error) { return nil, errors.New("permission denied") }
	c := NewServersCollector("/nope", read, nil)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("read failure must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Errored {
		t.Errorf("expected Errored, got %+v", sink.Completeness)
	}
	if len(sink.Nodes) != 0 {
		t.Error("a failed read must emit no nodes")
	}
}

func TestSanitizeURL(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: these are test URLs exercising query stripping, not credentials
		"https://mcp.example.com/api?token=x": "https://mcp.example.com/api",
		"https://host":                        "https://host",
		"":                                    "",
		"::not a url":                         "",
	}
	for in, want := range cases {
		if got := sanitizeURL(in); got != want {
			t.Errorf("sanitizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}
