// Package collect holds the MCP read-only collector. It reads the standard mcpServers
// configuration file and emits one mcp_server node per configured server, with no SDK
// dependency. It reads the file but emits only non-secret structural fields (name,
// transport, command, sanitized URL); it never emits the env values or authorization
// headers a server entry may hold, and it never records the raw file as evidence.
package collect

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const serversCollectorID = "collector:mcp.servers"

// ServersCollector reads the mcpServers config and emits the configured servers as
// mcp_server nodes. The configured MCP servers are the external tools an AI client on this
// host is allowed to invoke, a real supply-chain surface.
type ServersCollector struct {
	path     string
	readFile func(string) ([]byte, error)
	budget   *collect.Budget
}

// NewServersCollector builds the collector for the given config file path.
func NewServersCollector(path string, readFile func(string) ([]byte, error), budget *collect.Budget) *ServersCollector {
	return &ServersCollector{path: path, readFile: readFile, budget: budget}
}

func (c *ServersCollector) ID() string               { return serversCollectorID }
func (c *ServersCollector) Provider() model.Provider { return model.MCP }

func serversRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.MCP, Profile: permissions.Discovery, Permission: "read:mcp-config", By: serversCollectorID},
	}
}

func init() {
	for _, r := range serversRequirements() {
		permissions.Declare(r)
	}
}

func (c *ServersCollector) Requirements() []permissions.Requirement { return serversRequirements() }

// mcpConfig is the subset of the mcpServers config the collector reads. The env and headers
// (which hold secrets) are deliberately not modeled here so they cannot be emitted.
type mcpConfig struct {
	MCPServers map[string]struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		URL     string `json:"url"`
	} `json:"mcpServers"`
}

// Collect reads and parses the config file and emits one mcp_server node per server. A
// read or parse failure is a represented Errored gap, never a silent empty.
func (c *ServersCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "servers"
	scope := collect.Scope{Account: c.path}
	if err := ctx.Err(); err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Reason: "cancelled"})
		return err
	}
	if !c.budget.Spend() {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Reason: "budget exhausted"})
	}
	body, err := c.readFile(c.path)
	if err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Errored, Reason: redact.String(err.Error())})
		return nil
	}
	var cfg mcpConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Errored, Reason: redact.String(err.Error())})
		return nil
	}

	// Evidence is a sanitized summary (name + transport only), never the raw file, which
	// can hold secret env values and authorization headers.
	type summary struct {
		Name      string `json:"name"`
		Transport string `json:"transport"`
	}
	var summaries []summary
	count := 0
	for name, s := range cfg.MCPServers {
		if name == "" {
			continue
		}
		transport := transportOf(s.Type, s.Command, s.URL)
		_ = sink.Node(collect.Node{
			Type: model.NodeMCPServer, NativeID: "mcp:server:" + name, Name: name,
			Attributes: attrs(
				"transport", transport,
				"command", s.Command,
				"url", sanitizeURL(s.URL),
				"remote", boolAttr(s.URL != ""),
			),
		})
		summaries = append(summaries, summary{Name: name, Transport: transport})
		count++
	}
	sumJSON, _ := json.Marshal(summaries)
	_ = sink.Evidence(collect.Envelope{
		Provider: model.MCP, Service: service, Operation: "mcp.config.read", Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(sumJSON),
		Provenance: collect.Provenance{APIVersion: "mcpServers", Collector: serversCollectorID},
	})
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Complete, Collected: count})
}

// transportOf returns the server's transport: the declared type, else inferred from
// whether it is launched by a command (stdio) or reached at a URL (remote http).
func transportOf(declared, command, u string) string {
	if declared != "" {
		return declared
	}
	if u != "" {
		return "http"
	}
	if command != "" {
		return "stdio"
	}
	return ""
}

// sanitizeURL returns a remote server's URL with the query string dropped (it can carry a
// token) and only the scheme, host, and path kept. A URL that does not parse yields "".
func sanitizeURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func attrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
