// Package mcp is the MCP (Model Context Protocol) provider: a read-only adapter and scan
// source that inventory the MCP servers configured for an AI client on this host. Unlike
// the API providers, the source is a local configuration file (there is no remote "list
// MCP servers" API); the standard mcpServers config format is the real, doc-verified
// source. It reads the file with no SDK dependency and enters through the same collector,
// evidence, and completeness contracts as every other provider (ADR-0031). It never emits
// the secret material (env values, authorization headers) a server config may hold.
package mcp

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// Adapter implements auth.Resolver for the MCP config source. There is no credential: the
// "identity" is the configuration file this host exposes. The adapter confirms the file is
// present and readable.
type Adapter struct {
	// loadPath resolves the MCP config file path. Overridable in tests. The default reads
	// MCP_CONFIG_FILE from the environment.
	loadPath func() (string, error)
	// readFile reads a file. Overridable in tests.
	readFile func(string) ([]byte, error)
}

// New returns an MCP adapter that reads the config file named by MCP_CONFIG_FILE from the
// given environment lookup. The lookup is injected because only the process entrypoint
// touches process state directly. It performs no I/O until Resolve.
func New(lookupEnv config.LookupEnv) *Adapter {
	return &Adapter{
		loadPath: func() (string, error) { return pathFrom(lookupEnv) },
		readFile: os.ReadFile,
	}
}

func pathFrom(lookupEnv config.LookupEnv) (string, error) {
	v, _ := lookupEnv("MCP_CONFIG_FILE")
	if v = strings.TrimSpace(v); v == "" {
		return "", errors.New("no MCP_CONFIG_FILE in the environment")
	}
	return v, nil
}

// Resolve implements auth.Resolver. It confirms the MCP config file is present and readable
// and returns a non-secret Identity naming the file. Every failure is routed through
// auth.Fail.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolvePath(ctx, p, prof)
	return id, err
}

// resolvePath resolves and reads the config path once, returning the identity and the path,
// so the reported identity and the collector read the same file.
func (a *Adapter) resolvePath(_ context.Context, p model.Provider, prof auth.Profile) (auth.Identity, string, error) {
	if p != model.MCP {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown,
			errors.New("mcp adapter asked to resolve a non-mcp provider"))
	}
	path, err := a.loadPath()
	if err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown, err)
	}
	if _, err := a.readFile(path); err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown, err)
	}
	return auth.Identity{Provider: model.MCP, Account: path, Principal: "mcp-config"}, path, nil
}
