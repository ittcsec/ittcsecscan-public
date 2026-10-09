package mcp

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
	mcpcollect "github.com/ittcsec/ittcsecscan/providers/mcp/collect"
)

// Source is the MCP contribution to a scan: it resolves the config file and builds the
// read-only collector that inventories the configured MCP servers. It satisfies
// internal/scan.Source structurally.
type Source struct {
	adapter *Adapter
}

// NewSource returns an MCP scan source reading the config file named by MCP_CONFIG_FILE. It
// performs no I/O until Collectors.
func NewSource(lookupEnv config.LookupEnv) *Source { return &Source{adapter: New(lookupEnv)} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.MCP }

// Collectors resolves the config file and returns its path and the read-only collector. The
// path is resolved exactly once so the reported identity and the collector read the same
// file. A missing or unreadable file is returned as an error (a represented provider gap),
// never an empty success.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, path, err := s.adapter.resolvePath(ctx, model.MCP, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, mcpcollect.Collectors(path, s.adapter.readFile, budget), nil
}
