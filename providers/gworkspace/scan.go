package gworkspace

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
	gwscollect "github.com/ittcsec/ittcsecscan/providers/gworkspace/collect"
)

// Source is the Google Workspace contribution to a scan: it resolves the customer identity
// and builds the read-only collectors from the same bearer token. It satisfies
// internal/scan.Source structurally.
type Source struct {
	adapter *Adapter
}

// NewSource returns a Google Workspace scan source authenticating with a bearer token from
// the environment (the same adapter Resolve uses). It performs no I/O.
func NewSource(lookupEnv config.LookupEnv) *Source { return &Source{adapter: New(lookupEnv)} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.GoogleWorkspace }

// Collectors resolves the Workspace identity and returns the customer and the read-only
// collectors built with the same token. The token is resolved exactly once so the reported
// identity and the collector client cannot drift. An authentication failure is returned as
// an error; it is never turned into an empty success. Identity is resolved with the
// discovery profile.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, token, err := s.adapter.resolveToken(ctx, model.GoogleWorkspace, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, gwscollect.Collectors(id.Account, token, budget), nil
}
