package github

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
	githubcollect "github.com/ittcsec/ittcsecscan/providers/github/collect"
)

// Source is the GitHub contribution to a scan: it resolves the caller identity and
// builds the GitHub read-only collectors from the same token. It satisfies
// internal/scan.Source structurally, so this package keeps GitHub specifics
// confined and needs no import of the orchestrator.
type Source struct {
	adapter *Adapter
}

// NewSource returns a GitHub scan source authenticating with a token from the
// environment (the same adapter Resolve uses). It performs no I/O.
func NewSource(lookupEnv config.LookupEnv) *Source { return &Source{adapter: New(lookupEnv)} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.GitHub }

// Collectors resolves the GitHub identity and returns the authenticated login and
// the GitHub read-only collectors built with the same token. The token is resolved
// exactly once, so the reported identity and the collector clients come from the
// same resolution. An authentication failure is returned as an error (the scan
// records it as a provider gap and continues with the other providers); it is
// never turned into an empty success. Identity is resolved with the discovery
// profile: a scan enumerates the graph, it does not read deep evidence or plan
// remediation.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, token, err := s.adapter.resolveToken(ctx, model.GitHub, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, githubcollect.Collectors(id.Account, token, budget), nil
}
