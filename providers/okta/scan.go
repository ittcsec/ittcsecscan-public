package okta

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
	oktacollect "github.com/ittcsec/ittcsecscan/providers/okta/collect"
)

// Source is the Okta contribution to a scan: it resolves the org identity and builds the
// read-only collectors from the same API token. It satisfies internal/scan.Source
// structurally.
type Source struct {
	adapter *Adapter
}

// NewSource returns an Okta scan source authenticating with an API token from the
// environment (the same adapter Resolve uses). It performs no I/O.
func NewSource(lookupEnv config.LookupEnv) *Source { return &Source{adapter: New(lookupEnv)} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.Okta }

// Collectors resolves the Okta identity and returns the org URL and the read-only
// collectors built with the same token. The token is resolved exactly once so the reported
// identity and the collector client cannot drift. An authentication failure is returned as
// an error (the scan records it as a provider gap and continues); it is never turned into
// an empty success. Identity is resolved with the discovery profile.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, org, token, err := s.adapter.resolveCreds(ctx, model.Okta, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, oktacollect.Collectors(org, token, budget), nil
}
