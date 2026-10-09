package gitlab

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
	gitlabcollect "github.com/ittcsec/ittcsecscan/providers/gitlab/collect"
)

// Source is the GitLab contribution to a scan: it resolves the caller identity and
// builds the GitLab read-only collectors from the same authenticated token. It
// satisfies internal/scan.Source structurally.
type Source struct {
	adapter *Adapter
}

// NewSource returns a GitLab scan source authenticating with a token from the
// environment (the same adapter Resolve uses). It performs no I/O.
func NewSource(lookupEnv config.LookupEnv) *Source { return &Source{adapter: New(lookupEnv)} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.GitLab }

// Collectors resolves the GitLab identity and returns the account (username) and the
// GitLab read-only collectors built with the same token. The token is resolved
// exactly once so the reported identity and the collector clients cannot drift. An
// authentication failure is returned as an error (the scan records it as a provider
// gap and continues); it is never turned into an empty success. Identity is resolved
// with the discovery profile.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, token, err := s.adapter.resolveToken(ctx, model.GitLab, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, gitlabcollect.Collectors(id.Account, token, budget), nil
}
