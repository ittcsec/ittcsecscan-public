package k8s

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
	k8scollect "github.com/ittcsec/ittcsecscan/providers/k8s/collect"
)

// Source is the Kubernetes contribution to a scan: it resolves the in-cluster identity
// and builds the read-only collectors from the same credential. It satisfies
// internal/scan.Source structurally.
type Source struct {
	adapter *Adapter
}

// NewSource returns a Kubernetes scan source authenticating with the in-cluster service
// account (the same adapter Resolve uses). It performs no I/O.
func NewSource(lookupEnv config.LookupEnv) *Source { return &Source{adapter: New(lookupEnv)} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.Kubernetes }

// Collectors resolves the cluster identity and returns the cluster (API server URL) and
// the Kubernetes read-only collectors built with the same credential. The credential is
// resolved exactly once so the reported identity and the collector client cannot drift.
// An authentication failure is returned as an error (the scan records it as a provider
// gap and continues); it is never turned into an empty success. Identity is resolved
// with the discovery profile.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, cfg, err := s.adapter.resolveConfig(ctx, model.Kubernetes, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	client := k8scollect.NewClient(cfg.baseURL, cfg.token, httpClientFor(cfg.caPool))
	return id.Account, k8scollect.Collectors(id.Account, client, budget), nil
}
