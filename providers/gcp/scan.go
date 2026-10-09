package gcp

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	gcpcollect "github.com/ittcsec/ittcsecscan/providers/gcp/collect"
)

// Source is the GCP contribution to a scan: it resolves the caller identity and
// builds the GCP read-only collectors from the same credential. It satisfies
// internal/scan.Source structurally, so this package keeps the client libraries
// confined and needs no import of the orchestrator.
type Source struct {
	adapter *Adapter
}

// NewSource returns a GCP scan source authenticating through Application Default
// Credentials (the same adapter Resolve uses). It performs no I/O.
func NewSource() *Source { return &Source{adapter: New()} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.GCP }

// Collectors resolves the GCP identity and returns the project id and the GCP
// read-only collectors built with the authenticated credential. The credential is
// resolved exactly once, with the identity and collection scopes together, so the
// reported identity and the collector clients come from the same resolution and
// cannot drift across a token rotation. An authentication failure is returned as
// an error (the scan records it as a provider gap and continues with the other
// providers); it is never turned into an empty success. Identity is resolved with
// the discovery profile: a scan enumerates the graph, it does not read deep
// evidence or plan remediation.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, tokens, err := s.adapter.resolveCredential(ctx, model.GCP, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, gcpcollect.Collectors(id.Account, tokens, budget), nil
}
