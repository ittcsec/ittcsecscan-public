package azure

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	azurecollect "github.com/ittcsec/ittcsecscan/providers/azure/collect"
)

// Source is the Azure contribution to a scan: it resolves the caller identity
// and builds the Azure read-only collectors from the same credential. It
// satisfies internal/scan.Source structurally, so this package keeps the SDK
// confined and needs no import of the orchestrator.
type Source struct {
	adapter *Adapter
}

// NewSource returns an Azure scan source authenticating through
// DefaultAzureCredential (the same adapter Resolve uses). It performs no I/O.
func NewSource() *Source { return &Source{adapter: New()} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.Azure }

// Collectors resolves the Azure identity and returns the tenant id and the Azure
// read-only collectors built with the authenticated credential. The credential
// chain is resolved exactly once: the reported identity and the collector clients
// come from the same resolution, so they cannot drift across a token rotation,
// even though the identity call and the collection draw tokens for different
// scopes from that one credential. An authentication failure is returned as an
// error (the scan records it as a provider gap and continues with the other
// providers); it is never turned into an empty success. Identity is resolved with
// the discovery profile: a scan enumerates the graph, it does not read deep
// evidence or plan remediation.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, cred, err := s.adapter.resolveCredential(ctx, model.Azure, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, azurecollect.Collectors(id.Account, cred, budget), nil
}
