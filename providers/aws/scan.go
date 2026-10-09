package aws

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	awscollect "github.com/ittcsec/ittcsecscan/providers/aws/collect"
)

// Source is the AWS contribution to a scan: it resolves the caller identity and
// builds the AWS read-only collectors from the same authenticated config. It
// satisfies internal/scan.Source structurally, so this package keeps the SDK
// confined and needs no import of the orchestrator.
type Source struct {
	adapter *Adapter
}

// NewSource returns an AWS scan source authenticating through the SDK default
// credential chain (the same adapter Resolve uses). It performs no I/O.
func NewSource() *Source { return &Source{adapter: New()} }

// Provider reports the provider this source scans.
func (s *Source) Provider() model.Provider { return model.AWS }

// Collectors resolves the AWS identity and returns the account id and the AWS
// read-only collectors built with the authenticated config. The credential chain
// is resolved exactly once: the reported identity and the collector clients come
// from the same resolution, so they cannot drift across a token rotation. An
// authentication failure is returned as an error (the scan records it as a
// provider gap and continues with the other providers); it is never turned into
// an empty success. Identity is resolved with the discovery profile: a scan
// enumerates the graph, it does not read deep evidence or plan remediation.
func (s *Source) Collectors(ctx context.Context, budget *collect.Budget) (string, []collect.Collector, error) {
	id, cfg, err := s.adapter.resolveConfig(ctx, model.AWS, auth.Discovery)
	if err != nil {
		return "", nil, err
	}
	return id.Account, awscollect.Collectors(id.Account, cfg, budget), nil
}
