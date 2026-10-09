package auth

import (
	"context"
	"errors"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// Registry is the production Resolver: it dispatches to the credential adapter
// registered for a provider. It is the seam where the real AWS, Azure, and GCP
// adapters plug in under ADR-0017; until they do, a Registry has no adapters and
// therefore authenticates nothing.
//
// Fail closed: a provider with no registered adapter resolves to
// KindUnknown, never to a pass. An empty Registry, which is the production state
// today, reports every provider as unresolved. This is the honest pre-adapter
// behaviour, not a defect to paper over.
type Registry struct {
	resolvers map[model.Provider]Resolver
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{resolvers: make(map[model.Provider]Resolver)}
}

// Register installs res as the adapter for p, replacing any previous one. It is
// called during wiring, before the registry is used to resolve.
func (r *Registry) Register(p model.Provider, res Resolver) {
	r.resolvers[p] = res
}

// Providers returns the providers that have a registered adapter, in model
// order. Doctor uses it to report which providers ittcsecscan can even attempt
// to authenticate; it does not imply access has been verified.
func (r *Registry) Providers() []model.Provider {
	var out []model.Provider
	for _, p := range model.Providers {
		if _, ok := r.resolvers[p]; ok {
			out = append(out, p)
		}
	}
	return out
}

// Resolve implements Resolver by delegating to the registered adapter. With no
// adapter for p, or a cancelled context, it fails closed as KindUnknown.
func (r *Registry) Resolve(ctx context.Context, p model.Provider, prof Profile) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, fail(p, prof, KindUnknown, err)
	}
	res, ok := r.resolvers[p]
	if !ok {
		return Identity{}, fail(p, prof, KindUnknown, errNoResolver)
	}
	return res.Resolve(ctx, p, prof)
}

// errNoResolver is the cause when a provider has no registered adapter.
var errNoResolver = errors.New("no credential adapter is registered for this provider")
