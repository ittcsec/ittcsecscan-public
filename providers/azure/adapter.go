package azure

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// tenantInfo is the non-secret slice of an ARM tenant the adapter needs. It is a
// small local type so the SDK's paged response does not leak into the adapter's
// logic or its tests.
type tenantInfo struct {
	tenantID    string
	displayName string
	home        bool // the credential's own (Home category) tenant
}

// tenantLister is the one ARM call the adapter makes: list the tenants the
// credential can see (Tenants - List, no RBAC role). It is an interface so tests
// inject a stub and never touch the network or the real SDK.
type tenantLister interface {
	list(ctx context.Context) ([]tenantInfo, error)
}

// Adapter implements auth.Resolver for Azure.
type Adapter struct {
	// loadCredential builds the Azure default credential chain (environment,
	// workload identity, managed identity, Azure CLI). Overridable in tests.
	loadCredential func() (azcore.TokenCredential, error)
	// newLister builds the tenant lister from a credential. Overridable in tests.
	newLister func(azcore.TokenCredential) (tenantLister, error)
}

// New returns an Azure adapter that authenticates through DefaultAzureCredential.
// It performs no I/O; the credential chain is resolved lazily on each Resolve.
func New() *Adapter {
	return &Adapter{
		loadCredential: func() (azcore.TokenCredential, error) {
			return azidentity.NewDefaultAzureCredential(nil)
		},
		newLister: func(cred azcore.TokenCredential) (tenantLister, error) {
			factory, err := armsubscriptions.NewClientFactory(cred, nil)
			if err != nil {
				return nil, err
			}
			return &armTenantLister{client: factory.NewTenantsClient()}, nil
		},
	}
}

// Resolve implements auth.Resolver. It establishes the caller's identity with
// the ARM Tenants - List operation, which needs no RBAC role and performs no
// write (Azure REST API reference, verified 2026-09-17). It returns the
// authenticated (Home) tenant as the account; the principal field carries the
// tenant's display name, not the specific user or service principal, which Azure
// does not expose at this permission level. Every failure is routed through
// auth.Fail, so no credential material escapes in an error.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolveCredential(ctx, p, prof)
	return id, err
}

// resolveCredential resolves the Azure credential chain exactly once and
// establishes the caller's identity from it, returning both. One resolution
// serves both the reported identity and the read-only collector clients, so what
// identity reports and what collection runs under can never diverge (ADR-0018
// §3), the same guarantee the AWS adapter gives.
//
// The identity call and the collection use different token scopes from this one
// credential: identity draws an ARM (management) token here, and the Entra
// collector draws a Microsoft Graph token from the same credential. That is one
// resolution, not one scope: the single-resolution guarantee is about the
// credential being resolved once, not about every call using the same scope
// (unlike AWS, where identity and collection happen to share the management
// plane). Every failure is routed through auth.Fail, so no credential material
// escapes in an error.
func (a *Adapter) resolveCredential(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, azcore.TokenCredential, error) {
	if p != model.Azure {
		return auth.Identity{}, nil, auth.Fail(p, prof, auth.KindUnknown,
			errors.New("azure adapter asked to resolve a non-azure provider"))
	}
	cred, err := a.loadCredential()
	if err != nil {
		return auth.Identity{}, nil, auth.Fail(p, prof, classify(err), err)
	}
	lister, err := a.newLister(cred)
	if err != nil {
		return auth.Identity{}, nil, auth.Fail(p, prof, classify(err), err)
	}
	tenants, err := lister.list(ctx)
	if err != nil {
		return auth.Identity{}, nil, auth.Fail(p, prof, classify(err), err)
	}
	t, ok := homeTenant(tenants)
	if !ok {
		return auth.Identity{}, nil, auth.Fail(p, prof, auth.KindUnknown,
			errors.New("the credential resolved no tenant"))
	}
	return auth.Identity{
		Provider:  model.Azure,
		Account:   t.tenantID,
		Principal: t.displayName, // the authenticated tenant, not a specific principal (see doc)
	}, cred, nil
}

// homeTenant returns the credential's own tenant: the one marked Home, or the
// first tenant if none is marked. ok is false when there are no tenants.
func homeTenant(tenants []tenantInfo) (tenantInfo, bool) {
	if len(tenants) == 0 {
		return tenantInfo{}, false
	}
	for _, t := range tenants {
		if t.home {
			return t, true
		}
	}
	return tenants[0], true
}

// classify maps an Azure error to a seam Kind. A 401 from ARM means the token is
// missing, expired, or invalid; a 403 means the credential authenticated but is
// not authorised; everything else, including a credential-acquisition failure,
// is KindUnknown, so an unclassified failure fails closed. A cancelled or
// timed-out context is unknown, not a provider denial.
func classify(err error) auth.Kind {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return auth.KindUnknown
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusUnauthorized:
			return auth.KindExpired
		case http.StatusForbidden:
			return auth.KindDenied
		}
	}
	return auth.KindUnknown
}

// armTenantLister is the production tenantLister: it drains the ARM Tenants -
// List pager into tenantInfo values.
type armTenantLister struct {
	client *armsubscriptions.TenantsClient
}

func (l *armTenantLister) list(ctx context.Context) ([]tenantInfo, error) {
	var out []tenantInfo
	pager := l.client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}
			out = append(out, tenantInfo{
				tenantID:    deref(t.TenantID),
				displayName: deref(t.DisplayName),
				home:        t.TenantCategory != nil && *t.TenantCategory == armsubscriptions.TenantCategoryHome,
			})
		}
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
