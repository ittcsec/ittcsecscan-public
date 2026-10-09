// Package okta is the Okta provider: a read-only credential adapter and scan source that
// enter through the same auth, collector, evidence, and completeness contracts as the
// cloud, source-control, and Kubernetes providers (ADR-0031). It extends the human and
// machine identity domain to an external identity provider. It authenticates with an
// Okta API token (from the environment) and reads over plain HTTPS with no SDK
// dependency, the same shape as the GitHub, GitLab, GCP, and Azure collectors.
package okta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// identityClient is a bounded HTTP client for the identity probe (a single GET).
var identityClient = &http.Client{Timeout: 15 * time.Second}

// apiStatusError carries a non-2xx status from the identity probe so classify can map it
// to an auth.Kind. Its message names no token.
type apiStatusError struct{ status int }

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("okta: identity probe returned HTTP %d", e.status)
}

// Adapter implements auth.Resolver for Okta.
type Adapter struct {
	// loadCreds resolves the Okta org URL and API token. Overridable in tests. The
	// default reads OKTA_ORG_URL and OKTA_API_TOKEN from the environment; the product
	// never stores the token.
	loadCreds func() (orgURL, token string, err error)
	// introspect confirms the token works by listing one user. Overridable in tests; it
	// must never surface the raw token in its error.
	introspect func(ctx context.Context, orgURL, token string) error
}

// New returns an Okta adapter that authenticates with an API token read from the given
// environment lookup (OKTA_ORG_URL, OKTA_API_TOKEN). The lookup is injected because only
// the process entrypoint touches process state directly; the product never stores the
// token. It performs no I/O; the credential is resolved lazily on each Resolve.
func New(lookupEnv config.LookupEnv) *Adapter {
	return &Adapter{
		loadCreds:  func() (string, string, error) { return credsFrom(lookupEnv) },
		introspect: introspectUsers,
	}
}

func credsFrom(lookupEnv config.LookupEnv) (string, string, error) {
	org, _ := lookupEnv("OKTA_ORG_URL")
	token, _ := lookupEnv("OKTA_API_TOKEN")
	org = strings.TrimRight(strings.TrimSpace(org), "/")
	token = strings.TrimSpace(token)
	if org == "" {
		return "", "", errors.New("no OKTA_ORG_URL in the environment")
	}
	if token == "" {
		return "", "", errors.New("no OKTA_API_TOKEN in the environment")
	}
	return org, token, nil
}

// Resolve implements auth.Resolver. It establishes the caller's identity with a read-only
// one-user list, which performs no write, and returns a non-secret Identity naming the
// Okta org. Every failure is routed through auth.Fail, so no token escapes in an error.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, _, err := a.resolveCreds(ctx, p, prof)
	return id, err
}

// resolveCreds resolves the credentials once and confirms them, returning the identity
// plus the org URL and token, so the reported identity and the collectors' client cannot
// diverge (ADR-0018 §3). Every failure is routed through auth.Fail.
func (a *Adapter) resolveCreds(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, string, string, error) {
	if p != model.Okta {
		return auth.Identity{}, "", "", auth.Fail(p, prof, auth.KindUnknown,
			errors.New("okta adapter asked to resolve a non-okta provider"))
	}
	org, token, err := a.loadCreds()
	if err != nil {
		return auth.Identity{}, "", "", auth.Fail(p, prof, auth.KindUnknown, err)
	}
	if err := a.introspect(ctx, org, token); err != nil {
		return auth.Identity{}, "", "", auth.Fail(p, prof, classify(err), err)
	}
	return auth.Identity{Provider: model.Okta, Account: org, Principal: org}, org, token, nil
}

// introspectUsers lists one user to confirm the token is valid and has the read scope. The
// token is sent as an SSWS credential and never logged or returned.
func introspectUsers(ctx context.Context, orgURL, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, orgURL+"/api/v1/users?limit=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "SSWS "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := identityClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return &apiStatusError{status: resp.StatusCode}
	}
	return nil
}

// classify maps an identity-probe failure to an auth.Kind: 401 is an expired or invalid
// token, 403 is denied, anything else is unknown.
func classify(err error) auth.Kind {
	var se *apiStatusError
	if errors.As(err, &se) {
		switch se.status {
		case http.StatusUnauthorized:
			return auth.KindExpired
		case http.StatusForbidden:
			return auth.KindDenied
		}
	}
	return auth.KindUnknown
}
