// Package gworkspace is the Google Workspace provider: a read-only credential adapter and
// scan source that enter through the same auth, collector, evidence, and completeness
// contracts as the cloud, source-control, Kubernetes, and Okta providers (ADR-0031). It
// extends the human and machine identity domain to Google Workspace. It authenticates with
// an OAuth bearer token (from the environment) and reads the Admin SDK Directory API over
// plain HTTPS with no SDK dependency, the same shape as the GCP, Azure, GitHub, GitLab, and
// Okta collectors.
package gworkspace

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

// directoryBaseURL is the Admin SDK Directory API base. The adapter only issues the
// read-only one-user probe.
const directoryBaseURL = "https://admin.googleapis.com/admin/directory/v1"

// customerAlias is the Directory API alias for the caller's own Workspace account.
const customerAlias = "my_customer"

var identityClient = &http.Client{Timeout: 15 * time.Second}

type apiStatusError struct{ status int }

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("google workspace: identity probe returned HTTP %d", e.status)
}

// Adapter implements auth.Resolver for Google Workspace.
type Adapter struct {
	// loadToken resolves the OAuth bearer token. Overridable in tests. The default reads
	// GOOGLE_WORKSPACE_TOKEN from the environment; the product never stores the token.
	loadToken func() (string, error)
	// introspect confirms the token works by listing one user. Overridable in tests; it
	// must never surface the raw token in its error.
	introspect func(ctx context.Context, token string) error
}

// New returns a Google Workspace adapter that authenticates with a bearer token read from
// the given environment lookup (GOOGLE_WORKSPACE_TOKEN). The lookup is injected because
// only the process entrypoint touches process state directly; the product never stores the
// token. It performs no I/O; the token is resolved lazily on each Resolve.
func New(lookupEnv config.LookupEnv) *Adapter {
	return &Adapter{
		loadToken:  func() (string, error) { return tokenFrom(lookupEnv) },
		introspect: introspectUsers,
	}
}

func tokenFrom(lookupEnv config.LookupEnv) (string, error) {
	v, _ := lookupEnv("GOOGLE_WORKSPACE_TOKEN")
	if v = strings.TrimSpace(v); v == "" {
		return "", errors.New("no GOOGLE_WORKSPACE_TOKEN in the environment")
	}
	return v, nil
}

// Resolve implements auth.Resolver. It establishes the caller's identity with a read-only
// one-user list, which performs no write, and returns a non-secret Identity naming the
// Workspace customer. Every failure is routed through auth.Fail, so no token escapes.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolveToken(ctx, p, prof)
	return id, err
}

func (a *Adapter) resolveToken(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, string, error) {
	if p != model.GoogleWorkspace {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown,
			errors.New("google workspace adapter asked to resolve a non-google-workspace provider"))
	}
	token, err := a.loadToken()
	if err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown, err)
	}
	if err := a.introspect(ctx, token); err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, classify(err), err)
	}
	return auth.Identity{Provider: model.GoogleWorkspace, Account: customerAlias, Principal: "google-workspace-directory"}, token, nil
}

// introspectUsers lists one user to confirm the token is valid and has the read scope. The
// token is sent as a bearer credential and never logged or returned.
func introspectUsers(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryBaseURL+"/users?customer="+customerAlias+"&maxResults=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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
