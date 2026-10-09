// Package gitlab is the GitLab provider: a read-only credential adapter and scan
// source that enter through the same auth, collector, evidence, and completeness
// contracts as the cloud and GitHub providers (ADR-0031). It extends the
// repository-to-pipeline-to-artifact-to-workload path to a second source-control
// and CI/CD system. It authenticates with a token (from the environment) and reads
// over plain HTTP with no SDK dependency, the same shape as the GitHub, GCP, and
// Azure plain-HTTP collectors.
//
// The base URL is gitlab.com; self-managed GitLab host support is a tracked
// follow-up (GL-1), symmetric with the GitHub provider's single-host scope.
package gitlab

import (
	"context"
	"encoding/json"
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

// apiBaseURL is the GitLab REST API base (v4). The adapter only ever issues the
// read-only GET /user identity probe.
const apiBaseURL = "https://gitlab.com/api/v4"

// identityClient is a bounded HTTP client for the identity probe (a single GET).
var identityClient = &http.Client{Timeout: 15 * time.Second}

// apiStatusError carries a non-2xx status from the identity probe so classify can
// map it to an auth.Kind. Its message names no token.
type apiStatusError struct{ status int }

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("gitlab: identity probe returned HTTP %d", e.status)
}

// Adapter implements auth.Resolver for GitLab.
type Adapter struct {
	// loadToken resolves the GitLab token. Overridable in tests. The default reads
	// GITLAB_TOKEN from the environment; the product never stores the token.
	loadToken func() (string, error)
	// introspect returns the authenticated username by calling GET /user. Overridable
	// in tests; it must never surface the raw token in its error.
	introspect func(ctx context.Context, token string) (username string, err error)
}

// New returns a GitLab adapter that authenticates with a token read from the given
// environment lookup (GITLAB_TOKEN). The lookup is injected because only the process
// entrypoint touches process state directly; the product never stores the token. It
// performs no I/O; the token is resolved lazily on each Resolve.
func New(lookupEnv config.LookupEnv) *Adapter {
	return &Adapter{
		loadToken:  func() (string, error) { return tokenFrom(lookupEnv) },
		introspect: introspectUser,
	}
}

func tokenFrom(lookupEnv config.LookupEnv) (string, error) {
	v, _ := lookupEnv("GITLAB_TOKEN")
	if v = strings.TrimSpace(v); v == "" {
		return "", errors.New("no GITLAB_TOKEN in the environment")
	}
	return v, nil
}

// Resolve implements auth.Resolver. It establishes the caller's identity with the
// read-only GET /user call, which performs no write, and returns a non-secret
// Identity naming the authenticated username. Every failure is routed through
// auth.Fail, so no token escapes in an error.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolveToken(ctx, p, prof)
	return id, err
}

// resolveToken resolves the token once and establishes the caller's identity from
// that same token, returning both, so the reported identity and the token the
// collectors run under cannot diverge (ADR-0018 §3). Every failure is routed
// through auth.Fail.
func (a *Adapter) resolveToken(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, string, error) {
	if p != model.GitLab {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown,
			errors.New("gitlab adapter asked to resolve a non-gitlab provider"))
	}
	token, err := a.loadToken()
	if err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown, err)
	}
	username, err := a.introspect(ctx, token)
	if err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, classify(err), err)
	}
	return auth.Identity{Provider: model.GitLab, Account: username, Principal: username}, token, nil
}

// introspectUser calls GET /user and returns the authenticated username. The token
// is sent as a bearer credential and never logged or returned.
func introspectUser(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBaseURL+"/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := identityClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &apiStatusError{status: resp.StatusCode}
	}
	var u struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", err
	}
	if u.Username == "" {
		return "", errors.New("gitlab: /user returned no username")
	}
	return u.Username, nil
}

// classify maps an identity-probe failure to an auth.Kind: 401 is an expired or
// invalid token, 403 is denied, anything else is unknown.
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
