// Package github is the GitHub provider: a read-only credential adapter and scan
// source that enter through the same auth, collector, evidence, and completeness
// contracts as the cloud providers (ADR-0031). GitHub is the head of the
// repository-to-pipeline-to-artifact-to-workload priority path. It authenticates
// with a token (from the environment) and reads over plain HTTP with no SDK
// dependency, the same shape as the GCP and Azure plain-HTTP collectors.
package github

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

// apiBaseURL is the GitHub REST API base. The adapter only ever issues the
// read-only GET /user identity probe, which needs no special scope.
const apiBaseURL = "https://api.github.com"

// identityClient is a bounded HTTP client for the identity probe (a single GET).
var identityClient = &http.Client{Timeout: 15 * time.Second}

// apiStatusError carries a non-2xx status from the identity probe so classify can
// map it to an auth.Kind. Its message names no token.
type apiStatusError struct{ status int }

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("github: identity probe returned HTTP %d", e.status)
}

// Adapter implements auth.Resolver for GitHub.
type Adapter struct {
	// loadToken resolves the GitHub token. Overridable in tests. The default reads
	// GITHUB_TOKEN from the environment; the product never stores the token.
	loadToken func() (string, error)
	// introspect returns the authenticated login by calling GET /user. Overridable
	// in tests; it must never surface the raw token in its error.
	introspect func(ctx context.Context, token string) (login string, err error)
}

// New returns a GitHub adapter that authenticates with a token read from the given
// environment lookup (GITHUB_TOKEN). The lookup is injected because only the process
// entrypoint touches process state directly; the product never stores the token. It
// performs no I/O; the token is resolved lazily on each Resolve.
func New(lookupEnv config.LookupEnv) *Adapter {
	return &Adapter{
		loadToken:  func() (string, error) { return tokenFrom(lookupEnv) },
		introspect: introspectUser,
	}
}

func tokenFrom(lookupEnv config.LookupEnv) (string, error) {
	v, _ := lookupEnv("GITHUB_TOKEN")
	if v = strings.TrimSpace(v); v == "" {
		return "", errors.New("no GITHUB_TOKEN in the environment")
	}
	return v, nil
}

// Resolve implements auth.Resolver. It establishes the caller's identity with the
// read-only GET /user call, which performs no write, and returns a non-secret
// Identity naming the authenticated login. Every failure is routed through
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
	if p != model.GitHub {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown,
			errors.New("github adapter asked to resolve a non-github provider"))
	}
	token, err := a.loadToken()
	if err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, auth.KindUnknown, err)
	}
	login, err := a.introspect(ctx, token)
	if err != nil {
		return auth.Identity{}, "", auth.Fail(p, prof, classify(err), err)
	}
	return auth.Identity{Provider: model.GitHub, Account: login, Principal: login}, token, nil
}

// introspectUser calls GET /user and returns the authenticated login. The token is
// sent as a bearer credential and never logged or returned.
func introspectUser(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBaseURL+"/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
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
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", err
	}
	if u.Login == "" {
		return "", errors.New("github: /user returned no login")
	}
	return u.Login, nil
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
