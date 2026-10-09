package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// identityScope is the minimal scope that lets token introspection return the
// authenticated principal's email (Google authentication docs, 2026-09-17).
const identityScope = "https://www.googleapis.com/auth/userinfo.email"

// collectionScope is the OAuth scope the read-only collectors request. It is the
// broad cloud-platform scope, not a read-only-named scope, because the first
// collected read, IAM projects.serviceAccounts.list, accepts only
// cloud-platform (or the iam scope), never cloud-platform.read-only (Google IAM
// API reference, verified 2026-09-18). The OAuth scope is an upper bound on what
// a token could do; the actual read-only guarantee is enforced by the
// credential's granted IAM permissions, which the discovery permission template
// pins to read-only operations only (for example iam.serviceAccounts.list). The
// scope is broad; the permissions are not. This is documented for the operator in
// permissions/README.md and docs/cli.md, not only here.
const collectionScope = "https://www.googleapis.com/auth/cloud-platform"

// credentials is the non-secret part of Application Default Credentials the
// adapter needs, plus the token source it introspects. The access token from the
// source is transmitted to the introspection endpoint and never logged or
// returned.
type credentials struct {
	projectID string // the associated GCP project; may be empty
	tokens    oauth2.TokenSource
}

// Adapter implements auth.Resolver for GCP.
type Adapter struct {
	// loadADC resolves Application Default Credentials for the given scopes.
	// Overridable in tests. Scopes are bound at credential creation for GCP, so
	// the caller passes exactly the scopes that use of the credential needs.
	loadADC func(ctx context.Context, scopes ...string) (credentials, error)
	// introspect returns the authenticated principal's email by introspecting a
	// token from the source. Overridable in tests. It must never surface the raw
	// access token in its error.
	introspect func(ctx context.Context, ts oauth2.TokenSource) (string, error)
}

// New returns a GCP adapter that authenticates through Application Default
// Credentials. It performs no I/O; the credentials are resolved lazily.
func New() *Adapter {
	return &Adapter{
		loadADC: func(ctx context.Context, scopes ...string) (credentials, error) {
			creds, err := google.FindDefaultCredentials(ctx, scopes...)
			if err != nil {
				return credentials{}, err
			}
			return credentials{projectID: creds.ProjectID, tokens: creds.TokenSource}, nil
		},
		introspect: introspectTokeninfo,
	}
}

// Resolve implements auth.Resolver. It establishes the caller's identity by
// introspecting the Application Default Credentials access token at the OAuth 2.0
// tokeninfo endpoint, which needs no IAM permission and performs no write (Google
// authentication reference, verified 2026-09-17). Principal is the specific
// caller's email; Account is the credential's associated project, which may be
// empty. Resolve requests only the identity scope, so the zero-permission
// identity probe (auth plan) stays least-privilege; the scan path uses
// resolveCredential, which also requests the collection scope. Every failure is
// routed through auth.Fail, so no credential material, including the access
// token, escapes in an error.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolveWith(ctx, p, prof, identityScope)
	return id, err
}

// resolveCredential resolves Application Default Credentials exactly once, with
// the identity and collection scopes together, and establishes the caller's
// identity from that same credential, returning both (ADR-0018 §3). One
// resolution serves both the reported identity and the read-only collector
// clients, so what identity reports and what collection runs under cannot
// diverge.
//
// GCP binds OAuth scopes at credential creation, so serving both purposes from
// one credential means loading it once with both scopes: this is one resolution,
// not one scope. Unlike auth plan, which stays narrow at the identity scope, a
// scan needs the cloud-platform collection scope as well (see collectionScope for
// why it is broad and how read-only is nonetheless enforced).
func (a *Adapter) resolveCredential(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, oauth2.TokenSource, error) {
	id, creds, err := a.resolveWith(ctx, p, prof, identityScope, collectionScope)
	if err != nil {
		return auth.Identity{}, nil, err
	}
	return id, creds.tokens, nil
}

// resolveWith loads ADC once for the given scopes and introspects the resulting
// token for the principal email, returning the identity and the credentials.
// Every failure is routed through auth.Fail.
func (a *Adapter) resolveWith(ctx context.Context, p model.Provider, prof auth.Profile, scopes ...string) (auth.Identity, credentials, error) {
	if p != model.GCP {
		return auth.Identity{}, credentials{}, auth.Fail(p, prof, auth.KindUnknown,
			errors.New("gcp adapter asked to resolve a non-gcp provider"))
	}
	creds, err := a.loadADC(ctx, scopes...)
	if err != nil {
		return auth.Identity{}, credentials{}, auth.Fail(p, prof, classify(err), err)
	}
	email, err := a.introspect(ctx, creds.tokens)
	if err != nil {
		return auth.Identity{}, credentials{}, auth.Fail(p, prof, classify(err), err)
	}
	if email == "" {
		return auth.Identity{}, credentials{}, auth.Fail(p, prof, auth.KindUnknown,
			errors.New("token introspection returned no principal email"))
	}
	return auth.Identity{
		Provider:  model.GCP,
		Account:   creds.projectID, // may be empty: no associated default project (see doc)
		Principal: email,
	}, creds, nil
}

// tokeninfoEndpoint is Google's OAuth 2.0 token introspection endpoint.
const tokeninfoEndpoint = "https://oauth2.googleapis.com/tokeninfo" //nolint:gosec // G101: a public endpoint URL, not a credential

// tokeninfoClient bounds the introspection request so a hung endpoint cannot
// block a scan indefinitely when the caller's context has no deadline.
var tokeninfoClient = &http.Client{Timeout: 30 * time.Second}

// tokeninfoResponse is the subset of the tokeninfo JSON the adapter reads. The
// full response also carries scope, expiry, aud, and azp, which are not needed
// to name the principal.
type tokeninfoResponse struct {
	Email string `json:"email"`
}

// tokeninfoError carries the HTTP status of a non-200 tokeninfo response so
// classify can map it to a seam Kind. It deliberately holds no response body or
// token.
type tokeninfoError struct{ status int }

func (e *tokeninfoError) Error() string {
	return fmt.Sprintf("token introspection returned HTTP %d", e.status)
}

// introspectTokeninfo introspects the source's access token at the OAuth 2.0
// tokeninfo endpoint and returns the principal email. It uses a plain HTTP POST
// with the token in the form body, never the URL, and calls the endpoint
// directly rather than through google.golang.org/api, which would pull the gRPC
// and protobuf graphs for a single REST call (ADR-0017: minimal surface). The
// access token is never logged or placed in an error.
func introspectTokeninfo(ctx context.Context, ts oauth2.TokenSource) (string, error) {
	tok, err := ts.Token()
	if err != nil {
		return "", err
	}
	body := url.Values{"access_token": {tok.AccessToken}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokeninfoEndpoint, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tokeninfoClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &tokeninfoError{status: resp.StatusCode}
	}
	var info tokeninfoResponse
	if err := json.Unmarshal(data, &info); err != nil {
		return "", err
	}
	return info.Email, nil
}

// classify maps a GCP error to a seam Kind. A 401 from tokeninfo means the token
// is missing, expired, or invalid; a 403 means the credential authenticated but
// is not authorised; everything else, including a failure to find credentials,
// is KindUnknown, so an unclassified failure fails closed. A cancelled or
// timed-out context is unknown, not a provider denial.
func classify(err error) auth.Kind {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return auth.KindUnknown
	}
	var te *tokeninfoError
	if errors.As(err, &te) {
		switch te.status {
		case http.StatusUnauthorized:
			return auth.KindExpired
		case http.StatusForbidden:
			return auth.KindDenied
		}
	}
	return auth.KindUnknown
}
