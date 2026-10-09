// Package collect holds the GitHub read-only collectors. They read an account's
// repository graph over the GitHub REST API with plain HTTP and JSON (no SDK, the
// same choice as GCP and Azure, ADR-0017), and emit the provider-neutral nodes,
// evidence, and completeness the collection framework defines. Every request is a
// GET; the collectors never write.
package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

const (
	// githubBaseURL is the GitHub REST API base. Collectors only issue GETs.
	githubBaseURL = "https://api.github.com"
	// apiVersion is sent as the X-GitHub-Api-Version header and recorded as evidence
	// provenance.
	apiVersion = "2022-11-28"
	// maxResponseBytes caps a single page a collector will read, so a hostile or
	// malfunctioning endpoint cannot exhaust memory.
	maxResponseBytes = 16 << 20
)

// sharedHTTPClient is the one bounded HTTP client every GitHub collector reuses
// (connection pooling preserved), matching AWS, Azure, and GCP.
var sharedHTTPClient = collect.BoundedHTTPClient()

// githubError is a non-2xx GitHub REST response, carrying the HTTP status so a
// collector can classify denials and throttling. Its message is already redacted.
type githubError struct {
	status int
	body   string
}

func (e *githubError) Error() string { return fmt.Sprintf("github: HTTP %d: %s", e.status, e.body) }

// isDenied reports an access-denied response: 403 (missing scope) or 401 (unusable
// token mid-collection).
func isDenied(err error) bool {
	var ge *githubError
	return errors.As(err, &ge) && (ge.status == http.StatusForbidden || ge.status == http.StatusUnauthorized)
}

// isThrottle reports a throttled response (429, or a 403 with a rate-limit body is
// left to a later backoff follow-up; 429 is the represented Partial gap for now).
func isThrottle(err error) bool {
	var ge *githubError
	return errors.As(err, &ge) && ge.status == http.StatusTooManyRequests
}

// githubAPI is the read-only GitHub REST surface a collector uses: fetch a URL and
// return the raw JSON body plus the URL of the next page (from the Link header, "" if
// none). It is an interface so tests inject a stub and never touch the network or a
// real token.
type githubAPI interface {
	get(ctx context.Context, url string) (body []byte, next string, err error)
}

// githubClient issues authenticated read-only GETs with the resolved token.
type githubClient struct {
	token string
	http  *http.Client
}

func (c *githubClient) get(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		// The body can echo request context and provider text; redact before it is
		// carried in an error.
		return nil, "", &githubError{status: resp.StatusCode, body: redact.String(string(body))}
	}
	return body, nextLink(resp.Header.Get("Link")), nil
}

// nextLink extracts the URL with rel="next" from a GitHub Link header, or "" when
// there is no next page. GitHub paginates with the Link header, not a body token.
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		segs := strings.Split(strings.TrimSpace(part), ";")
		if len(segs) < 2 {
			continue
		}
		url := strings.TrimSpace(segs[0])
		if !strings.HasPrefix(url, "<") || !strings.HasSuffix(url, ">") {
			continue
		}
		for _, p := range segs[1:] {
			if strings.TrimSpace(p) == `rel="next"` {
				return url[1 : len(url)-1]
			}
		}
	}
	return ""
}
