// Package collect holds the GitLab read-only collectors. They read an account's
// project graph over the GitLab REST API (v4) with plain HTTP and JSON (no SDK, the
// same choice as GitHub, GCP, and Azure, ADR-0017 and ADR-0031), and emit the
// provider-neutral nodes, evidence, and completeness the collection framework
// defines. Every request is a GET; the collectors never write.
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
	// gitlabBaseURL is the GitLab REST API base (v4). Collectors only issue GETs.
	gitlabBaseURL = "https://gitlab.com/api/v4"
	// maxResponseBytes caps a single page a collector will read, so a hostile or
	// malfunctioning endpoint cannot exhaust memory.
	maxResponseBytes = 16 << 20
)

// sharedHTTPClient is the one bounded HTTP client every GitLab collector reuses
// (connection pooling preserved), matching GitHub, AWS, Azure, and GCP.
var sharedHTTPClient = collect.BoundedHTTPClient()

// gitlabError is a non-2xx GitLab REST response, carrying the HTTP status so a
// collector can classify denials and throttling. Its message is already redacted.
type gitlabError struct {
	status int
	body   string
}

func (e *gitlabError) Error() string { return fmt.Sprintf("gitlab: HTTP %d: %s", e.status, e.body) }

// isDenied reports an access-denied response: 403 (missing scope) or 401 (unusable
// token mid-collection).
func isDenied(err error) bool {
	var ge *gitlabError
	return errors.As(err, &ge) && (ge.status == http.StatusForbidden || ge.status == http.StatusUnauthorized)
}

// isThrottle reports a throttled response (429).
func isThrottle(err error) bool {
	var ge *gitlabError
	return errors.As(err, &ge) && ge.status == http.StatusTooManyRequests
}

// gitlabAPI is the read-only GitLab REST surface a collector uses: fetch a URL and
// return the raw JSON body plus the URL of the next page (from the Link header, "" if
// none). It is an interface so tests inject a stub and never touch the network or a
// real token.
type gitlabAPI interface {
	get(ctx context.Context, url string) (body []byte, next string, err error)
}

// gitlabClient issues authenticated read-only GETs with the resolved token.
type gitlabClient struct {
	token string
	http  *http.Client
}

func (c *gitlabClient) get(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
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
		return nil, "", &gitlabError{status: resp.StatusCode, body: redact.String(string(body))}
	}
	return body, nextLink(resp.Header.Get("Link")), nil
}

// nextLink extracts the URL with rel="next" from a GitLab Link header, or "" when
// there is no next page. GitLab paginates offset pages with the RFC 5988 Link header,
// the same format GitHub uses.
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
