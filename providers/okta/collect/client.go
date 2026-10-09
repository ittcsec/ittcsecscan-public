// Package collect holds the Okta read-only collectors. They read an org's users and
// groups over the Okta Core API with plain HTTPS and JSON (no SDK, the same choice as
// GitHub, GitLab, GCP, and Azure), and emit the provider-neutral nodes, edges, evidence,
// and completeness the collection framework defines. Every request is a GET; the
// collectors never write.
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

// maxResponseBytes caps a single page a collector will read.
const maxResponseBytes = 16 << 20

// pageLimit is the page size requested from list endpoints.
const pageLimit = 200

// maxPages bounds how many pages a listing will follow.
const maxPages = 1000

var sharedHTTPClient = collect.BoundedHTTPClient()

// oktaError is a non-2xx Okta response, carrying the HTTP status. Its message is redacted.
type oktaError struct {
	status int
	body   string
}

func (e *oktaError) Error() string { return fmt.Sprintf("okta: HTTP %d: %s", e.status, e.body) }

func isDenied(err error) bool {
	var oe *oktaError
	return errors.As(err, &oe) && (oe.status == http.StatusForbidden || oe.status == http.StatusUnauthorized)
}

func isThrottle(err error) bool {
	var oe *oktaError
	return errors.As(err, &oe) && oe.status == http.StatusTooManyRequests
}

// oktaAPI is the read-only Okta surface a collector uses: fetch a URL and return the raw
// JSON body plus the next-page URL (from the Link header, "" if none). It is an interface
// so tests inject a stub and never touch the network or a real token.
type oktaAPI interface {
	get(ctx context.Context, url string) (body []byte, next string, err error)
}

type oktaClient struct {
	token string
	http  *http.Client
}

func (c *oktaClient) get(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
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
		return nil, "", &oktaError{status: resp.StatusCode, body: redact.String(string(body))}
	}
	return body, nextLink(resp.Header.Get("Link")), nil
}

// nextLink extracts the URL with rel="next" from an Okta Link header (RFC 5988), or ""
// when there is no next page. Okta paginates with the Link header, the same format GitHub
// and GitLab use.
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
