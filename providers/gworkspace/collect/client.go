// Package collect holds the Google Workspace read-only collectors. They read a customer's
// users and groups over the Admin SDK Directory API with plain HTTPS and JSON (no SDK, the
// same choice as GitHub, GitLab, GCP, Azure, and Okta), and emit the provider-neutral
// nodes, edges, evidence, and completeness the collection framework defines. Every request
// is a GET; the collectors never write.
package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

const (
	directoryBaseURL = "https://admin.googleapis.com/admin/directory/v1"
	customerAlias    = "my_customer"
	maxResponseBytes = 16 << 20
	pageSize         = 200
	maxPages         = 1000
)

var sharedHTTPClient = collect.BoundedHTTPClient()

type gwsError struct {
	status int
	body   string
}

func (e *gwsError) Error() string {
	return fmt.Sprintf("google workspace: HTTP %d: %s", e.status, e.body)
}

func isDenied(err error) bool {
	var ge *gwsError
	return errors.As(err, &ge) && (ge.status == http.StatusForbidden || ge.status == http.StatusUnauthorized)
}

func isThrottle(err error) bool {
	var ge *gwsError
	return errors.As(err, &ge) && ge.status == http.StatusTooManyRequests
}

// gwsAPI is the read-only Directory surface a collector uses: fetch a URL and return the
// raw JSON body. The Directory API paginates with a nextPageToken in the body, so the
// caller reads the next page by re-requesting with that token. It is an interface so tests
// inject a stub and never touch the network or a real token.
type gwsAPI interface {
	get(ctx context.Context, url string) (body []byte, err error)
}

type gwsClient struct {
	token string
	http  *http.Client
}

func (c *gwsClient) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &gwsError{status: resp.StatusCode, body: redact.String(string(body))}
	}
	return body, nil
}
