// Package collect holds the Kubernetes read-only collectors. They read a cluster's
// identity and RBAC graph over the Kubernetes REST API with plain HTTPS and JSON (no
// client-go, the same dependency-free choice as GCP, Azure, GitHub, and GitLab), and
// emit the provider-neutral nodes, edges, evidence, and completeness the collection
// framework defines. Every request is a GET; the collectors never write.
package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// maxResponseBytes caps a single page a collector will read, so a hostile or
// malfunctioning endpoint cannot exhaust memory.
const maxResponseBytes = 32 << 20

// API is the read-only Kubernetes REST surface a collector uses: fetch a path (relative
// to the API server base) and return the raw JSON body. Kubernetes paginates with a
// continue token carried in the response body (metadata.continue), so the caller reads
// the next page by re-requesting with that token; the client does not parse it. It is an
// interface so tests inject a stub and never touch the network or a real token.
type API interface {
	Get(ctx context.Context, path string) (body []byte, err error)
}

// k8sError is a non-2xx Kubernetes API response, carrying the HTTP status so a collector
// can classify denials and throttling. Its message is already redacted.
type k8sError struct {
	status int
	body   string
}

func (e *k8sError) Error() string { return fmt.Sprintf("kubernetes: HTTP %d: %s", e.status, e.body) }

// isDenied reports an access-denied response: 403 (RBAC forbids the read) or 401
// (unusable token mid-collection).
func isDenied(err error) bool {
	var ke *k8sError
	return errors.As(err, &ke) && (ke.status == http.StatusForbidden || ke.status == http.StatusUnauthorized)
}

// isThrottle reports a throttled response (429, the API server's priority-and-fairness
// rejection).
func isThrottle(err error) bool {
	var ke *k8sError
	return errors.As(err, &ke) && ke.status == http.StatusTooManyRequests
}

// k8sClient issues authenticated read-only GETs against the cluster API server with the
// resolved service account token over a CA-trusting HTTPS client.
type k8sClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient builds the read-only Kubernetes API client. httpClient must already trust the
// cluster CA (the adapter builds it from the mounted ca.crt).
func NewClient(baseURL, token string, httpClient *http.Client) API {
	return &k8sClient{baseURL: baseURL, token: token, http: httpClient}
}

func (c *k8sClient) Get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
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
		// The body is an API Status object that can echo request context; redact before
		// it is carried in an error.
		return nil, &k8sError{status: resp.StatusCode, body: redact.String(string(body))}
	}
	return body, nil
}

// listMeta is the list envelope's metadata: the continue token for the next page (empty
// when the listing is complete), doc-verified against the Kubernetes API concepts
// reference.
type listMeta struct {
	Continue string `json:"continue"`
}
