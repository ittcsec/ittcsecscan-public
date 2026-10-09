package update

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// TargetPath is the repository-relative path a target's content is fetched from. The
// target's trust name (the targets-metadata key) may contain characters that are not
// safe in a path, so content lives under targets/<safe-name>.bin; integrity is still
// checked against the trust name, so the path is untrusted and cannot smuggle content.
func TargetPath(name string) string { return "targets/" + safeName(name) + ".bin" }

// FetchAndVerifyTarget fetches a target's content and verifies its length and hash
// against the signed targets metadata before returning it. Nothing unverified is ever
// returned to the caller for installation.
func (c *Client) FetchAndVerifyTarget(f Fetcher, t *Targets, name string) (Target, []byte, error) {
	data, err := f.Fetch(TargetPath(name))
	if err != nil {
		return Target{}, nil, fmt.Errorf("fetch target %s: %w", name, err)
	}
	tgt, err := c.VerifyTarget(t, name, data)
	if err != nil {
		return Target{}, nil, err
	}
	return tgt, data, nil
}

// DirFetcher serves metadata and target files from a local directory: an offline
// bundle. It reads nothing outside the directory (path traversal is refused), so an
// offline update needs no network at all.
type DirFetcher struct{ dir string }

// NewDirFetcher returns a Fetcher backed by a local bundle directory.
func NewDirFetcher(dir string) *DirFetcher { return &DirFetcher{dir: dir} }

// Fetch reads a bundle file, refusing any name that escapes the bundle directory.
func (d *DirFetcher) Fetch(name string) ([]byte, error) {
	p := filepath.Join(d.dir, filepath.FromSlash(name))
	rel, err := filepath.Rel(d.dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("update: invalid bundle path %q", name)
	}
	return os.ReadFile(p) //nolint:gosec // G304: path is confined to the bundle directory (checked above)
}

// maxFetchBytes caps any single metadata or target download, so a hostile mirror
// cannot exhaust memory with an unbounded body.
const maxFetchBytes = 64 << 20

// HTTPFetcher fetches metadata and targets over HTTPS. It transmits no request body,
// no credentials, no cookies, and no inventory (not even installed versions): it only
// issues GETs with a minimal, anonymous, static User-Agent, so an update check reveals
// only that some client fetched public metadata (ADR-0030 section 6).
type HTTPFetcher struct {
	base   string
	client *http.Client
	ua     string
}

// NewHTTPFetcher returns an HTTPS-only fetcher for a repository base URL.
func NewHTTPFetcher(baseURL string) (*HTTPFetcher, error) {
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("update: repository URL must be https")
	}
	client := collect.BoundedHTTPClient()
	client.Timeout = 30 * time.Second // bounded overall timeout for the whole request
	return &HTTPFetcher{
		base:   strings.TrimRight(baseURL, "/"),
		client: client,
		ua:     "ittcsecscan-updater (" + runtime.GOOS + "/" + runtime.GOARCH + ")",
	}, nil
}

// Fetch issues a bare GET for name under the repository base and returns the
// length-capped body. It sets only a User-Agent and Accept header, never authorization
// or any request body.
func (h *HTTPFetcher) Fetch(name string) ([]byte, error) {
	url := h.base + "/" + name
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", h.ua)
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("update: fetch %s: status %d", name, resp.StatusCode)
	}
	return body, nil
}
