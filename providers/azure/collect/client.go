package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// sharedHTTPClient is the one bounded HTTP client every Azure collector's REST
// client reuses (connection pooling preserved), so an unreachable endpoint fails
// fast instead of hanging. One definition, shared, matching GCP and AWS.
var sharedHTTPClient = collect.BoundedHTTPClient()

// azureError is a non-2xx Azure REST response (Microsoft Graph or Azure Resource
// Manager), carrying the HTTP status so a collector can classify denials and
// throttling. Its message is already redacted.
type azureError struct {
	status int
	body   string
}

func (e *azureError) Error() string { return fmt.Sprintf("azure: HTTP %d: %s", e.status, e.body) }

// isDenied reports an access-denied response: a 403 (missing permission) or a 401
// (an unusable token mid-collection).
func isDenied(err error) bool {
	var ae *azureError
	return errors.As(err, &ae) && (ae.status == http.StatusForbidden || ae.status == http.StatusUnauthorized)
}

// isThrottle reports a throttled response (429). Retry-with-backoff is a noted
// follow-up; for now a throttle is a represented Partial gap.
func isThrottle(err error) bool {
	var ae *azureError
	return errors.As(err, &ae) && ae.status == http.StatusTooManyRequests
}

// azureGet mints a token for scope from the shared credential and issues one
// read-only GET, returning the body or an *azureError (redacted). It is shared by
// the Graph (Entra) and Resource Manager (RBAC) collectors, which differ only in
// their base URL and token scope, so the token, header, body-cap, and redaction
// handling live in one place.
func azureGet(ctx context.Context, cred azcore.TokenCredential, httpc *http.Client, scope, url string) ([]byte, error) {
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// The body can echo the request and provider text; redact before it is
		// carried in an error.
		return nil, &azureError{status: resp.StatusCode, body: redact.String(string(body))}
	}
	return body, nil
}
