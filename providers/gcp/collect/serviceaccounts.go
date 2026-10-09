// Package collect holds the GCP read-only collectors. They read a project's
// identity graph through the credential the identity adapter already resolved,
// and emit the provider-neutral nodes, evidence, and completeness the collection
// framework defines.
//
// GCP resources are read over their REST APIs with plain HTTP and JSON, not the
// generated client libraries: those pull the gRPC and protobuf graphs for what
// here is a couple of REST calls, and a bearer token from the shared OAuth token
// source plus net/http is lighter and fully sufficient (ADR-0017, and the same
// choice made for GCP identity and for Azure). The GCP client libraries stay
// confined to providers/gcp (ADR-0016 §1).
//
// This first collector inventories the project's machine identities (service
// accounts). GCP's human and group identities appear only inside the project IAM
// policy, whose members, roles, and bindings carry value only together; that
// whole policy graph is its own next collector rather than being split into
// nodes here and edges later (unlike AWS and Azure, whose directory-style dumps
// did decompose that way).
package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// identityCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const identityCollectorID = "collector:gcp.iam.serviceaccounts"

const (
	// iamBaseURL is the GCP IAM v1 REST endpoint. The collector only ever issues
	// GETs against the read-only list resource below.
	iamBaseURL = "https://iam.googleapis.com/v1"
	// iamAPIVersion is recorded as evidence provenance.
	iamAPIVersion = "v1"
	// pageSize is the service-account page size the collector requests.
	pageSize = 100
	// maxPages bounds how many pages the collector will follow, so an endpoint
	// that returns a non-empty nextPageToken forever cannot hang the scan. Hitting
	// it is a represented Partial gap, never a silent stop. At pageSize 100 this is
	// 100k service accounts, far above any real project.
	maxPages = 1000
	// maxResponseBytes caps a single page the collector will read, so a hostile or
	// malfunctioning endpoint cannot exhaust memory.
	maxResponseBytes = 16 << 20
)

// sharedHTTPClient is the one bounded HTTP client every GCP collector's REST
// client reuses (connection pooling preserved), so an unreachable endpoint fails
// fast instead of hanging. One definition, shared, matching Azure and AWS.
var sharedHTTPClient = collect.BoundedHTTPClient()

// gcpAPI is the read-only GCP REST surface the collector uses: fetch a list URL
// (the base resource, then each page) and return the raw JSON body. It is an
// interface so tests inject a stub and never touch the network, a real token, or
// the client libraries.
type gcpAPI interface {
	get(ctx context.Context, url string) ([]byte, error)
}

// IdentityCollector reads a GCP project's service accounts: the project's machine
// identities. The read was verified against the IAM API reference (v1,
// 2026-09-18): projects.serviceAccounts.list is a read-only GET, paginated by
// pageToken/nextPageToken, requiring iam.serviceAccounts.list, and it returns no
// secret value (service-account keys are a separate resource this never reads).
type IdentityCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewIdentityCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3). The token
// source is the same one the identity adapter used, so identity and collection
// cannot come from two different resolutions. budget is the scan's shared call
// cap (nil is unlimited).
func NewIdentityCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *IdentityCollector {
	return &IdentityCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newIdentityCollector is the injectable constructor tests use with a stub API.
// It has no budget (unlimited); a test that needs one sets the field.
func newIdentityCollector(projectID string, api gcpAPI) *IdentityCollector {
	return &IdentityCollector{projectID: projectID, api: api}
}

func (c *IdentityCollector) ID() string               { return identityCollectorID }
func (c *IdentityCollector) Provider() model.Provider { return model.GCP }

// identityRequirements are the read-only IAM permissions this collector needs,
// credited to it. They are registered at init so the templates reconcile against
// real code (ADR-0016). The OAuth scope the scan requests is broader than these
// permissions (see the adapter's collectionScope); it is these permissions, not
// the scope, that keep the collection read-only.
func identityRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "iam.serviceAccounts.list", By: identityCollectorID},
	}
}

func init() {
	for _, r := range identityRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *IdentityCollector) Requirements() []permissions.Requirement { return identityRequirements() }

// Collect reads the project and its service accounts, emitting nodes, evidence,
// and completeness. IAM service accounts are a global (project-wide) resource, so
// there is one region: "global". Multi-project and organization-hierarchy
// enumeration is a noted follow-up; this collector scopes to the credential's
// resolved project.
func (c *IdentityCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		// No project to scope to: the credential has no associated default
		// project. That is a represented gap, not a silent empty and not an error.
		return sink.Complete(collect.Completeness{
			Service: "iam.serviceAccounts", Region: collect.Global, Scope: c.scope(),
			Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to",
		})
	}
	if err := sink.Node(collect.Node{Type: model.NodeProject, NativeID: c.projectID}); err != nil {
		return err
	}
	return c.serviceAccounts(ctx, sink)
}

// serviceAccounts reads the project's service accounts fully, following
// nextPageToken, and records completeness. A denied or throttled read is an
// expected, represented gap (Denied or Partial); an unexpected error is surfaced.
// A read is never reported Complete when a page failed.
func (c *IdentityCollector) serviceAccounts(ctx context.Context, sink collect.Sink) error {
	const service = "iam.serviceAccounts"
	base := fmt.Sprintf("%s/projects/%s/serviceAccounts", iamBaseURL, url.PathEscape(c.projectID))
	pageToken := ""
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			// The endpoint kept returning a next-page token past the bound: stop
			// and record the gap rather than following it forever.
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "page limit reached"})
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return nil
		}
		u := fmt.Sprintf("%s?pageSize=%d", base, pageSize)
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence("serviceAccounts.list", body))
		var page serviceAccountPage
		if err := json.Unmarshal(body, &page); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, sa := range page.Accounts {
			_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: sa.Email, Name: sa.DisplayName,
				Attributes: attrs("unique_id", sa.UniqueID, "oauth2_client_id", sa.Oauth2ClientID, "disabled", boolAttr(sa.Disabled))})
		}
		count += len(page.Accounts)
		if page.NextPageToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return nil
		}
		pageToken = page.NextPageToken
	}
}

// serviceAccountPage is the subset of the projects.serviceAccounts.list response
// the collector reads.
type serviceAccountPage struct {
	Accounts []struct {
		Email          string `json:"email"`
		DisplayName    string `json:"displayName"`
		UniqueID       string `json:"uniqueId"`
		Oauth2ClientID string `json:"oauth2ClientId"`
		Disabled       *bool  `json:"disabled"`
	} `json:"accounts"`
	NextPageToken string `json:"nextPageToken"`
}

func (c *IdentityCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

// evidence builds a redacted, secret-free envelope for one read. The raw JSON
// body is the evidence; it still passes through redaction as defence in depth
// even though the read returns no secret value.
func (c *IdentityCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "iam", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: identityCollectorID},
	}
}

// completeness classifies a GCP error into a completeness record with a redacted
// reason.
func (c *IdentityCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{
		Service: service, Region: collect.Global, Scope: c.scope(),
		Status: status, Collected: collected, Reason: redact.String(err.Error()),
	}
}

// gcpError is a non-2xx GCP REST response, carrying the HTTP status and the
// google.rpc error reason so the collector can tell an access denial from a
// disabled API, and classify throttling. Its message is already redacted.
type gcpError struct {
	status int
	reason string // the google.rpc ErrorInfo reason, e.g. SERVICE_DISABLED
	body   string
}

func (e *gcpError) Error() string { return fmt.Sprintf("gcp: HTTP %d: %s", e.status, e.body) }

// errorReason extracts the google.rpc ErrorInfo reason from a GCP error body (for
// example SERVICE_DISABLED), so a disabled API can be told apart from an
// access-control denial. It is parsed from the raw body before redaction; an
// unparseable body yields "".
func errorReason(body []byte) string {
	var b struct {
		Error struct {
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &b) == nil {
		for _, d := range b.Error.Details {
			if d.Reason != "" {
				return d.Reason
			}
		}
	}
	return ""
}

// isServiceDisabled reports a 403 whose cause is that the API is not enabled on
// the project (SERVICE_DISABLED), which is not an access-control denial: the
// remediation is to enable the API, not to grant a permission. It is recorded as
// Unsupported, not Denied.
func isServiceDisabled(err error) bool {
	var ge *gcpError
	return errors.As(err, &ge) && ge.status == http.StatusForbidden && ge.reason == "SERVICE_DISABLED"
}

// isDenied reports an access-denied GCP response: a missing IAM permission is 403
// (403 PERMISSION_DENIED), and a 401 is an unusable token mid-collection. A 403
// whose reason is that the API is disabled is not a denial (see
// isServiceDisabled) and is excluded.
func isDenied(err error) bool {
	var ge *gcpError
	return errors.As(err, &ge) &&
		(ge.status == http.StatusForbidden || ge.status == http.StatusUnauthorized) &&
		ge.reason != "SERVICE_DISABLED"
}

// isThrottle reports a throttled GCP response (429). Retry-with-backoff is a
// noted follow-up; for now a throttle is a represented Partial gap.
func isThrottle(err error) bool {
	var ge *gcpError
	return errors.As(err, &ge) && ge.status == http.StatusTooManyRequests
}

// gcpClient is the production gcpAPI: it authenticates with a bearer token from
// the shared token source and issues read-only GETs.
type gcpClient struct {
	tokens oauth2.TokenSource
	http   *http.Client
}

func (g *gcpClient) get(ctx context.Context, url string) ([]byte, error) {
	return gcpDo(ctx, g.http, g.tokens, http.MethodGet, url, nil)
}

// gcpDo issues one authenticated request to a GCP REST endpoint and returns the
// body, or a *gcpError for a non-200 (with the body redacted). It is shared by
// the GET collectors and the getIamPolicy POST, so the token, header, body-cap,
// and redaction handling live in one place.
func gcpDo(ctx context.Context, httpc *http.Client, tokens oauth2.TokenSource, method, url string, body []byte) ([]byte, error) {
	tok, err := tokens.Token()
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// The body can echo the request and provider text; parse the reason from
		// the raw body, then redact before it is carried in an error.
		return nil, &gcpError{status: resp.StatusCode, reason: errorReason(data), body: redact.String(string(data))}
	}
	return data, nil
}

func attrs(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func boolAttr(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}
