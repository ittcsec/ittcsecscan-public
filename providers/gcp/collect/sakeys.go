package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// serviceAccountKeyCollectorID is the stable id this collector is credited with.
const serviceAccountKeyCollectorID = "collector:gcp.iam.serviceAccountKeys"

// svcServiceAccountKeys is the completeness service for the key enumeration.
const svcServiceAccountKeys = "iam.serviceAccountKeys"

// ServiceAccountKeyCollector reads the age of each service account's user-managed
// keys: the long-lived, downloadable private keys that are GCP's highest-risk
// standing credential (a system-managed key is Google-held and auto-rotated, so
// this collector reads only user-managed keys). An old or undisabled user-managed
// key is a rotation and exfiltration risk; the key-list response is metadata only
// (creation and expiry time, algorithm, origin, disabled state) and never contains
// private key material.
//
// It lists the project's service accounts (iam.serviceAccounts.list) and then each
// account's user-managed keys (iam.serviceAccountKeys.list), verified against the
// IAM API reference (v1, 2026-10-04): both are read-only GETs. Each key becomes a
// credential node keyed by its full resource name, joined to its service account by
// a contains_secret edge and carrying the key's age in days computed against scan
// time. The per-account key list is bounded by the shared call budget; the
// remainder is a recorded Partial gap, never a silent stop.
type ServiceAccountKeyCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget  // the scan's shared call cap; nil is unlimited
	now       func() time.Time // injectable clock; nil uses time.Now
}

// NewServiceAccountKeyCollector builds the collector with a REST client that
// authenticates with a token from the adapter's resolved credential (ADR-0018 §3).
func NewServiceAccountKeyCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *ServiceAccountKeyCollector {
	return &ServiceAccountKeyCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newServiceAccountKeyCollector is the injectable constructor tests use with a stub
// API and a fixed clock.
func newServiceAccountKeyCollector(projectID string, api gcpAPI, now func() time.Time) *ServiceAccountKeyCollector {
	return &ServiceAccountKeyCollector{projectID: projectID, api: api, now: now}
}

func (c *ServiceAccountKeyCollector) ID() string               { return serviceAccountKeyCollectorID }
func (c *ServiceAccountKeyCollector) Provider() model.Provider { return model.GCP }

func serviceAccountKeyRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: serviceAccountKeyCollectorID}
	}
	return []permissions.Requirement{
		req("iam.serviceAccounts.list"),
		req("iam.serviceAccountKeys.list"),
	}
}

func init() {
	for _, r := range serviceAccountKeyRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *ServiceAccountKeyCollector) Requirements() []permissions.Requirement {
	return serviceAccountKeyRequirements()
}

func (c *ServiceAccountKeyCollector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

// Collect lists the service accounts and then each account's user-managed keys,
// emitting a credential node with the key's age per key. The whole operation is one
// completeness record (iam.serviceAccountKeys): a failure to list the accounts, or
// a per-account key-list gap, is recorded there, never a false empty-complete.
func (c *ServiceAccountKeyCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{
			Service: svcServiceAccountKeys, Region: collect.Global, Scope: c.scope(),
			Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to",
		})
	}
	emails, listed, err := c.listAccounts(ctx, sink)
	if err != nil {
		return err
	}
	if !listed.done {
		// Could not fully enumerate the accounts, so the key coverage is unknown.
		return sink.Complete(collect.Completeness{Service: svcServiceAccountKeys, Region: collect.Global, Scope: c.scope(), Status: listed.status, Collected: 0, Reason: listed.reason})
	}

	total := 0
	reason := ""
	for _, email := range emails {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: svcServiceAccountKeys, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: total, Reason: "cancelled"})
			return err
		}
		n, gap := c.accountKeys(ctx, sink, email)
		total += n
		if gap != "" {
			reason = gap
			if gap == "budget exhausted" {
				break
			}
		}
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: svcServiceAccountKeys, Region: collect.Global, Scope: c.scope(), Status: status, Collected: total, Reason: reason})
}

// listOutcome is how the account enumeration ended.
type listOutcome struct {
	done   bool
	status collect.Status
	reason string
}

// listAccounts lists the project's service accounts (emails only), budget-bounded
// and paginated. It does not record its own completeness; the outcome folds into
// the single iam.serviceAccountKeys record so the operation is reported once.
func (c *ServiceAccountKeyCollector) listAccounts(ctx context.Context, sink collect.Sink) ([]string, listOutcome, error) {
	base := fmt.Sprintf("%s/projects/%s/serviceAccounts", iamBaseURL, url.PathEscape(c.projectID))
	pageToken := ""
	var emails []string
	for page := 0; ; page++ {
		if page >= maxPages {
			return emails, listOutcome{status: collect.Partial, reason: "page limit reached"}, nil
		}
		if err := ctx.Err(); err != nil {
			return emails, listOutcome{status: collect.Partial, reason: "cancelled"}, err
		}
		if !c.budget.Spend() {
			return emails, listOutcome{status: collect.Partial, reason: "budget exhausted"}, nil
		}
		u := fmt.Sprintf("%s?pageSize=%d", base, pageSize)
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return emails, listOutcome{status: c.statusOf(err), reason: credKeyReason(err)}, nil
			}
			return emails, listOutcome{}, err
		}
		_ = sink.Evidence(c.evidence("serviceAccounts.list", body))
		var pg serviceAccountPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return emails, listOutcome{status: collect.Errored, reason: redact.String(err.Error())}, nil
		}
		for _, sa := range pg.Accounts {
			if sa.Email != "" {
				emails = append(emails, sa.Email)
			}
		}
		if pg.NextPageToken == "" {
			return emails, listOutcome{done: true, status: collect.Complete}, nil
		}
		pageToken = pg.NextPageToken
	}
}

// accountKeys lists one service account's user-managed keys and emits a credential
// node with its age per key, joined to the account by a contains_secret edge. It
// returns the count emitted and a reason if the read did not fully complete. The
// list is a single GET (keys are not paginated), so one budget unit per account.
func (c *ServiceAccountKeyCollector) accountKeys(ctx context.Context, sink collect.Sink, email string) (int, string) {
	if !c.budget.Spend() {
		return 0, "budget exhausted"
	}
	u := fmt.Sprintf("%s/projects/%s/serviceAccounts/%s/keys?keyTypes=USER_MANAGED",
		iamBaseURL, url.PathEscape(c.projectID), url.PathEscape(email))
	body, err := c.api.get(ctx, u)
	if err != nil {
		switch {
		case isServiceDisabled(err):
			return 0, "service disabled"
		case isDenied(err):
			return 0, "denied"
		case isThrottle(err):
			return 0, "throttled"
		default:
			return 0, redact.String(err.Error())
		}
	}
	_ = sink.Evidence(c.evidence("serviceAccounts.keys.list", body))
	var resp struct {
		Keys []struct {
			Name            string `json:"name"`
			ValidAfterTime  string `json:"validAfterTime"`
			ValidBeforeTime string `json:"validBeforeTime"`
			KeyAlgorithm    string `json:"keyAlgorithm"`
			KeyOrigin       string `json:"keyOrigin"`
			KeyType         string `json:"keyType"`
			Disabled        *bool  `json:"disabled"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, redact.String(err.Error())
	}
	now := c.clock()
	count := 0
	for _, k := range resp.Keys {
		if k.Name == "" {
			continue
		}
		a := map[string]string{
			"key_type":          "user_managed",
			"service_account":   email,
			"valid_after_time":  k.ValidAfterTime,
			"valid_before_time": k.ValidBeforeTime,
			"key_algorithm":     k.KeyAlgorithm,
			"key_origin":        k.KeyOrigin,
			"disabled":          boolAttr(k.Disabled),
		}
		if created, ok := parseKeyTime(k.ValidAfterTime); ok {
			a["key_age_days"] = strconv.Itoa(int(now.Sub(created).Hours() / 24))
		}
		_ = sink.Node(collect.Node{Type: model.NodeCredential, NativeID: k.Name, Attributes: pruneEmptyKey(a)})
		_ = sink.Link(collect.Link{SourceNativeID: email, TargetNativeID: k.Name, Kind: model.EdgeContainsSecret})
		count++
	}
	return count, ""
}

// parseKeyTime parses a GCP RFC3339 timestamp; ok is false when the field is empty
// or unparseable, so a key with no creation time is represented as unknown age,
// never age zero.
func parseKeyTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// pruneEmptyKey drops empty-valued attributes so an absent field is absent, not "".
func pruneEmptyKey(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func (c *ServiceAccountKeyCollector) statusOf(err error) collect.Status {
	switch {
	case isServiceDisabled(err):
		return collect.Unsupported
	case isDenied(err):
		return collect.Denied
	case isThrottle(err):
		return collect.Partial
	}
	return collect.Errored
}

// credKeyReason is the redacted reason for an account-list error.
func credKeyReason(err error) string {
	switch {
	case isServiceDisabled(err):
		return "service disabled"
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	return redact.String(err.Error())
}

func (c *ServiceAccountKeyCollector) scope() collect.Scope {
	return collect.Scope{Account: c.projectID}
}

func (c *ServiceAccountKeyCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "iam", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: serviceAccountKeyCollectorID},
	}
}
