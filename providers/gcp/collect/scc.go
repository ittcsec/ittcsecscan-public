package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// sccCollectorID is the stable id this collector is credited with.
const sccCollectorID = "collector:gcp.scc.sources"

const (
	// sccBaseURL is the Security Command Center API v1 endpoint. The collector reads
	// only the registered security sources; it never reads individual findings.
	sccBaseURL = "https://securitycenter.googleapis.com/v1"
	// sccAPIVersion is recorded as evidence provenance.
	sccAPIVersion = "v1"
)

// SCCCollector reads a GCP project's registered Security Command Center sources, the
// GCP counterpart of the AWS security-services collector (GuardDuty, Security Hub,
// Inspector, Macie). A Security Command Center source is a security service or
// integration that reports findings (Security Health Analytics, Event Threat
// Detection, Web Security Scanner, and third-party integrations), so listing the
// sources captures which detection services are active for the project, the same posture
// the AWS collector captures by listing detectors and analyzers. The read was verified
// against the Security Command Center API reference (v1, 2026-09-22):
// projects.sources.list is a read-only GET paginated by pageToken, requiring
// securitycenter.sources.list.
//
// Each source becomes a control node keyed by its full resource name (ADR-0019 §2).
// Per ADR-0019 §3 no verdict is synthesized: the set of active sources is a fact, and
// whether coverage is sufficient is the rule engine's call.
//
// Deliberately out of scope, a documented boundary rather than a silent gap:
// individual findings (findings.list). Findings are the alerts a source produces, the
// equivalent of GuardDuty findings the AWS security-services collector likewise does
// not enumerate; ingesting them is a separate, later concern with its own contract.
type SCCCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewSCCCollector builds the collector with a REST client that authenticates with a
// token from the adapter's resolved credential (ADR-0018 §3).
func NewSCCCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *SCCCollector {
	return &SCCCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newSCCCollector is the injectable constructor tests use with a stub API.
func newSCCCollector(projectID string, api gcpAPI) *SCCCollector {
	return &SCCCollector{projectID: projectID, api: api}
}

func (c *SCCCollector) ID() string               { return sccCollectorID }
func (c *SCCCollector) Provider() model.Provider { return model.GCP }

func sccRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "securitycenter.sources.list", By: sccCollectorID},
	}
}

func init() {
	for _, r := range sccRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *SCCCollector) Requirements() []permissions.Requirement { return sccRequirements() }

// Collect lists the project's Security Command Center sources, emitting one control
// node each and one completeness record (scc.sources). An empty or unactivated project
// is an honest Complete/0; a disabled API is Unsupported; a denied or throttled read is
// a represented gap. Security Command Center not being activated on the project
// surfaces as Denied or Unsupported, never as a silent pass.
func (c *SCCCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "scc.sources"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
	}
	base := fmt.Sprintf("%s/projects/%s/sources", sccBaseURL, url.PathEscape(c.projectID))
	pageToken := ""
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
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
		u := base
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence("sources.list", body))
		var pg sccSourcePage
		if err := json.Unmarshal(body, &pg); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, src := range pg.Sources {
			if src.Name == "" {
				continue
			}
			a := map[string]string{
				"display_name": src.DisplayName,
				"description":  src.Description,
			}
			for k, v := range a {
				if v == "" {
					delete(a, k)
				}
			}
			_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: "//securitycenter.googleapis.com/" + src.Name, Name: src.DisplayName, Attributes: a})
			count++
		}
		if pg.NextPageToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return nil
		}
		pageToken = pg.NextPageToken
	}
}

type sccSourcePage struct {
	Sources []struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
	} `json:"sources"`
	NextPageToken string `json:"nextPageToken"`
}

func (c *SCCCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *SCCCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "securitycenter", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: sccAPIVersion, Collector: sccCollectorID},
	}
}

func (c *SCCCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: redact.String(err.Error())}
}
