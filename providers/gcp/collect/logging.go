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

// loggingCollectorID is the stable id this collector is credited with.
const loggingCollectorID = "collector:gcp.logging"

const (
	// loggingBaseURL is the Cloud Logging API v2 endpoint. The collector reads only
	// the logging *configuration* (sinks and buckets); it never reads log entries.
	// The entry-content operations (entries.list, entries.tail) are refused by the
	// read-only path gate (ForbiddenPaths) as defence in depth.
	loggingBaseURL = "https://logging.googleapis.com/v2"
	// loggingAPIVersion is recorded as evidence provenance.
	loggingAPIVersion = "v2"
)

// LoggingCollector reads a GCP project's audit-logging configuration, the GCP
// counterpart of the AWS CloudTrail and Config collectors and Azure's logging
// collector. It reads the two project-scoped configuration resources that answer
// "where are logs routed and how long are they kept": log sinks (routing and export
// destinations) and log buckets (retention). Reads verified against the Cloud Logging
// API reference (v2, 2026-09-22): projects.sinks.list (logging.sinks.list) and
// projects.locations.buckets.list with the locations/- wildcard (logging.buckets.list)
// are read-only GETs paginated by pageToken. No log entry content is ever read; the
// entries.list/tail content operations are refused by the read-only path gate.
//
// Each sink and bucket becomes a control node keyed by its full resource name
// (ADR-0019 §2). A sink records its destination as a forward-key fact so the
// destination bucket, dataset, or topic joins; a bucket records its customer-managed
// encryption key so the Cloud KMS node joins. Per ADR-0019 §3 no verdict is
// synthesized: retention days and whether a sink is disabled are raw facts, not a
// "logging insufficient" conclusion.
type LoggingCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewLoggingCollector builds the collector with a REST client that authenticates with
// a token from the adapter's resolved credential (ADR-0018 §3).
func NewLoggingCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *LoggingCollector {
	return &LoggingCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newLoggingCollector is the injectable constructor tests use with a stub API.
func newLoggingCollector(projectID string, api gcpAPI) *LoggingCollector {
	return &LoggingCollector{projectID: projectID, api: api}
}

func (c *LoggingCollector) ID() string               { return loggingCollectorID }
func (c *LoggingCollector) Provider() model.Provider { return model.GCP }

func loggingRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: loggingCollectorID}
	}
	return []permissions.Requirement{
		req("logging.sinks.list"),
		req("logging.buckets.list"),
	}
}

func init() {
	for _, r := range loggingRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *LoggingCollector) Requirements() []permissions.Requirement { return loggingRequirements() }

// Collect lists the project's log sinks and log buckets, emitting one control node
// each and one completeness record per resource (logging.sinks, logging.buckets). An
// empty project is an honest Complete/0; a disabled API is Unsupported; a denied or
// throttled read is a represented gap.
func (c *LoggingCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		_ = sink.Complete(collect.Completeness{Service: "logging.sinks", Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
		_ = sink.Complete(collect.Completeness{Service: "logging.buckets", Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
		return nil
	}
	if err := c.listSinks(ctx, sink); err != nil {
		return err
	}
	return c.listBuckets(ctx, sink)
}

func (c *LoggingCollector) listSinks(ctx context.Context, sink collect.Sink) error {
	const service = "logging.sinks"
	base := fmt.Sprintf("%s/projects/%s/sinks", loggingBaseURL, url.PathEscape(c.projectID))
	return c.page(ctx, sink, service, base, "sinks.list", func(body []byte) (int, string, error) {
		var pg logSinkPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return 0, "", err
		}
		for _, s := range pg.Sinks {
			if s.Name == "" {
				continue
			}
			a := map[string]string{
				// Forward key: the destination bucket, dataset, or topic joins here.
				"destination":     s.Destination,
				"filter":          s.Filter,
				"description":     s.Description,
				"writer_identity": s.WriterIdentity,
				"disabled":        boolStr(s.Disabled),
			}
			for k, v := range a {
				if v == "" {
					delete(a, k)
				}
			}
			_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: "//logging.googleapis.com/" + sinkName(c.projectID, s.Name), Name: s.Name, Attributes: a})
		}
		return len(pg.Sinks), pg.NextPageToken, nil
	})
}

func (c *LoggingCollector) listBuckets(ctx context.Context, sink collect.Sink) error {
	const service = "logging.buckets"
	// The locations/- wildcard lists buckets across every location in one paginated
	// call, so there is no per-location fan-out.
	base := fmt.Sprintf("%s/projects/%s/locations/-/buckets", loggingBaseURL, url.PathEscape(c.projectID))
	return c.page(ctx, sink, service, base, "buckets.list", func(body []byte) (int, string, error) {
		var pg logBucketPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return 0, "", err
		}
		for _, b := range pg.Buckets {
			if b.Name == "" {
				continue
			}
			a := map[string]string{
				"description":       b.Description,
				"lifecycle_state":   b.LifecycleState,
				"locked":            boolStr(b.Locked),
				"analytics_enabled": boolStr(b.AnalyticsEnabled),
			}
			if b.RetentionDays != 0 {
				a["retention_days"] = fmt.Sprintf("%d", b.RetentionDays)
			}
			if b.CmekSettings != nil && b.CmekSettings.KmsKeyName != "" {
				// Forward key: joins the Cloud KMS crypto-key node.
				a["cmek_key"] = b.CmekSettings.KmsKeyName
			}
			for k, v := range a {
				if v == "" {
					delete(a, k)
				}
			}
			_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: "//logging.googleapis.com/" + b.Name, Name: lastPathSegment(b.Name), Attributes: a})
		}
		return len(pg.Buckets), pg.NextPageToken, nil
	})
}

// page runs a paginated Cloud Logging list. decode returns the page's item count, the
// next-page token ("" on the last page), and any decode error. It records evidence per
// page and one completeness record for the service.
func (c *LoggingCollector) page(ctx context.Context, sink collect.Sink, service, base, op string, decode func([]byte) (int, string, error)) error {
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
		_ = sink.Evidence(c.evidence(op, body))
		n, next, err := decode(body)
		if err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		count += n
		if next == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return nil
		}
		pageToken = next
	}
}

// sinkName returns a sink's full relative resource name. sinks.list returns the short
// sink id in "name", so the project is prepended for a canonical key.
func sinkName(project, name string) string {
	return "projects/" + project + "/sinks/" + name
}

type logSinkPage struct {
	Sinks []struct {
		Name           string `json:"name"`
		Destination    string `json:"destination"`
		Filter         string `json:"filter"`
		Description    string `json:"description"`
		WriterIdentity string `json:"writerIdentity"`
		Disabled       bool   `json:"disabled"`
	} `json:"sinks"`
	NextPageToken string `json:"nextPageToken"`
}

type logBucketPage struct {
	Buckets []struct {
		Name             string `json:"name"`
		Description      string `json:"description"`
		RetentionDays    int    `json:"retentionDays"`
		Locked           bool   `json:"locked"`
		LifecycleState   string `json:"lifecycleState"`
		AnalyticsEnabled bool   `json:"analyticsEnabled"`
		CmekSettings     *struct {
			KmsKeyName string `json:"kmsKeyName"`
		} `json:"cmekSettings"`
	} `json:"buckets"`
	NextPageToken string `json:"nextPageToken"`
}

func (c *LoggingCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *LoggingCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "logging", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: loggingAPIVersion, Collector: loggingCollectorID},
	}
}

func (c *LoggingCollector) completeness(service string, collected int, err error) collect.Completeness {
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
