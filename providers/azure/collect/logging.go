package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// loggingCollectorID is the stable id this collector is credited with.
const loggingCollectorID = "collector:azure.logging"

// LoggingCollector reads the tenant's Azure audit-logging configuration, the Azure
// counterpart of the AWS CloudTrail and Config collectors. It covers the two
// subscription-scoped resources that answer "is the platform audit trail being
// retained and where": Log Analytics workspaces (the log sinks) and the subscription
// diagnostic settings (the Activity Log export configuration). Both are read with a
// single read-only List; no log content is retrieved, only the configuration.
//
// Known blind spot, represented explicitly rather than silently: per-resource
// diagnostic settings (whether an individual storage account, key vault, and so on
// exports its own platform logs) require a diagnostic-settings read against every
// resource id, a fan-out this collector deliberately does not perform. Only the
// subscription-level Activity Log setting is collected here. A later pass can add
// per-resource settings under the same contract; until then their absence is a
// documented boundary, not a gap asserted as configured.
//
// Each workspace and diagnostic setting becomes a control node keyed by its ARM
// resource id. A diagnostic setting records its destination sinks (workspace, storage
// account, event hub) as id facts so they join the workspace and storage nodes, and
// its enabled log categories as a sorted canonical-JSON fact. Per ADR-0019 §3 no
// verdict is synthesized: which categories are enabled is a fact, whether that is
// sufficient is the rule engine's call.
type LoggingCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewLoggingCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewLoggingCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *LoggingCollector {
	return &LoggingCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newLoggingCollector is the injectable constructor tests use with a stub API.
func newLoggingCollector(tenantID string, api armAPI) *LoggingCollector {
	return &LoggingCollector{tenantID: tenantID, api: api}
}

func (c *LoggingCollector) ID() string               { return loggingCollectorID }
func (c *LoggingCollector) Provider() model.Provider { return model.Azure }

func loggingRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Azure, Profile: permissions.Discovery, Permission: p, By: loggingCollectorID}
	}
	return []permissions.Requirement{
		req("Microsoft.OperationalInsights/workspaces/read"),
		req("Microsoft.Insights/diagnosticSettings/read"),
	}
}

func init() {
	for _, r := range loggingRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *LoggingCollector) Requirements() []permissions.Requirement { return loggingRequirements() }

type logResource struct {
	service    string
	path       string
	apiVersion string
	decode     func(c *LoggingCollector, sink collect.Sink, raw json.RawMessage) (int, error)
}

func (c *LoggingCollector) resources() []logResource {
	return []logResource{
		{"logging.workspaces", "Microsoft.OperationalInsights/workspaces", "2026-03-01", (*LoggingCollector).decodeWorkspaces},
		{"logging.diagnosticSettings", "Microsoft.Insights/diagnosticSettings", "2021-05-01-preview", (*LoggingCollector).decodeDiagnosticSettings},
	}
}

// Collect enumerates the accessible subscriptions and, for each, lists the Log
// Analytics workspaces and the subscription-level diagnostic settings. One
// completeness record is produced per (resource, subscription), plus
// logging.subscriptions.
func (c *LoggingCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "logging.subscriptions", tenantScope, subscriptionsAPIVersion,
		fmt.Sprintf("%s/subscriptions?api-version=%s", armBaseURL, subscriptionsAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []subscription
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			subs = append(subs, page...)
			return len(page), nil
		})
	if err != nil {
		return err
	}

	for _, sub := range subs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sub.SubscriptionID == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeSubscription, NativeID: sub.SubscriptionID, Name: sub.DisplayName,
			Attributes: attrs("state", sub.State)})
		scope := collect.Scope{Account: c.tenantID, Resource: sub.SubscriptionID}
		for _, r := range c.resources() {
			decode := r.decode
			_ = c.pageThrough(ctx, sink, r.service, scope, r.apiVersion,
				fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=%s", armBaseURL, sub.SubscriptionID, r.path, r.apiVersion),
				func(raw json.RawMessage) (int, error) { return decode(c, sink, raw) })
		}
	}
	return nil
}

func (c *LoggingCollector) decodeWorkspaces(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []workspace
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, w := range page {
		if w.ID == "" {
			continue
		}
		p := w.Properties
		a := map[string]string{
			"azure_type":                      "log_analytics_workspace",
			"location":                        w.Location,
			"customer_id":                     p.CustomerID,
			"sku":                             p.Sku.Name,
			"provisioning_state":              p.ProvisioningState,
			"public_network_access_ingestion": p.PublicNetworkAccessForIngestion,
			"public_network_access_query":     p.PublicNetworkAccessForQuery,
		}
		if p.RetentionInDays != nil {
			a["retention_days"] = strconv.Itoa(*p.RetentionInDays)
		}
		if f := p.Features; f != nil {
			a["disable_local_auth"] = boolAttr(f.DisableLocalAuth)
			a["immediate_purge_30_days"] = boolAttr(f.ImmediatePurgeDataOn30Days)
		}
		if wc := p.WorkspaceCapping; wc != nil && wc.DailyQuotaGb != 0 {
			a["daily_quota_gb"] = strconv.FormatFloat(wc.DailyQuotaGb, 'f', -1, 64)
		}
		mapTags(a, w.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: w.ID, Name: w.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

func (c *LoggingCollector) decodeDiagnosticSettings(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []diagnosticSetting
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, d := range page {
		if d.ID == "" {
			continue
		}
		p := d.Properties
		logs := make([]diagLogFact, 0, len(p.Logs))
		for _, l := range p.Logs {
			logs = append(logs, diagLogFact{Category: l.Category, CategoryGroup: l.CategoryGroup, Enabled: derefBool(l.Enabled)})
		}
		sort.Slice(logs, func(i, j int) bool {
			if logs[i].Category != logs[j].Category {
				return logs[i].Category < logs[j].Category
			}
			return logs[i].CategoryGroup < logs[j].CategoryGroup
		})
		a := map[string]string{
			"azure_type": "diagnostic_setting",
			"scope":      "subscription",
			// Destination sinks, recorded as id facts so they join the workspace and
			// storage nodes.
			"workspace_id":                   p.WorkspaceID,
			"storage_account_id":             p.StorageAccountID,
			"event_hub_authorization_rule":   p.EventHubAuthorizationRuleID,
			"log_analytics_destination_type": p.LogAnalyticsDestinationType,
		}
		if len(logs) > 0 {
			a["logs"] = canonicalJSON(logs)
		}
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: d.ID, Name: d.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

// diagLogFact is one diagnostic-setting log category as reported.
type diagLogFact struct {
	Category      string `json:"category,omitempty"`
	CategoryGroup string `json:"category_group,omitempty"`
	Enabled       bool   `json:"enabled"`
}

func derefBool(b *bool) bool { return b != nil && *b }

type workspace struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		CustomerID        string `json:"customerId"`
		ProvisioningState string `json:"provisioningState"`
		Sku               struct {
			Name string `json:"name"`
		} `json:"sku"`
		RetentionInDays                 *int   `json:"retentionInDays"`
		PublicNetworkAccessForIngestion string `json:"publicNetworkAccessForIngestion"`
		PublicNetworkAccessForQuery     string `json:"publicNetworkAccessForQuery"`
		Features                        *struct {
			DisableLocalAuth           *bool `json:"disableLocalAuth"`
			ImmediatePurgeDataOn30Days *bool `json:"immediatePurgeDataOn30Days"`
		} `json:"features"`
		WorkspaceCapping *struct {
			DailyQuotaGb float64 `json:"dailyQuotaGb"`
		} `json:"workspaceCapping"`
	} `json:"properties"`
}

type diagnosticSetting struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		WorkspaceID                 string `json:"workspaceId"`
		StorageAccountID            string `json:"storageAccountId"`
		EventHubAuthorizationRuleID string `json:"eventHubAuthorizationRuleId"`
		LogAnalyticsDestinationType string `json:"logAnalyticsDestinationType"`
		Logs                        []struct {
			Category      string `json:"category"`
			CategoryGroup string `json:"categoryGroup"`
			Enabled       *bool  `json:"enabled"`
		} `json:"logs"`
	} `json:"properties"`
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending budget
// per page and recording evidence and completeness for service at scope. A denied or
// throttled read is a represented gap (returns nil); an unexpected error is surfaced;
// a page is never reported Complete on a failure.
func (c *LoggingCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(loggingGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(loggingGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(loggingGap(service, scope, collect.Partial, count, "budget exhausted"))
			return nil
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence(service, apiVersion, scope, body))
		var list armList
		if err := json.Unmarshal(body, &list); err != nil {
			_ = sink.Complete(loggingGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(loggingGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(loggingGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *LoggingCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "logging", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: loggingCollectorID},
	}
}

func (c *LoggingCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return loggingGap(service, scope, status, collected, redact.String(err.Error()))
}

func loggingGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}
