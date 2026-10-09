package collect

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// defenderCollectorID is the stable id this collector is credited with.
const defenderCollectorID = "collector:azure.defender"

// DefenderCollector reads the tenant's Microsoft Defender for Cloud configuration, the
// Azure counterpart of the AWS security-services collector (GuardDuty, Security Hub,
// Inspector, Macie). Where AWS exposes each threat-protection service separately,
// Defender for Cloud folds them into a single per-subscription pricings list: one
// entry per plan (VirtualMachines, StorageAccounts, SqlServers, KeyVaults,
// Containers, CloudPosture, and so on), each with its own tier. A subscription-wide
// pricings read therefore captures the whole threat-protection posture in one call,
// so the collector does not force the AWS five-service shape onto a service that does
// not have it. It also reads the auto-provisioning setting (whether the monitoring
// agent is deployed automatically).
//
// Each plan and setting becomes a control node keyed by its ARM resource id. Per
// ADR-0019 §3 no verdict is synthesized: the pricing tier (Free or Standard) is
// recorded as a fact, whether a given plan should be Standard is the rule engine's
// call. A denied read is a represented gap, never asserted as "Defender disabled".
//
// Security contacts (alert notification configuration) are a separate Defender feature
// whose schema has shifted across API versions; they are a deliberate future addition
// under the same contract, not collected here.
type DefenderCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewDefenderCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewDefenderCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *DefenderCollector {
	return &DefenderCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newDefenderCollector is the injectable constructor tests use with a stub API.
func newDefenderCollector(tenantID string, api armAPI) *DefenderCollector {
	return &DefenderCollector{tenantID: tenantID, api: api}
}

func (c *DefenderCollector) ID() string               { return defenderCollectorID }
func (c *DefenderCollector) Provider() model.Provider { return model.Azure }

func defenderRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Azure, Profile: permissions.Discovery, Permission: p, By: defenderCollectorID}
	}
	return []permissions.Requirement{
		req("Microsoft.Security/pricings/read"),
		req("Microsoft.Security/autoProvisioningSettings/read"),
	}
}

func init() {
	for _, r := range defenderRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *DefenderCollector) Requirements() []permissions.Requirement { return defenderRequirements() }

type defenderResource struct {
	service    string
	path       string
	apiVersion string
	decode     func(c *DefenderCollector, sink collect.Sink, raw json.RawMessage) (int, error)
}

func (c *DefenderCollector) resources() []defenderResource {
	return []defenderResource{
		{"defender.pricings", "Microsoft.Security/pricings", "2024-01-01", (*DefenderCollector).decodePricings},
		{"defender.autoProvisioning", "Microsoft.Security/autoProvisioningSettings", "2017-08-01-preview", (*DefenderCollector).decodeAutoProvisioning},
	}
}

// Collect enumerates the accessible subscriptions and, for each, reads the Defender
// plans and the auto-provisioning setting. One completeness record is produced per
// (resource, subscription), plus defender.subscriptions.
func (c *DefenderCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "defender.subscriptions", tenantScope, subscriptionsAPIVersion,
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

func (c *DefenderCollector) decodePricings(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []pricing
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, p := range page {
		if p.ID == "" {
			continue
		}
		a := map[string]string{
			"azure_type":      "defender_plan",
			"plan":            p.Name,
			"pricing_tier":    p.Properties.PricingTier,
			"sub_plan":        p.Properties.SubPlan,
			"enforce":         p.Properties.Enforce,
			"enablement_time": p.Properties.EnablementTime,
		}
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: p.ID, Name: p.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

func (c *DefenderCollector) decodeAutoProvisioning(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []autoProvisioningSetting
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, s := range page {
		if s.ID == "" {
			continue
		}
		a := map[string]string{
			"azure_type":     "auto_provisioning_setting",
			"auto_provision": s.Properties.AutoProvision,
		}
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: s.ID, Name: s.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

type pricing struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PricingTier    string `json:"pricingTier"`
		SubPlan        string `json:"subPlan"`
		Enforce        string `json:"enforce"`
		EnablementTime string `json:"enablementTime"`
	} `json:"properties"`
}

type autoProvisioningSetting struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		AutoProvision string `json:"autoProvision"`
	} `json:"properties"`
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending budget
// per page and recording evidence and completeness for service at scope. A denied or
// throttled read is a represented gap (returns nil); an unexpected error is surfaced;
// a page is never reported Complete on a failure.
func (c *DefenderCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(defenderGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(defenderGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(defenderGap(service, scope, collect.Partial, count, "budget exhausted"))
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
			_ = sink.Complete(defenderGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(defenderGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(defenderGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *DefenderCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "defender", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: defenderCollectorID},
	}
}

func (c *DefenderCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return defenderGap(service, scope, status, collected, redact.String(err.Error()))
}

func defenderGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}
