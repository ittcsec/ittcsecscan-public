package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const conditionalAccessCollectorID = "collector:azure.entra.conditionalAccess"

// ConditionalAccessCollector reads the tenant's Conditional Access policies: the
// per-condition access controls (MFA, device state, location, app) that are the
// primary access-governance surface on licensed tenants. Each policy becomes a
// control node with its state and a canonical summary of its conditions and grant
// controls, never a verdict.
//
// It reads GET /identity/conditionalAccess/policies with Policy.Read.All
// (doc-verified 2026-10-04). Conditional Access requires an Entra ID P1/P2 license;
// an unlicensed tenant returns an empty list (HTTP 200) or a licensing error, and
// neither can be distinguished from a licensed tenant that genuinely has zero
// policies. So, per ADR-0036, BOTH an empty list and a licensing error are recorded
// Unsupported, never Complete and never a pass: the scanner never claims a tenant
// has "no CA gaps" when it simply cannot see CA.
type ConditionalAccessCollector struct {
	tenantID string
	api      graphAPI
	budget   *collect.Budget
}

// NewConditionalAccessCollector builds the collector with a Graph client that mints a
// Graph-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewConditionalAccessCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *ConditionalAccessCollector {
	return &ConditionalAccessCollector{tenantID: tenantID, api: &graphClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

func newConditionalAccessCollector(tenantID string, api graphAPI) *ConditionalAccessCollector {
	return &ConditionalAccessCollector{tenantID: tenantID, api: api}
}

func (c *ConditionalAccessCollector) ID() string               { return conditionalAccessCollectorID }
func (c *ConditionalAccessCollector) Provider() model.Provider { return model.Azure }

func conditionalAccessRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.Azure, Profile: permissions.Discovery,
		Permission: "Policy.Read.All", By: conditionalAccessCollectorID,
	}}
}

func init() {
	for _, r := range conditionalAccessRequirements() {
		permissions.Declare(r)
	}
}

func (c *ConditionalAccessCollector) Requirements() []permissions.Requirement {
	return conditionalAccessRequirements()
}

// Collect reads the Conditional Access policies. An empty list or a licensing error
// is Unsupported (never Complete/pass); a denial is Denied; real policies are
// Complete and each becomes a control node.
func (c *ConditionalAccessCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "entra.conditionalAccess"
	if !c.budget.Spend() {
		return sink.Complete(c.gap(service, collect.Partial, 0, "budget exhausted"))
	}
	body, err := c.api.get(ctx, graphBaseURL+"/identity/conditionalAccess/policies")
	if err != nil {
		if ctx.Err() != nil {
			_ = sink.Complete(c.gap(service, collect.Partial, 0, "cancelled"))
			return ctx.Err()
		}
		// A licensing error (the tenant has no eligible Entra ID P1/P2) is not a
		// permission problem and must not read as "no CA gaps": record Unsupported.
		if isLicensingError(err) {
			return sink.Complete(c.gap(service, collect.Unsupported, 0, "conditional access not available (no eligible Entra ID P1/P2 license)"))
		}
		_ = sink.Complete(c.completeness(service, err))
		if isDenied(err) || isThrottle(err) {
			return nil
		}
		return err
	}
	_ = sink.Evidence(c.evidence(service, body))
	var env struct {
		Value []conditionalAccessPolicy `json:"value"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return sink.Complete(c.gap(service, collect.Errored, 0, redact.String(err.Error())))
	}
	if len(env.Value) == 0 {
		// An empty result on a tenant that may be unlicensed is indistinguishable
		// from a licensed tenant with zero policies, so it is Unsupported, never
		// Complete/0: the scanner does not assert that CA is clean when it cannot see
		// whether CA even applies.
		return sink.Complete(c.gap(service, collect.Unsupported, 0, "no conditional access policies returned; CA requires Entra ID P1/P2 and an empty result cannot be distinguished from an unlicensed tenant"))
	}
	for _, p := range env.Value {
		if p.ID == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: c.tenantID + "/ca/" + p.ID, Name: p.DisplayName,
			Attributes: attrs("azure_type", "conditional_access_policy", "state", p.State, "conditions", canonicalJSON(p.Conditions), "grant_controls", canonicalJSON(p.GrantControls))})
	}
	return sink.Complete(c.gap(service, collect.Complete, len(env.Value), ""))
}

// conditionalAccessPolicy is the subset of a CA policy the collector records. The
// conditions and grant controls are kept as raw JSON so a downstream consumer sees
// the real configuration; none is a secret value.
type conditionalAccessPolicy struct {
	ID            string          `json:"id"`
	DisplayName   string          `json:"displayName"`
	State         string          `json:"state"`
	Conditions    json.RawMessage `json:"conditions"`
	GrantControls json.RawMessage `json:"grantControls"`
}

// isLicensingError reports an error that indicates Conditional Access is unavailable
// because the tenant lacks an eligible license, as opposed to a permission denial.
// Graph signals this on some tenants with a specific message rather than an empty
// list; the check is on the error text, after redaction (no secret value is in a CA
// licensing error).
func isLicensingError(err error) bool {
	var ae *azureError
	if !errors.As(err, &ae) {
		return false
	}
	msg := strings.ToLower(ae.body)
	return strings.Contains(msg, "license") || strings.Contains(msg, "licence") ||
		strings.Contains(msg, "not enabled for this tenant") || strings.Contains(msg, "tenant is not")
}

func (c *ConditionalAccessCollector) scope() collect.Scope { return collect.Scope{Account: c.tenantID} }

func (c *ConditionalAccessCollector) evidence(service string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "entra", Operation: service, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: graphAPIVersion, Collector: conditionalAccessCollectorID},
	}
}

func (c *ConditionalAccessCollector) completeness(service string, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return c.gap(service, status, 0, redact.String(err.Error()))
}

func (c *ConditionalAccessCollector) gap(service string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}
