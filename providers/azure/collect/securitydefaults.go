package collect

import (
	"context"
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const securityDefaultsCollectorID = "collector:azure.entra.securityDefaults"

// SecurityDefaultsCollector reads the tenant's security defaults enforcement policy:
// the single tenant-wide switch that, when enabled, requires MFA registration,
// blocks legacy authentication, and protects privileged actions. It is the baseline
// identity protection for tenants that do not use Conditional Access, and unlike
// Conditional Access it is available on every tenant regardless of license, so it is
// always a real, assessable signal.
//
// It reads GET /policies/identitySecurityDefaultsEnforcementPolicy with
// Policy.Read.All (doc-verified 2026-10-04): a single read-only object with an
// isEnabled boolean, no secret value. It emits one control node carrying
// security_defaults_enabled, never a verdict.
type SecurityDefaultsCollector struct {
	tenantID string
	api      graphAPI
	budget   *collect.Budget
}

// NewSecurityDefaultsCollector builds the collector with a Graph client that mints a
// Graph-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewSecurityDefaultsCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *SecurityDefaultsCollector {
	return &SecurityDefaultsCollector{tenantID: tenantID, api: &graphClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

func newSecurityDefaultsCollector(tenantID string, api graphAPI) *SecurityDefaultsCollector {
	return &SecurityDefaultsCollector{tenantID: tenantID, api: api}
}

func (c *SecurityDefaultsCollector) ID() string               { return securityDefaultsCollectorID }
func (c *SecurityDefaultsCollector) Provider() model.Provider { return model.Azure }

func securityDefaultsRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.Azure, Profile: permissions.Discovery,
		Permission: "Policy.Read.All", By: securityDefaultsCollectorID,
	}}
}

func init() {
	for _, r := range securityDefaultsRequirements() {
		permissions.Declare(r)
	}
}

func (c *SecurityDefaultsCollector) Requirements() []permissions.Requirement {
	return securityDefaultsRequirements()
}

// Collect reads the security defaults policy and emits one control node. A denied or
// throttled read is a represented gap; the read is never reported Complete on a
// failure.
func (c *SecurityDefaultsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "entra.securityDefaults"
	if !c.budget.Spend() {
		return sink.Complete(c.gap(service, collect.Partial, 0, "budget exhausted"))
	}
	body, err := c.api.get(ctx, graphBaseURL+"/policies/identitySecurityDefaultsEnforcementPolicy")
	if err != nil {
		if ctx.Err() != nil {
			_ = sink.Complete(c.gap(service, collect.Partial, 0, "cancelled"))
			return ctx.Err()
		}
		_ = sink.Complete(c.completeness(service, err))
		if isDenied(err) || isThrottle(err) {
			return nil
		}
		return err
	}
	_ = sink.Evidence(c.evidence(service, body))
	var pol struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		IsEnabled   *bool  `json:"isEnabled"`
	}
	if err := json.Unmarshal(body, &pol); err != nil {
		return sink.Complete(c.gap(service, collect.Errored, 0, redact.String(err.Error())))
	}
	id := pol.ID
	if id == "" {
		id = "identitySecurityDefaultsEnforcementPolicy"
	}
	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: c.tenantID + "/" + id, Name: pol.DisplayName,
		Attributes: attrs("azure_type", "security_defaults", "security_defaults_enabled", boolAttr(pol.IsEnabled))})
	return sink.Complete(c.gap(service, collect.Complete, 1, ""))
}

func (c *SecurityDefaultsCollector) scope() collect.Scope { return collect.Scope{Account: c.tenantID} }

func (c *SecurityDefaultsCollector) evidence(service string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "entra", Operation: service, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: graphAPIVersion, Collector: securityDefaultsCollectorID},
	}
}

func (c *SecurityDefaultsCollector) completeness(service string, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return c.gap(service, status, 0, redact.String(err.Error()))
}

func (c *SecurityDefaultsCollector) gap(service string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}
