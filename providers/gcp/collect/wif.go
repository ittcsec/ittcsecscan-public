package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const wifCollectorID = "collector:gcp.iam.workloadIdentityFederation"

const (
	svcWIFPools     = "iam.workloadIdentityPools"
	svcWIFProviders = "iam.workloadIdentityPoolProviders"
)

// WorkloadIdentityCollector reads the project's workload identity federation
// configuration: the workload identity pools and, for each, its providers. A WIF
// provider establishes trust from an external identity provider (an OIDC issuer, an
// AWS account, or a SAML IdP) so external workloads can impersonate GCP service
// accounts without a key. A provider with a weak or absent attribute condition, or a
// broad issuer/audience, is a standing external-access surface the service-account
// and IAM-policy collectors do not fully capture.
//
// It reads the IAM v1 REST pools and providers lists (both read-only GETs, verified
// 2026-10-04). WIF pools live under locations/global, so this is not a regional
// collector. The provider's attribute mapping and condition are recorded as facts,
// never a verdict: whether a provider's trust is too broad is the rule engine's call.
type WorkloadIdentityCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget
}

// NewWorkloadIdentityCollector builds the collector with a REST client that
// authenticates with a token from the adapter's resolved credential (ADR-0018 §3).
func NewWorkloadIdentityCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *WorkloadIdentityCollector {
	return &WorkloadIdentityCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

func newWorkloadIdentityCollector(projectID string, api gcpAPI) *WorkloadIdentityCollector {
	return &WorkloadIdentityCollector{projectID: projectID, api: api}
}

func (c *WorkloadIdentityCollector) ID() string               { return wifCollectorID }
func (c *WorkloadIdentityCollector) Provider() model.Provider { return model.GCP }

func wifRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: wifCollectorID}
	}
	return []permissions.Requirement{
		req("iam.workloadIdentityPools.list"),
		req("iam.workloadIdentityPoolProviders.list"),
	}
}

func init() {
	for _, r := range wifRequirements() {
		permissions.Declare(r)
	}
}

func (c *WorkloadIdentityCollector) Requirements() []permissions.Requirement {
	return wifRequirements()
}

// Collect lists the pools and their providers, emitting a pool node per pool and a
// provider node per provider with a contains edge. A failure to list the pools
// leaves the providers pass an honest Complete/0; a per-pool provider-list gap is a
// recorded Partial on the providers service.
func (c *WorkloadIdentityCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		_ = sink.Complete(c.gap(svcWIFPools, collect.Unsupported, 0, "the credential has no associated default project to scope to"))
		_ = sink.Complete(c.gap(svcWIFProviders, collect.Unsupported, 0, "the credential has no associated default project to scope to"))
		return nil
	}
	pools, outcome, err := c.listPools(ctx, sink)
	if err != nil {
		return err
	}
	_ = sink.Complete(c.gap(svcWIFPools, outcome.status, len(pools), outcome.reason))
	if !outcome.done {
		_ = sink.Complete(c.gap(svcWIFProviders, collect.Complete, 0, ""))
		return nil
	}

	total := 0
	reason := ""
	for _, pool := range pools {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcWIFProviders, collect.Partial, total, "cancelled"))
			return err
		}
		n, gap := c.poolProviders(ctx, sink, pool)
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
	_ = sink.Complete(c.gap(svcWIFProviders, status, total, reason))
	return nil
}

// wifOutcome is how the pool enumeration ended.
type wifOutcome struct {
	done   bool
	status collect.Status
	reason string
}

// listPools lists the project's workload identity pools, emitting a pool node each.
func (c *WorkloadIdentityCollector) listPools(ctx context.Context, sink collect.Sink) ([]string, wifOutcome, error) {
	base := fmt.Sprintf("%s/projects/%s/locations/global/workloadIdentityPools", iamBaseURL, url.PathEscape(c.projectID))
	pageToken := ""
	var poolNames []string
	for page := 0; ; page++ {
		if page >= maxPages {
			return poolNames, wifOutcome{status: collect.Partial, reason: "page limit reached"}, nil
		}
		if err := ctx.Err(); err != nil {
			return poolNames, wifOutcome{status: collect.Partial, reason: "cancelled"}, err
		}
		if !c.budget.Spend() {
			return poolNames, wifOutcome{status: collect.Partial, reason: "budget exhausted"}, nil
		}
		u := fmt.Sprintf("%s?pageSize=%d", base, pageSize)
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			if isServiceDisabled(err) || isDenied(err) || isThrottle(err) {
				return poolNames, wifOutcome{status: c.statusOf(err), reason: wifReason(err)}, nil
			}
			return poolNames, wifOutcome{}, err
		}
		_ = sink.Evidence(c.evidence("workloadIdentityPools.list", body))
		var resp struct {
			Pools []struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
				State       string `json:"state"`
				Disabled    bool   `json:"disabled"`
			} `json:"workloadIdentityPools"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return poolNames, wifOutcome{status: collect.Errored, reason: redact.String(err.Error())}, nil
		}
		for _, p := range resp.Pools {
			if p.Name == "" {
				continue
			}
			poolNames = append(poolNames, p.Name)
			_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: p.Name, Name: p.DisplayName,
				Attributes: attrs("gcp_type", "wif_pool", "state", p.State, "disabled", strconv.FormatBool(p.Disabled))})
		}
		if resp.NextPageToken == "" {
			return poolNames, wifOutcome{done: true, status: collect.Complete}, nil
		}
		pageToken = resp.NextPageToken
	}
}

// poolProviders lists one pool's providers, emitting a provider node (keyed by its
// resource name) and a contains edge from the pool. It returns the count and a
// reason if the read did not fully complete.
func (c *WorkloadIdentityCollector) poolProviders(ctx context.Context, sink collect.Sink, poolName string) (int, string) {
	base := fmt.Sprintf("%s/%s/providers", iamBaseURL, poolName)
	pageToken := ""
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return count, "page limit reached"
		}
		if !c.budget.Spend() {
			return count, "budget exhausted"
		}
		u := fmt.Sprintf("%s?pageSize=%d", base, pageSize)
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			switch {
			case isServiceDisabled(err):
				return count, "service disabled"
			case isDenied(err):
				return count, "denied"
			case isThrottle(err):
				return count, "throttled"
			default:
				return count, redact.String(err.Error())
			}
		}
		_ = sink.Evidence(c.evidence("workloadIdentityPoolProviders.list", body))
		var resp struct {
			Providers []struct {
				Name               string            `json:"name"`
				DisplayName        string            `json:"displayName"`
				State              string            `json:"state"`
				Disabled           bool              `json:"disabled"`
				AttributeCondition string            `json:"attributeCondition"`
				AttributeMapping   map[string]string `json:"attributeMapping"`
				OIDC               *struct {
					IssuerURI        string   `json:"issuerUri"`
					AllowedAudiences []string `json:"allowedAudiences"`
				} `json:"oidc"`
				AWS *struct {
					AccountID string `json:"accountId"`
				} `json:"aws"`
				SAML *struct {
					IdpMetadataXML string `json:"idpMetadataXml"`
				} `json:"saml"`
			} `json:"workloadIdentityPoolProviders"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return count, redact.String(err.Error())
		}
		for _, p := range resp.Providers {
			if p.Name == "" {
				continue
			}
			c.emitProvider(sink, poolName, p.Name, p.DisplayName, p.State, p.Disabled, p.AttributeCondition, providerKind(p.OIDC != nil, p.AWS != nil, p.SAML != nil), issuerOf(p.OIDC, p.AWS))
			count++
		}
		if resp.NextPageToken == "" {
			return count, ""
		}
		pageToken = resp.NextPageToken
	}
}

func (c *WorkloadIdentityCollector) emitProvider(sink collect.Sink, pool, name, displayName, state string, disabled bool, condition, kind, issuer string) {
	a := map[string]string{
		"gcp_type":                "wif_provider",
		"pool":                    pool,
		"provider_type":           kind,
		"state":                   state,
		"disabled":                strconv.FormatBool(disabled),
		"has_attribute_condition": strconv.FormatBool(condition != ""),
		"attribute_condition":     condition,
		"external_issuer":         issuer,
	}
	_ = sink.Node(collect.Node{Type: model.NodeGateway, NativeID: name, Name: displayName, Attributes: pruneEmptyWIF(a)})
	_ = sink.Link(collect.Link{SourceNativeID: pool, TargetNativeID: name, Kind: model.EdgeContains})
}

// providerKind names the external identity source of a provider.
func providerKind(oidc, aws, saml bool) string {
	switch {
	case oidc:
		return "oidc"
	case aws:
		return "aws"
	case saml:
		return "saml"
	}
	return "unknown"
}

// issuerOf returns the external issuer identifier: the OIDC issuer URI or the AWS
// account id (the SAML metadata XML is a document, not recorded here).
func issuerOf(oidc *struct {
	IssuerURI        string   `json:"issuerUri"`
	AllowedAudiences []string `json:"allowedAudiences"`
}, aws *struct {
	AccountID string `json:"accountId"`
}) string {
	if oidc != nil {
		return oidc.IssuerURI
	}
	if aws != nil {
		return aws.AccountID
	}
	return ""
}

func pruneEmptyWIF(m map[string]string) map[string]string {
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

func (c *WorkloadIdentityCollector) statusOf(err error) collect.Status {
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

func wifReason(err error) string {
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

func (c *WorkloadIdentityCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *WorkloadIdentityCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "iam", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: wifCollectorID},
	}
}

func (c *WorkloadIdentityCollector) gap(service string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}
