package collect

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// appCredentialCollectorID is the stable id this collector is credited with.
const appCredentialCollectorID = "collector:azure.entra.appCredentials"

// AppCredentialCollector reads the tenant's Entra application registrations and
// their credential expiry metadata: for each app object its key credentials
// (certificates) and password credentials (client secrets), with each
// credential's start and end date, type, and usage. It is the Entra counterpart
// of the AWS access-key age signal: an expired or long-lived app credential is a
// standing authentication risk, and an app with no credential expiry visibility
// cannot be governed.
//
// It is read over the Microsoft Graph /applications list with Application.Read.All,
// the same permission the identity collector already holds (ADR-0036). The read
// returns credential metadata only: Graph never returns a secret value on a read
// (passwordCredentials.secretText is write-once at creation), and this collector
// additionally strips the secret-adjacent passwordCredentials.hint field
// structurally, by building evidence from a hint-free typed model rather than the
// raw wire body, so the hint can never reach evidence (invariant: never log
// sensitive values).
//
// Graph shape: each application becomes a workload node keyed by its object id
// (azure_type app_registration, distinct from the service principal the identity
// collector emits by its own object id); each credential becomes a credential node
// keyed by its keyId, joined to the app by a contains_secret edge. Joining an app
// registration to its service principal by appId is a named follow-up, recorded in
// known-limitations.
type AppCredentialCollector struct {
	tenantID string
	api      graphAPI
	budget   *collect.Budget  // the scan's shared call cap; nil is unlimited
	now      func() time.Time // injectable clock; nil uses time.Now
}

// NewAppCredentialCollector builds the collector with a Graph client that mints a
// Graph-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewAppCredentialCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *AppCredentialCollector {
	return &AppCredentialCollector{tenantID: tenantID, api: &graphClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newAppCredentialCollector is the injectable constructor tests use with a stub
// API and a fixed clock.
func newAppCredentialCollector(tenantID string, api graphAPI, now func() time.Time) *AppCredentialCollector {
	return &AppCredentialCollector{tenantID: tenantID, api: api, now: now}
}

func (c *AppCredentialCollector) ID() string               { return appCredentialCollectorID }
func (c *AppCredentialCollector) Provider() model.Provider { return model.Azure }

func appCredentialRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.Azure, Profile: permissions.Discovery,
		Permission: "Application.Read.All", By: appCredentialCollectorID,
	}}
}

func init() {
	for _, r := range appCredentialRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permission the collector needs.
func (c *AppCredentialCollector) Requirements() []permissions.Requirement {
	return appCredentialRequirements()
}

func (c *AppCredentialCollector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

// Collect lists the application registrations and emits an app node plus a
// credential node per key/password credential with its expiry facts. A denied or
// throttled read is a represented gap; a page is never reported Complete on a
// failure.
func (c *AppCredentialCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "entra.appCredentials"
	url := graphBaseURL + "/applications?$select=id,appId,displayName,keyCredentials,passwordCredentials"
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return sink.Complete(c.gap(service, collect.Partial, count, "page limit reached"))
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(service, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			return sink.Complete(c.gap(service, collect.Partial, count, "budget exhausted"))
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		var env struct {
			Value    []application `json:"value"`
			NextLink string        `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			_ = sink.Complete(c.gap(service, collect.Errored, count, redact.String(err.Error())))
			return err
		}
		// Evidence is built from the hint-free typed model, never the raw body, so
		// the secret-adjacent passwordCredentials.hint cannot reach evidence.
		_ = sink.Evidence(c.evidence(service, env.Value))
		for _, app := range env.Value {
			c.emitApp(sink, app)
			count++
		}
		if env.NextLink == "" {
			return sink.Complete(c.gap(service, collect.Complete, count, ""))
		}
		url = env.NextLink
	}
}

// emitApp maps one application registration to its app node and a credential node
// per key/password credential, with a contains_secret edge from app to credential.
func (c *AppCredentialCollector) emitApp(sink collect.Sink, app application) {
	if app.ID == "" {
		return
	}
	now := c.clock()
	creds := make([]credential, 0, len(app.KeyCredentials)+len(app.PasswordCredentials))
	for _, k := range app.KeyCredentials {
		creds = append(creds, credential{kind: "certificate", keyID: k.KeyID, displayName: k.DisplayName, start: k.StartDateTime, end: k.EndDateTime, usage: k.Usage, ctype: k.Type})
	}
	for _, p := range app.PasswordCredentials {
		creds = append(creds, credential{kind: "client_secret", keyID: p.KeyID, displayName: p.DisplayName, start: p.StartDateTime, end: p.EndDateTime})
	}

	var earliest time.Time
	hasEarliest := false
	expiredCount := 0
	for _, cr := range creds {
		if cr.keyID == "" {
			continue
		}
		end, ok := parseGraphTime(cr.end)
		expired := ok && !end.After(now)
		if expired {
			expiredCount++
		}
		if ok && (!hasEarliest || end.Before(earliest)) {
			earliest, hasEarliest = end, true
		}
		a := map[string]string{
			"azure_type":      "app_credential",
			"credential_type": cr.kind,
			"app_id":          app.AppID,
			"app_object_id":   app.ID,
			"app_name":        app.DisplayName,
			"display_name":    cr.displayName,
			"start_date_time": cr.start,
			"end_date_time":   cr.end,
			"usage":           cr.usage,
			"key_type":        cr.ctype,
		}
		if ok {
			a["expired"] = strconv.FormatBool(expired)
			a["days_until_expiry"] = strconv.Itoa(int(end.Sub(now).Hours() / 24))
		}
		// Credential lifetime (end minus start) in days, so a rule can flag an
		// over-long-lived credential with fact_num while the limit stays in the signed
		// rule. This is static (it does not change day to day), unlike days_until_expiry.
		if start, sok := parseGraphTime(cr.start); sok && ok && end.After(start) {
			a["credential_lifetime_days"] = strconv.Itoa(int(end.Sub(start).Hours() / 24))
		}
		_ = sink.Node(collect.Node{Type: model.NodeCredential, NativeID: cr.keyID, Name: cr.displayName, Attributes: pruneEmptyAzure(a)})
		_ = sink.Link(collect.Link{SourceNativeID: app.ID, TargetNativeID: cr.keyID, Kind: model.EdgeContainsSecret})
	}

	appAttrs := map[string]string{
		"azure_type":       "app_registration",
		"app_id":           app.AppID,
		"credential_count": strconv.Itoa(len(creds)),
	}
	if expiredCount > 0 {
		appAttrs["has_expired_credential"] = "true"
	}
	if hasEarliest {
		appAttrs["earliest_credential_expiry"] = earliest.UTC().Format(time.RFC3339)
	}
	_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: app.ID, Name: app.DisplayName, Attributes: pruneEmptyAzure(appAttrs)})
}

// credential is the normalized, hint-free view of one app credential.
type credential struct {
	kind        string // certificate | client_secret
	keyID       string
	displayName string
	start       string
	end         string
	usage       string // key credentials only
	ctype       string // key credentials only (e.g. AsymmetricX509Cert)
}

// application is the hint-free model of a Graph application registration. It
// deliberately omits passwordCredentials.hint and secretText and keyCredentials.key
// so no secret or secret-adjacent value is parsed, modeled, or placed in evidence.
type application struct {
	ID             string `json:"id"`
	AppID          string `json:"appId"`
	DisplayName    string `json:"displayName"`
	KeyCredentials []struct {
		KeyID         string `json:"keyId"`
		DisplayName   string `json:"displayName"`
		StartDateTime string `json:"startDateTime"`
		EndDateTime   string `json:"endDateTime"`
		Usage         string `json:"usage"`
		Type          string `json:"type"`
	} `json:"keyCredentials"`
	PasswordCredentials []struct {
		KeyID         string `json:"keyId"`
		DisplayName   string `json:"displayName"`
		StartDateTime string `json:"startDateTime"`
		EndDateTime   string `json:"endDateTime"`
	} `json:"passwordCredentials"`
}

// parseGraphTime parses a Graph RFC3339 timestamp; ok is false when the field is
// empty or unparseable, so a missing expiry is represented as unknown, never as
// not-expired.
func parseGraphTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func (c *AppCredentialCollector) scope() collect.Scope { return collect.Scope{Account: c.tenantID} }

// evidence builds a redacted envelope from the hint-free typed applications, so
// the secret-adjacent hint field is absent by construction, not by filtering.
func (c *AppCredentialCollector) evidence(service string, apps []application) collect.Envelope {
	raw, err := json.Marshal(apps)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.Azure, Service: "entra", Operation: service, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: graphAPIVersion, Collector: appCredentialCollectorID},
	}
}

func (c *AppCredentialCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return c.gap(service, status, collected, redact.String(err.Error()))
}

func (c *AppCredentialCollector) gap(service string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}
