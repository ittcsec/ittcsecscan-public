package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// cloudKMSCollectorID is the stable id this collector is credited with.
const cloudKMSCollectorID = "collector:gcp.cloudkms.cryptokeys"

const (
	// cloudKMSBaseURL is the Cloud KMS API v1 endpoint. The collector only issues
	// the read-only locations.list, keyRings.list, and cryptoKeys.list GETs; it
	// never retrieves key material. Cloud KMS keys are non-exportable by design, and
	// the value operations (Decrypt, AsymmetricDecrypt) are POSTs this never makes.
	cloudKMSBaseURL = "https://cloudkms.googleapis.com/v1"
	// cloudKMSAPIVersion is recorded as evidence provenance.
	cloudKMSAPIVersion = "v1"
)

// errBudget is the sentinel a sub-list returns when the scan's shared call budget is
// exhausted mid-fan-out, so the top-level Collect can stop and record one Partial gap
// rather than misreport a budget stop as an unreadable ring.
var errBudget = errors.New("budget exhausted")

func isBudget(err error) bool { return errors.Is(err, errBudget) }

// CloudKMSCollector reads a GCP project's Cloud KMS crypto keys, the GCP counterpart
// of the AWS KMS and Azure Key Vault collectors: the key-management control plane. It
// reads key metadata only (purpose, rotation schedule, protection level, algorithm,
// primary version state); no key material is ever retrieved, the same restraint the
// AWS KMS and Azure Key Vault collectors apply. Reads verified against the Cloud KMS
// API reference (v1, 2026-09-22): projects.locations.list, keyRings.list, and
// cryptoKeys.list are read-only GETs paginated by pageToken.
//
// Cloud KMS keys live under project/location/keyRing, with no single project-global
// list, so the collector fans out: list the project's locations, then each location's
// key rings, then each ring's crypto keys. Each crypto key becomes a control node
// keyed by its full resource name (ADR-0019 §2), and its relative name
// (projects/.../cryptoKeys/{key}) is recorded as a fact so the customer-managed-key
// references the storage, compute, and Cloud SQL collectors record (which use exactly
// that relative form) resolve onto it. Per ADR-0019 §3 no verdict is synthesized:
// rotation period and protection level are raw facts, not a "weak key" conclusion.
type CloudKMSCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewCloudKMSCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3).
func NewCloudKMSCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *CloudKMSCollector {
	return &CloudKMSCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newCloudKMSCollector is the injectable constructor tests use with a stub API.
func newCloudKMSCollector(projectID string, api gcpAPI) *CloudKMSCollector {
	return &CloudKMSCollector{projectID: projectID, api: api}
}

func (c *CloudKMSCollector) ID() string               { return cloudKMSCollectorID }
func (c *CloudKMSCollector) Provider() model.Provider { return model.GCP }

func cloudKMSRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: cloudKMSCollectorID}
	}
	return []permissions.Requirement{
		req("cloudkms.locations.list"),
		req("cloudkms.keyRings.list"),
		req("cloudkms.cryptoKeys.list"),
	}
}

func init() {
	for _, r := range cloudKMSRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *CloudKMSCollector) Requirements() []permissions.Requirement { return cloudKMSRequirements() }

// Collect fans out over the project's locations and key rings to list crypto keys,
// emitting one control node per key. It produces one completeness record,
// cloudkms.cryptoKeys: Complete when every location and ring read succeeded, Partial
// when some did not (with a count in the reason), Denied or Unsupported when the
// top-level locations read itself was refused or the API is disabled. A partial
// sub-read never becomes a pass, and a disabled API is never a denial.
func (c *CloudKMSCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "cloudkms.cryptoKeys"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
	}

	locations, err := c.listNames(ctx, sink, "locations.list",
		fmt.Sprintf("%s/projects/%s/locations", cloudKMSBaseURL, url.PathEscape(c.projectID)), "locations")
	if err != nil {
		// The top-level locations read failed: classify it and stop. Nothing was
		// collected, so this is the whole service's status, never a pass.
		_ = sink.Complete(c.completeness(service, 0, err))
		if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
			return nil
		}
		return err
	}

	count := 0
	degraded := false
	reason := ""
	for _, loc := range locations {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		rings, err := c.listNames(ctx, sink, "keyRings.list",
			fmt.Sprintf("%s/%s/keyRings", cloudKMSBaseURL, loc), "keyRings")
		if err != nil {
			if isBudget(err) {
				_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
				return nil
			}
			degraded = true
			reason = "some key rings or locations unreadable"
			continue
		}
		for _, ring := range rings {
			n, err := c.listKeys(ctx, sink, ring)
			count += n
			if err != nil {
				if isBudget(err) {
					_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
					return nil
				}
				degraded = true
				reason = "some key rings or locations unreadable"
			}
		}
	}
	status := collect.Complete
	if degraded {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: count, Reason: reason})
}

// listNames pages a KMS list whose items carry a "name" and returns the names. It
// records evidence for each page. It returns an error (classified by the caller) on a
// failed read or an exhausted budget (errBudget).
func (c *CloudKMSCollector) listNames(ctx context.Context, sink collect.Sink, op, base, field string) ([]string, error) {
	pageToken := ""
	var out []string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !c.budget.Spend() {
			return nil, errBudget
		}
		u := base
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			return nil, err
		}
		_ = sink.Evidence(c.evidence(op, body))
		var pg kmsNameListPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, err
		}
		items := pg.Locations
		if field == "keyRings" {
			items = pg.KeyRings
		}
		for _, it := range items {
			if it.Name != "" {
				out = append(out, it.Name)
			}
		}
		if pg.NextPageToken == "" {
			return out, nil
		}
		pageToken = pg.NextPageToken
	}
}

// listKeys pages a key ring's crypto keys, emits a control node per key, and returns
// the number emitted. ringName is a relative resource name
// (projects/{p}/locations/{loc}/keyRings/{ring}).
func (c *CloudKMSCollector) listKeys(ctx context.Context, sink collect.Sink, ringName string) (int, error) {
	base := fmt.Sprintf("%s/%s/cryptoKeys", cloudKMSBaseURL, ringName)
	pageToken := ""
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return count, nil
		}
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if !c.budget.Spend() {
			return count, errBudget
		}
		u := base
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			return count, err
		}
		_ = sink.Evidence(c.evidence("cryptoKeys.list", body))
		var pg cryptoKeyListPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return count, err
		}
		for _, k := range pg.CryptoKeys {
			c.emitKey(sink, k)
			count++
		}
		if pg.NextPageToken == "" {
			return count, nil
		}
		pageToken = pg.NextPageToken
	}
}

func (c *CloudKMSCollector) emitKey(sink collect.Sink, k cryptoKey) {
	if k.Name == "" {
		return
	}
	a := map[string]string{
		// The relative name is the exact form the storage, compute, and Cloud SQL
		// CMK references use, so recording it lets those forward-keys join this node.
		"resource_name":       k.Name,
		"purpose":             k.Purpose,
		"rotation_period":     k.RotationPeriod,
		"next_rotation_time":  k.NextRotationTime,
		"crypto_key_backend":  k.CryptoKeyBackend,
		"import_only":         boolStr(k.ImportOnly),
		"rotation_configured": boolStr(k.RotationPeriod != ""),
	}
	if p := k.Primary; p != nil {
		a["primary_state"] = p.State
		a["protection_level"] = p.ProtectionLevel
		a["algorithm"] = p.Algorithm
	}
	if v := k.VersionTemplate; v != nil {
		if a["protection_level"] == "" {
			a["protection_level"] = v.ProtectionLevel
		}
		if a["algorithm"] == "" {
			a["algorithm"] = v.Algorithm
		}
	}
	for lk, lv := range k.Labels {
		if lk != "" {
			a["label:"+lk] = lv
		}
	}
	for ak, av := range a {
		if av == "" {
			delete(a, ak)
		}
	}
	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: "//cloudkms.googleapis.com/" + k.Name, Name: lastPathSegment(k.Name), Attributes: a})
}

func lastPathSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

type kmsNameListPage struct {
	Locations []struct {
		Name string `json:"name"`
	} `json:"locations"`
	KeyRings []struct {
		Name string `json:"name"`
	} `json:"keyRings"`
	NextPageToken string `json:"nextPageToken"`
}

type cryptoKeyListPage struct {
	CryptoKeys    []cryptoKey `json:"cryptoKeys"`
	NextPageToken string      `json:"nextPageToken"`
}

// cryptoKey is the subset of the CryptoKey resource the collector reads (verified
// against the Cloud KMS API reference, v1, 2026-09-22). No key material is read.
type cryptoKey struct {
	Name             string            `json:"name"`
	Purpose          string            `json:"purpose"`
	RotationPeriod   string            `json:"rotationPeriod"`
	NextRotationTime string            `json:"nextRotationTime"`
	ImportOnly       bool              `json:"importOnly"`
	CryptoKeyBackend string            `json:"cryptoKeyBackend"`
	Labels           map[string]string `json:"labels"`
	Primary          *struct {
		State           string `json:"state"`
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	} `json:"primary"`
	VersionTemplate *struct {
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	} `json:"versionTemplate"`
}

func (c *CloudKMSCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *CloudKMSCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "cloudkms", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: cloudKMSAPIVersion, Collector: cloudKMSCollectorID},
	}
}

func (c *CloudKMSCollector) completeness(service string, collected int, err error) collect.Completeness {
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
