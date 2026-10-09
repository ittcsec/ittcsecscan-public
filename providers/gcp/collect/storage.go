package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// storageCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const storageCollectorID = "collector:gcp.storage.buckets"

const (
	// storageBaseURL is the Cloud Storage JSON API v1 endpoint. The collector only
	// ever issues GETs against the read-only bucket-metadata and bucket-IAM
	// resources below; it never reads object listings or contents (objects.get with
	// alt=media, which the read-only path gate forbids).
	storageBaseURL = "https://storage.googleapis.com/storage/v1"
	// storageAPIVersion is recorded as evidence provenance.
	storageAPIVersion = "v1"
)

// StorageCollector reads a GCP project's Cloud Storage buckets and their
// security-relevant configuration (location, uniform access, public-access
// prevention, default CMEK, versioning, retention, logging, labels, legacy ACL
// public grants) plus each bucket's IAM policy (to detect an actual public
// binding). The reads were verified against the Cloud Storage JSON API reference
// (v1, 2026-09-20): buckets.list (projection=full) and buckets.getIamPolicy are
// read-only GETs, buckets.list paginated by pageToken, and neither returns object
// contents. It records the provider's own facts and does not synthesize an "is
// public" verdict: that belongs to the rule and reachability engines.
//
// Cloud Storage buckets.list is a project-global call, so (like AWS S3) this
// collector is the global-list special case and does not fan out over a region
// set; each bucket's location is recorded as an attribute.
type StorageCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewStorageCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3), over the one
// bounded HTTP client. budget is the scan's shared call cap (nil is unlimited).
func NewStorageCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *StorageCollector {
	return &StorageCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newStorageCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newStorageCollector(projectID string, api gcpAPI) *StorageCollector {
	return &StorageCollector{projectID: projectID, api: api}
}

func (c *StorageCollector) ID() string               { return storageCollectorID }
func (c *StorageCollector) Provider() model.Provider { return model.GCP }

// storageRequirements are the read-only permissions this collector needs, credited
// to it (verified against the Cloud Storage service reference, 2026-09-20), and
// registered at init so the templates reconcile against real code (ADR-0016).
func storageRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.GCP, Profile: permissions.Discovery, Permission: p, By: storageCollectorID}
	}
	return []permissions.Requirement{
		req("storage.buckets.list"),
		req("storage.buckets.getIamPolicy"),
	}
}

func init() {
	for _, r := range storageRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *StorageCollector) Requirements() []permissions.Requirement { return storageRequirements() }

// Collect lists the project's buckets, then reads each bucket's IAM policy. Two
// completeness records are produced: storage.buckets (the list) and
// storage.bucketIam (the per-bucket IAM pass). An absent configuration field (no
// default CMEK, versioning off, uniform access off) is recorded as a fact, never a
// gap: an absent protection is a fact regardless of how the provider signals it.
func (c *StorageCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		_ = sink.Complete(collect.Completeness{Service: "storage.buckets", Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
		return nil
	}
	buckets, err := c.listBuckets(ctx, sink)
	if err != nil {
		return err
	}
	return c.bucketIam(ctx, sink, buckets)
}

// listBuckets reads the project's buckets fully (projection=full), following
// pageToken, and records completeness. It returns the parsed buckets; the nodes
// are emitted after their IAM is read, so each node is emitted once with its
// configuration and IAM facts together.
func (c *StorageCollector) listBuckets(ctx context.Context, sink collect.Sink) ([]gcsBucket, error) {
	const service = "storage.buckets"
	base := fmt.Sprintf("%s/b?project=%s&projection=full", storageBaseURL, url.QueryEscape(c.projectID))
	pageToken := ""
	var out []gcsBucket
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: len(out), Reason: "page limit reached"})
			return out, nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: len(out), Reason: "cancelled"})
			return nil, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: len(out), Reason: "budget exhausted"})
			return out, nil
		}
		u := base
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			_ = sink.Complete(c.completeness(service, collect.Global, len(out), err))
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return nil, nil
			}
			return nil, err
		}
		_ = sink.Evidence(c.evidence("buckets.list", body))
		var page bucketListPage
		if err := json.Unmarshal(body, &page); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: len(out), Reason: redact.String(err.Error())})
			return nil, fmt.Errorf("%s: decoding page: %w", service, err)
		}
		out = append(out, page.Items...)
		if page.NextPageToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: len(out)})
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}

// bucketIam reads each bucket's IAM policy, emits one data-store node per bucket
// (configuration facts plus any public IAM binding), and records one aggregate
// completeness. Every bucket is emitted even if its IAM read is denied or the
// budget runs out, so a bucket is never dropped from the graph; the IAM gap is
// recorded. A per-bucket denial does not stop the others; budget exhaustion stops
// the IAM reads but the remaining buckets are still emitted with their config.
func (c *StorageCollector) bucketIam(ctx context.Context, sink collect.Sink, buckets []gcsBucket) error {
	const service = "storage.bucketIam"
	reason := ""
	done := 0
	exhausted := false
	for _, b := range buckets {
		if b.Name == "" {
			continue
		}
		a := configAttrs(b)
		switch {
		case exhausted:
			reason = "budget exhausted"
		default:
			if err := ctx.Err(); err != nil {
				reason = "cancelled"
				exhausted = true
			} else if !c.budget.Spend() {
				reason = "budget exhausted"
				exhausted = true
			} else if body, err := c.api.get(ctx, storageBaseURL+"/b/"+url.PathEscape(b.Name)+"/iam"); err != nil {
				reason = c.iamGap(err)
			} else {
				_ = sink.Evidence(c.evidence("buckets.getIamPolicy", body))
				addPublicIAM(a, body)
				done++
			}
		}
		_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: bucketResourceName(b.Name), Name: b.Name, Attributes: a})
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: done, Reason: reason})
	return nil
}

// bucketListPage is the subset of the buckets.list response the collector reads.
type bucketListPage struct {
	Items         []gcsBucket `json:"items"`
	NextPageToken string      `json:"nextPageToken"`
}

// gcsBucket is the subset of the Bucket resource the collector reads (verified
// against the Cloud Storage JSON API reference, 2026-09-20). No object listing or
// content is read.
type gcsBucket struct {
	Name             string `json:"name"`
	Location         string `json:"location"`
	LocationType     string `json:"locationType"`
	StorageClass     string `json:"storageClass"`
	IamConfiguration *struct {
		UniformBucketLevelAccess *struct {
			Enabled bool `json:"enabled"`
		} `json:"uniformBucketLevelAccess"`
		PublicAccessPrevention string `json:"publicAccessPrevention"`
	} `json:"iamConfiguration"`
	Encryption *struct {
		DefaultKmsKeyName string `json:"defaultKmsKeyName"`
	} `json:"encryption"`
	Versioning *struct {
		Enabled bool `json:"enabled"`
	} `json:"versioning"`
	RetentionPolicy *struct {
		RetentionPeriod string `json:"retentionPeriod"`
	} `json:"retentionPolicy"`
	Logging *struct {
		LogBucket string `json:"logBucket"`
	} `json:"logging"`
	Labels map[string]string `json:"labels"`
	Acl    []struct {
		Entity string `json:"entity"`
		Role   string `json:"role"`
	} `json:"acl"`
}

// configAttrs records a bucket's configuration facts. The protection facts
// (uniform access, public-access prevention, versioning, customer-managed
// encryption) are recorded even when the underlying field is absent, so an absent
// protection is an explicit fact, never a silent gap.
func configAttrs(b gcsBucket) map[string]string {
	a := map[string]string{
		"location":      b.Location,
		"location_type": b.LocationType,
		"storage_class": b.StorageClass,
	}
	uniform := false
	pap := "inherited" // the API default when unset
	if b.IamConfiguration != nil {
		if u := b.IamConfiguration.UniformBucketLevelAccess; u != nil {
			uniform = u.Enabled
		}
		if b.IamConfiguration.PublicAccessPrevention != "" {
			pap = b.IamConfiguration.PublicAccessPrevention
		}
	}
	a["uniform_bucket_level_access"] = boolStr(uniform)
	a["public_access_prevention"] = pap

	versioning := b.Versioning != nil && b.Versioning.Enabled
	a["versioning"] = map[bool]string{true: "enabled", false: "disabled"}[versioning]

	cmek := b.Encryption != nil && b.Encryption.DefaultKmsKeyName != ""
	a["customer_managed_encryption"] = boolStr(cmek)
	if cmek {
		a["default_kms_key"] = b.Encryption.DefaultKmsKeyName
	}
	if b.RetentionPolicy != nil && b.RetentionPolicy.RetentionPeriod != "" {
		a["retention_period"] = b.RetentionPolicy.RetentionPeriod
	}
	if b.Logging != nil && b.Logging.LogBucket != "" {
		a["log_bucket"] = b.Logging.LogBucket
	}
	for k, v := range b.Labels {
		if k != "" {
			a["label:"+k] = v
		}
	}
	// Legacy ACL public grants (present only when uniform access is off), recorded
	// as facts. allUsers is anyone; allAuthenticatedUsers is any Google account.
	var allUsers, allAuth []string
	for _, e := range b.Acl {
		switch e.Entity {
		case "allUsers":
			allUsers = append(allUsers, e.Role)
		case "allAuthenticatedUsers":
			allAuth = append(allAuth, e.Role)
		}
	}
	if len(allUsers) > 0 {
		a["acl_all_users"] = joinSortedGCS(allUsers)
	}
	if len(allAuth) > 0 {
		a["acl_all_authenticated_users"] = joinSortedGCS(allAuth)
	}
	// Drop empty optional fields; the protection facts above are always non-empty.
	for k, v := range a {
		if v == "" {
			delete(a, k)
		}
	}
	return a
}

// addPublicIAM records the roles a bucket's IAM policy grants to the public
// principals (allUsers, allAuthenticatedUsers) as facts. The "is public"
// conclusion is left to the rule engine.
func addPublicIAM(a map[string]string, body []byte) {
	var pol struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if json.Unmarshal(body, &pol) != nil {
		return
	}
	var allUsers, allAuth []string
	for _, b := range pol.Bindings {
		for _, m := range b.Members {
			switch m {
			case "allUsers":
				allUsers = append(allUsers, b.Role)
			case "allAuthenticatedUsers":
				allAuth = append(allAuth, b.Role)
			}
		}
	}
	if len(allUsers) > 0 {
		a["iam_all_users_roles"] = joinSortedGCS(allUsers)
	}
	if len(allAuth) > 0 {
		a["iam_all_authenticated_users_roles"] = joinSortedGCS(allAuth)
	}
}

// bucketResourceName is the bucket's full (asset-inventory) resource name, the
// canonical id this node is keyed by (ADR-0019 §2), so it is consistent with how
// other GCP assets are keyed.
func bucketResourceName(name string) string {
	return "//storage.googleapis.com/projects/_/buckets/" + name
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func joinSortedGCS(xs []string) string {
	s := append([]string(nil), xs...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// iamGap classifies a per-bucket getIamPolicy error into a gap reason.
func (c *StorageCollector) iamGap(err error) string {
	switch {
	case isServiceDisabled(err):
		return "api disabled"
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	return redact.String(err.Error())
}

func (c *StorageCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

// evidence builds a redacted, secret-free envelope for one read.
func (c *StorageCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "storage", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: storageAPIVersion, Collector: storageCollectorID},
	}
}

// completeness classifies a GCP error into a completeness record with a redacted
// reason (used for the bucket-list read).
func (c *StorageCollector) completeness(service, region string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{
		Service: service, Region: region, Scope: c.scope(),
		Status: status, Collected: collected, Reason: redact.String(err.Error()),
	}
}
