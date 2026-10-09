package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// repositoriesCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const repositoriesCollectorID = "collector:github.repositories"

const (
	// perPage is the repository page size requested.
	perPage = 100
	// maxPages bounds how many pages the collector will follow, so an endpoint that
	// returns a next link forever cannot hang the scan. Hitting it is a represented
	// Partial gap. At perPage 100 this covers 100k repositories.
	maxPages = 1000
)

// RepositoriesCollector reads the repositories the authenticated token can see:
// GET /user/repos (paginated by the Link header), a read-only call verified against
// the GitHub REST reference (2022-11-28) that requires only metadata read and returns
// no file content. It emits one repository node per repository, keyed by its full
// name (owner/repo), the canonical id that also lets later pipeline/artifact/workload
// edges join this repository to the rest of the graph.
type RepositoriesCollector struct {
	account string
	api     githubAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewRepositoriesCollector builds the collector with a client that authenticates
// with the resolved token (ADR-0018 §3). budget is the scan's shared call cap.
func NewRepositoriesCollector(account, token string, budget *collect.Budget) *RepositoriesCollector {
	return &RepositoriesCollector{account: account, api: &githubClient{token: token, http: sharedHTTPClient}, budget: budget}
}

// newRepositoriesCollector is the injectable constructor tests use with a stub API.
func newRepositoriesCollector(account string, api githubAPI) *RepositoriesCollector {
	return &RepositoriesCollector{account: account, api: api}
}

func (c *RepositoriesCollector) ID() string               { return repositoriesCollectorID }
func (c *RepositoriesCollector) Provider() model.Provider { return model.GitHub }

// repositoriesRequirements is the read-only permission this collector needs. GitHub
// permissions are token scopes / fine-grained permissions rather than IAM actions;
// listing repositories needs only repository metadata read.
func repositoriesRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GitHub, Profile: permissions.Discovery, Permission: "metadata:read", By: repositoriesCollectorID},
	}
}

func init() {
	for _, r := range repositoriesRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *RepositoriesCollector) Requirements() []permissions.Requirement {
	return repositoriesRequirements()
}

// repository is the subset of the GitHub repositories list response the collector
// reads. It reads no file content, only repository metadata.
type repository struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
}

// Collect reads every repository the token can see, following the Link header, and
// records completeness. Repositories are an account-wide (global) resource. A denied
// or throttled read is a represented gap (Denied or Partial); a read is never
// reported Complete when a page failed.
func (c *RepositoriesCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "repositories"
	scope := collect.Scope{Account: c.account}
	url := fmt.Sprintf("%s/user/repos?per_page=%d&type=all&sort=full_name", githubBaseURL, perPage)
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "page limit reached"})
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return nil
		}
		body, next, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence("repos.list", scope, body))
		var repos []repository
		if err := json.Unmarshal(body, &repos); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, r := range repos {
			_ = sink.Node(collect.Node{
				Type: model.NodeRepository, NativeID: r.FullName, Name: r.Name,
				Attributes: attrs(
					"visibility", r.Visibility,
					"private", boolAttr(r.Private),
					"archived", boolAttr(r.Archived),
					"disabled", boolAttr(r.Disabled),
					"fork", boolAttr(r.Fork),
					"default_branch", r.DefaultBranch,
					"owner", r.Owner.Login,
					"owner_type", r.Owner.Type,
				),
			})
		}
		count += len(repos)
		if next == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Complete, Collected: count})
			return nil
		}
		url = next
	}
}

// completeness maps a failed read to a represented gap: Denied for a 403/401,
// Partial for a throttle, Errored otherwise. It never reports Complete on failure.
func (c *RepositoriesCollector) completeness(service string, scope collect.Scope, count int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: count, Reason: redact.String(err.Error())}
}

// evidence builds the evidence envelope for a GitHub read: the response is redacted
// and stamped with provider, service, operation, scope, and provenance.
func (c *RepositoriesCollector) evidence(operation string, scope collect.Scope, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GitHub, Service: "repositories", Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: repositoriesCollectorID},
	}
}

// attrs builds an attribute map from key/value pairs, dropping empty values so a
// node carries only the facts actually present.
func attrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
