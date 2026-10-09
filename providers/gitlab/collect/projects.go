package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// projectsCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const projectsCollectorID = "collector:gitlab.projects"

const (
	// perPage is the project page size requested.
	perPage = 100
	// maxPages bounds how many pages the collector will follow, so an endpoint that
	// returns a next link forever cannot hang the scan. Hitting it is a represented
	// Partial gap. At perPage 100 this covers 100k projects.
	maxPages = 1000
)

// ProjectsCollector reads the projects the authenticated token is a member of:
// GET /projects?membership=true (paginated by the Link header), a read-only call
// verified against the GitLab REST reference (v4) that needs only read_api and returns
// no file content. It emits one repository node per project, keyed by its
// path_with_namespace (group/project), the canonical id that also lets later
// pipeline/artifact/workload edges join this project to the rest of the graph. It maps
// GitLab projects onto the shared NodeRepository type, the same node the GitHub
// repositories collector emits, so both source-control systems share one graph shape.
type ProjectsCollector struct {
	account string
	api     gitlabAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewProjectsCollector builds the collector with a client that authenticates with the
// resolved token (ADR-0018 §3). budget is the scan's shared call cap.
func NewProjectsCollector(account, token string, budget *collect.Budget) *ProjectsCollector {
	return &ProjectsCollector{account: account, api: &gitlabClient{token: token, http: sharedHTTPClient}, budget: budget}
}

// newProjectsCollector is the injectable constructor tests use with a stub API.
func newProjectsCollector(account string, api gitlabAPI) *ProjectsCollector {
	return &ProjectsCollector{account: account, api: api}
}

func (c *ProjectsCollector) ID() string               { return projectsCollectorID }
func (c *ProjectsCollector) Provider() model.Provider { return model.GitLab }

// projectsRequirements is the read-only permission this collector needs. GitLab
// permissions are token scopes rather than IAM actions; listing projects needs only
// read_api.
func projectsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GitLab, Profile: permissions.Discovery, Permission: "read_api", By: projectsCollectorID},
	}
}

func init() {
	for _, r := range projectsRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *ProjectsCollector) Requirements() []permissions.Requirement {
	return projectsRequirements()
}

// project is the subset of the GitLab projects list response the collector reads. It
// reads no file content, only project metadata.
type project struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	Name              string `json:"name"`
	Visibility        string `json:"visibility"`
	Archived          bool   `json:"archived"`
	DefaultBranch     string `json:"default_branch"`
	WebURL            string `json:"web_url"`
	CIConfigPath      string `json:"ci_config_path"`
	Namespace         struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	} `json:"namespace"`
	ForkedFrom *struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"forked_from_project"`
}

// Collect reads every project the token is a member of, following the Link header, and
// records completeness. Projects are an account-wide (global) resource. A denied or
// throttled read is a represented gap (Denied or Partial); a read is never reported
// Complete when a page failed.
func (c *ProjectsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "projects"
	scope := collect.Scope{Account: c.account}
	url := fmt.Sprintf("%s/projects?membership=true&per_page=%d&order_by=path&sort=asc", gitlabBaseURL, perPage)
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
		_ = sink.Evidence(c.evidence("projects.list", scope, body))
		var projects []project
		if err := json.Unmarshal(body, &projects); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, p := range projects {
			fork := ""
			if p.ForkedFrom != nil {
				fork = "true"
			}
			_ = sink.Node(collect.Node{
				Type: model.NodeRepository, NativeID: p.PathWithNamespace, Name: p.Name,
				Attributes: attrs(
					"visibility", p.Visibility,
					"archived", boolAttr(p.Archived),
					"fork", fork,
					"default_branch", p.DefaultBranch,
					"namespace", p.Namespace.Path,
					"namespace_kind", p.Namespace.Kind,
					"web_url", p.WebURL,
					"gitlab_id", strconv.Itoa(p.ID),
				),
			})
		}
		count += len(projects)
		if next == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Complete, Collected: count})
			return nil
		}
		url = next
	}
}

// completeness maps a failed read to a represented gap: Denied for a 403/401, Partial
// for a throttle, Errored otherwise. It never reports Complete on failure.
func (c *ProjectsCollector) completeness(service string, scope collect.Scope, count int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: count, Reason: redact.String(err.Error())}
}

// evidence builds the evidence envelope for a GitLab read: the response is redacted
// and stamped with provider, service, operation, scope, and provenance.
func (c *ProjectsCollector) evidence(operation string, scope collect.Scope, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GitLab, Service: "projects", Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: "v4", Collector: projectsCollectorID},
	}
}

// attrs builds an attribute map from key/value pairs, dropping empty values so a node
// carries only the facts actually present.
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
