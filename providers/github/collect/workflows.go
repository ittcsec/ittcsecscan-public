package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// workflowsCollectorID is the stable id this collector is credited with.
const workflowsCollectorID = "collector:github.workflows"

// WorkflowsCollector reads each repository's GitHub Actions workflows and models them
// as pipeline nodes contained by their repository, the repository-to-pipeline segment
// of the priority path. It lists repositories (GET /user/repos) to know which to query,
// then GET /repos/{owner}/{repo}/actions/workflows for each, both read-only calls
// verified against the GitHub REST reference (2022-11-28) that return no file content.
// It emits pipeline nodes keyed by "<full_name>/<path>" and a contains edge from the
// repository (keyed by full_name, the same id the repositories collector emits) to the
// pipeline, so the two collectors' output joins in one scan.
type WorkflowsCollector struct {
	account string
	api     githubAPI
	budget  *collect.Budget
}

// NewWorkflowsCollector builds the collector with a client that authenticates with the
// resolved token. budget is the scan's shared call cap (nil is unlimited).
func NewWorkflowsCollector(account, token string, budget *collect.Budget) *WorkflowsCollector {
	return &WorkflowsCollector{account: account, api: &githubClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newWorkflowsCollector(account string, api githubAPI) *WorkflowsCollector {
	return &WorkflowsCollector{account: account, api: api}
}

func (c *WorkflowsCollector) ID() string               { return workflowsCollectorID }
func (c *WorkflowsCollector) Provider() model.Provider { return model.GitHub }

func workflowsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GitHub, Profile: permissions.Discovery, Permission: "metadata:read", By: workflowsCollectorID},
		{Provider: model.GitHub, Profile: permissions.Discovery, Permission: "actions:read", By: workflowsCollectorID},
	}
}

func init() {
	for _, r := range workflowsRequirements() {
		permissions.Declare(r)
	}
}

func (c *WorkflowsCollector) Requirements() []permissions.Requirement { return workflowsRequirements() }

type workflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type workflowsPage struct {
	Workflows []workflow `json:"workflows"`
}

// Collect lists the repositories, then each repository's workflows, emitting pipeline
// nodes and contains edges. It records one completeness for the workflow enumeration:
// Complete when every repository's workflows were read, Partial when some repository's
// read was denied or throttled (named in the reason), never a silent stop.
func (c *WorkflowsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "workflows"
	scope := collect.Scope{Account: c.account}

	repos, denied := c.listRepos(ctx, sink)
	if denied != "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Denied, Reason: denied})
	}

	pipelines := 0
	degraded := ""
	for _, full := range repos {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: pipelines, Reason: "cancelled"})
			return err
		}
		n, err := c.repoWorkflows(ctx, sink, full)
		pipelines += n
		if err != nil {
			if degraded == "" {
				degraded = redact.String(err.Error())
			}
		}
	}
	status := collect.Complete
	if degraded != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: pipelines, Reason: degraded})
}

// listRepos enumerates the repositories the token can see, returning their full names.
// A denied read returns a non-empty reason; the caller records the gap.
func (c *WorkflowsCollector) listRepos(ctx context.Context, sink collect.Sink) ([]string, string) {
	repoURL := fmt.Sprintf("%s/user/repos?per_page=%d&type=all&sort=full_name", githubBaseURL, perPage)
	var full []string
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return full, "budget exhausted"
		}
		body, next, err := c.api.get(ctx, repoURL)
		if err != nil {
			if isDenied(err) || isThrottle(err) {
				return nil, redact.String(err.Error())
			}
			return nil, redact.String(err.Error())
		}
		_ = sink.Evidence(c.evidence("repos.list", collect.Scope{Account: c.account}, body))
		var repos []repository
		if err := json.Unmarshal(body, &repos); err != nil {
			return nil, redact.String(err.Error())
		}
		for _, r := range repos {
			full = append(full, r.FullName)
		}
		if next == "" {
			break
		}
		repoURL = next
	}
	return full, ""
}

// repoWorkflows reads one repository's workflows, emitting a pipeline node and a
// contains edge per workflow. It returns the count and any read error (denial,
// throttle, or decode), which the caller aggregates into a Partial reason.
func (c *WorkflowsCollector) repoWorkflows(ctx context.Context, sink collect.Sink, full string) (int, error) {
	owner, repo, ok := strings.Cut(full, "/")
	if !ok || owner == "" || repo == "" {
		return 0, nil
	}
	wfURL := fmt.Sprintf("%s/repos/%s/%s/actions/workflows?per_page=%d", githubBaseURL, url.PathEscape(owner), url.PathEscape(repo), perPage)
	count := 0
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return count, fmt.Errorf("budget exhausted before %s", full)
		}
		body, next, err := c.api.get(ctx, wfURL)
		if err != nil {
			return count, fmt.Errorf("%s workflows: %w", full, err)
		}
		_ = sink.Evidence(c.evidence("actions.workflows.list", collect.Scope{Account: c.account, Resource: full}, body))
		var page workflowsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return count, fmt.Errorf("%s workflows: %w", full, err)
		}
		for _, w := range page.Workflows {
			pipelineID := full + "/" + w.Path
			_ = sink.Node(collect.Node{
				Type: model.NodePipeline, NativeID: pipelineID, Name: w.Name,
				Attributes: attrs("path", w.Path, "state", w.State, "workflow_id", fmt.Sprint(w.ID), "repository", full),
			})
			_ = sink.Link(collect.Link{SourceNativeID: full, TargetNativeID: pipelineID, Kind: model.EdgeContains})
		}
		count += len(page.Workflows)
		if next == "" {
			break
		}
		wfURL = next
	}
	return count, nil
}

func (c *WorkflowsCollector) evidence(operation string, scope collect.Scope, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GitHub, Service: "workflows", Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: workflowsCollectorID},
	}
}
