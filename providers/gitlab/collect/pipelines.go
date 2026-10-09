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

// pipelinesCollectorID is the stable id this collector is credited with.
const pipelinesCollectorID = "collector:gitlab.pipelines"

// defaultCIConfigPath is GitLab's default CI/CD configuration file, used to key a
// project's pipeline node when the project sets no explicit ci_config_path.
const defaultCIConfigPath = ".gitlab-ci.yml"

// PipelinesCollector models each project's CI/CD pipeline as a pipeline node contained
// by its project, the repository-to-pipeline segment of the priority path. A GitLab
// project has a single root CI configuration (at ci_config_path, default
// .gitlab-ci.yml), unlike GitHub's many workflow files, so this emits at most one
// pipeline node per project, keyed by "<path_with_namespace>/<ci_config_path>".
//
// It lists projects (GET /projects) to know which to query, then GET
// /projects/:id/pipelines for each: a read-only call verified against the GitLab REST
// reference (v4) that returns pipeline run metadata, no file content. The pipelines
// endpoint is used as the authoritative signal that a project actually runs CI: a
// pipeline node is emitted only for a project that has at least one pipeline, so the
// graph never asserts a pipeline where CI is merely enabled but never configured. The
// latest pipeline's status and ref are carried as attributes; the node identity is the
// configuration, not any single run. A contains edge joins the project (keyed by
// path_with_namespace, the same id the projects collector emits) to the pipeline.
type PipelinesCollector struct {
	account string
	api     gitlabAPI
	budget  *collect.Budget
}

// NewPipelinesCollector builds the collector with a client that authenticates with the
// resolved token. budget is the scan's shared call cap (nil is unlimited).
func NewPipelinesCollector(account, token string, budget *collect.Budget) *PipelinesCollector {
	return &PipelinesCollector{account: account, api: &gitlabClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newPipelinesCollector(account string, api gitlabAPI) *PipelinesCollector {
	return &PipelinesCollector{account: account, api: api}
}

func (c *PipelinesCollector) ID() string               { return pipelinesCollectorID }
func (c *PipelinesCollector) Provider() model.Provider { return model.GitLab }

func pipelinesRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GitLab, Profile: permissions.Discovery, Permission: "read_api", By: pipelinesCollectorID},
	}
}

func init() {
	for _, r := range pipelinesRequirements() {
		permissions.Declare(r)
	}
}

func (c *PipelinesCollector) Requirements() []permissions.Requirement { return pipelinesRequirements() }

// projectRef is the subset of a project the pipelines collector needs: the numeric id
// (for the pipelines URL), the path (for keying and the contains edge), and the CI
// configuration path (for the pipeline node key).
type projectRef struct {
	id           int
	path         string
	ciConfigPath string
}

// pipeline is the subset of a GitLab pipeline the collector reads. It reads no file
// content, only pipeline run metadata.
type pipeline struct {
	ID     int    `json:"id"`
	Ref    string `json:"ref"`
	SHA    string `json:"sha"`
	Status string `json:"status"`
	Source string `json:"source"`
	WebURL string `json:"web_url"`
}

// Collect lists the projects, then reads each project's pipelines, emitting one pipeline
// node and a contains edge per project that runs CI. It records one completeness:
// Complete when every project's pipelines were read, Partial when some project's read was
// denied or throttled (named in the reason), Denied when the project listing itself was
// denied, never a silent stop.
func (c *PipelinesCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "pipelines"
	scope := collect.Scope{Account: c.account}

	projects, denied := c.listProjects(ctx, sink)
	if denied != "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Denied, Reason: denied})
	}

	pipelines := 0
	degraded := ""
	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: pipelines, Reason: "cancelled"})
			return err
		}
		n, err := c.projectPipeline(ctx, sink, p)
		pipelines += n
		if err != nil && degraded == "" {
			degraded = redact.String(err.Error())
		}
	}
	status := collect.Complete
	if degraded != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: pipelines, Reason: degraded})
}

// listProjects enumerates the projects the token is a member of, returning the id, path,
// and CI config path of each. A denied read returns a non-empty reason.
func (c *PipelinesCollector) listProjects(ctx context.Context, sink collect.Sink) ([]projectRef, string) {
	url := fmt.Sprintf("%s/projects?membership=true&per_page=%d&order_by=path&sort=asc", gitlabBaseURL, perPage)
	var refs []projectRef
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return refs, "budget exhausted"
		}
		body, next, err := c.api.get(ctx, url)
		if err != nil {
			return nil, redact.String(err.Error())
		}
		_ = sink.Evidence(c.evidence("projects.list", collect.Scope{Account: c.account}, body))
		var projects []project
		if err := json.Unmarshal(body, &projects); err != nil {
			return nil, redact.String(err.Error())
		}
		for _, p := range projects {
			refs = append(refs, projectRef{id: p.ID, path: p.PathWithNamespace, ciConfigPath: p.CIConfigPath})
		}
		if next == "" {
			break
		}
		url = next
	}
	return refs, ""
}

// projectPipeline reads a project's latest pipeline and, if one exists, emits the
// project's pipeline node and a contains edge. It returns the count (0 or 1) and any
// read error (denial, throttle, or decode), which the caller aggregates into a Partial
// reason. A project with no pipeline emits nothing: CI is not asserted without evidence.
func (c *PipelinesCollector) projectPipeline(ctx context.Context, sink collect.Sink, ref projectRef) (int, error) {
	if !c.budget.Spend() {
		return 0, fmt.Errorf("budget exhausted before project %s", ref.path)
	}
	url := fmt.Sprintf("%s/projects/%d/pipelines?per_page=1&order_by=id&sort=desc", gitlabBaseURL, ref.id)
	body, _, err := c.api.get(ctx, url)
	if err != nil {
		return 0, fmt.Errorf("%s pipelines: %w", ref.path, err)
	}
	_ = sink.Evidence(c.evidence("pipelines.list", collect.Scope{Account: c.account, Resource: ref.path}, body))
	var pipelines []pipeline
	if err := json.Unmarshal(body, &pipelines); err != nil {
		return 0, fmt.Errorf("%s pipelines: %w", ref.path, err)
	}
	if len(pipelines) == 0 {
		return 0, nil
	}
	cfg := ref.ciConfigPath
	if cfg == "" {
		cfg = defaultCIConfigPath
	}
	pipelineID := ref.path + "/" + cfg
	latest := pipelines[0]
	_ = sink.Node(collect.Node{
		Type: model.NodePipeline, NativeID: pipelineID, Name: cfg,
		Attributes: attrs(
			"ci_config_path", cfg,
			"repository", ref.path,
			"latest_status", latest.Status,
			"latest_ref", latest.Ref,
			"latest_source", latest.Source,
			"latest_pipeline_id", strconv.Itoa(latest.ID),
		),
	})
	_ = sink.Link(collect.Link{SourceNativeID: ref.path, TargetNativeID: pipelineID, Kind: model.EdgeContains})
	return 1, nil
}

func (c *PipelinesCollector) evidence(operation string, scope collect.Scope, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GitLab, Service: "pipelines", Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: "v4", Collector: pipelinesCollectorID},
	}
}
