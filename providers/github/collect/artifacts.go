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

// artifactsCollectorID is the stable id this collector is credited with.
const artifactsCollectorID = "collector:github.artifacts"

// ArtifactsCollector reads each repository's GitHub Actions build artifacts and models
// them as artifact nodes built by their pipeline, the pipeline-to-artifact segment of
// the priority path. For each repository it lists workflow runs (to map a run to its
// workflow path, the pipeline node id) and then the artifacts, both read-only calls
// verified against the GitHub REST reference (2022-11-28) that return no file content
// (the artifact's downloadable contents are a separate endpoint this never reads). It
// emits artifact nodes keyed by "<full_name>/artifacts/<id>" with a builds edge from
// the pipeline that produced them; an artifact whose run cannot be mapped to a
// workflow is attached to its repository with a contains edge so it is never dropped.
//
// The artifact-to-workload join (which cloud workload an artifact deploys to) is a
// tracked gap (EX-2b): the cloud resource's native id is not present in read-only
// GitHub metadata, and inferring it would require reading workflow file contents
// (which the read-only gate forbids) or fabricating the edge. It is left unemitted.
type ArtifactsCollector struct {
	account string
	api     githubAPI
	budget  *collect.Budget
}

// NewArtifactsCollector builds the collector with a client that authenticates with the
// resolved token. budget is the scan's shared call cap (nil is unlimited).
func NewArtifactsCollector(account, token string, budget *collect.Budget) *ArtifactsCollector {
	return &ArtifactsCollector{account: account, api: &githubClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newArtifactsCollector(account string, api githubAPI) *ArtifactsCollector {
	return &ArtifactsCollector{account: account, api: api}
}

func (c *ArtifactsCollector) ID() string               { return artifactsCollectorID }
func (c *ArtifactsCollector) Provider() model.Provider { return model.GitHub }

func artifactsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GitHub, Profile: permissions.Discovery, Permission: "metadata:read", By: artifactsCollectorID},
		{Provider: model.GitHub, Profile: permissions.Discovery, Permission: "actions:read", By: artifactsCollectorID},
	}
}

func init() {
	for _, r := range artifactsRequirements() {
		permissions.Declare(r)
	}
}

func (c *ArtifactsCollector) Requirements() []permissions.Requirement { return artifactsRequirements() }

type runsPage struct {
	WorkflowRuns []struct {
		ID   int64  `json:"id"`
		Path string `json:"path"`
	} `json:"workflow_runs"`
}

type artifactsResponse struct {
	Artifacts []struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		SizeInBytes int64  `json:"size_in_bytes"`
		Expired     bool   `json:"expired"`
		CreatedAt   string `json:"created_at"`
		WorkflowRun struct {
			ID int64 `json:"id"`
		} `json:"workflow_run"`
	} `json:"artifacts"`
}

// Collect lists repositories, then for each maps runs to workflow paths and emits its
// artifacts. It records one completeness for the artifact enumeration: Complete when
// every repository was read, Partial when a repository's read was denied or throttled.
func (c *ArtifactsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "artifacts"
	scope := collect.Scope{Account: c.account}

	repos, denied := c.listRepos(ctx, sink)
	if denied != "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Denied, Reason: denied})
	}

	artifacts := 0
	degraded := ""
	for _, full := range repos {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: artifacts, Reason: "cancelled"})
			return err
		}
		n, err := c.repoArtifacts(ctx, sink, full)
		artifacts += n
		if err != nil && degraded == "" {
			degraded = redact.String(err.Error())
		}
	}
	status := collect.Complete
	if degraded != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: artifacts, Reason: degraded})
}

// listRepos enumerates the repositories the token can see, returning their full names.
func (c *ArtifactsCollector) listRepos(ctx context.Context, sink collect.Sink) ([]string, string) {
	repoURL := fmt.Sprintf("%s/user/repos?per_page=%d&type=all&sort=full_name", githubBaseURL, perPage)
	var full []string
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return full, "budget exhausted"
		}
		body, next, err := c.api.get(ctx, repoURL)
		if err != nil {
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

// repoArtifacts maps the repository's runs to workflow paths, then emits its artifacts
// with a builds edge from the producing pipeline (or a contains edge from the
// repository when the run cannot be mapped). It returns the count and any read error.
func (c *ArtifactsCollector) repoArtifacts(ctx context.Context, sink collect.Sink, full string) (int, error) {
	owner, repo, ok := strings.Cut(full, "/")
	if !ok || owner == "" || repo == "" {
		return 0, nil
	}
	runPath, err := c.runPaths(ctx, sink, owner, repo, full)
	if err != nil {
		return 0, err
	}

	artURL := fmt.Sprintf("%s/repos/%s/%s/actions/artifacts?per_page=%d", githubBaseURL, url.PathEscape(owner), url.PathEscape(repo), perPage)
	count := 0
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return count, fmt.Errorf("budget exhausted before %s artifacts", full)
		}
		body, next, err := c.api.get(ctx, artURL)
		if err != nil {
			return count, fmt.Errorf("%s artifacts: %w", full, err)
		}
		_ = sink.Evidence(c.evidence("actions.artifacts.list", collect.Scope{Account: c.account, Resource: full}, body))
		var resp artifactsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return count, fmt.Errorf("%s artifacts: %w", full, err)
		}
		for _, a := range resp.Artifacts {
			artID := fmt.Sprintf("%s/artifacts/%d", full, a.ID)
			_ = sink.Node(collect.Node{
				Type: model.NodeArtifact, NativeID: artID, Name: a.Name,
				Attributes: attrs("size_bytes", fmt.Sprint(a.SizeInBytes), "expired", boolAttr(a.Expired), "created_at", a.CreatedAt, "repository", full),
			})
			if path, ok := runPath[a.WorkflowRun.ID]; ok && path != "" {
				_ = sink.Link(collect.Link{SourceNativeID: full + "/" + path, TargetNativeID: artID, Kind: model.EdgeBuilds})
			} else {
				// The producing workflow could not be determined: attach to the
				// repository so the artifact is not an orphan, never guess a pipeline.
				_ = sink.Link(collect.Link{SourceNativeID: full, TargetNativeID: artID, Kind: model.EdgeContains})
			}
		}
		count += len(resp.Artifacts)
		if next == "" {
			break
		}
		artURL = next
	}
	return count, nil
}

// runPaths maps a repository's workflow run ids to the workflow path that produced
// them, so an artifact can be linked to its pipeline. It reads one page of recent runs
// (bounded); an unmapped run simply yields a repository contains edge upstream.
func (c *ArtifactsCollector) runPaths(ctx context.Context, sink collect.Sink, owner, repo, full string) (map[int64]string, error) {
	out := map[int64]string{}
	if !c.budget.Spend() {
		return out, fmt.Errorf("budget exhausted before %s runs", full)
	}
	runsURL := fmt.Sprintf("%s/repos/%s/%s/actions/runs?per_page=%d", githubBaseURL, url.PathEscape(owner), url.PathEscape(repo), perPage)
	body, _, err := c.api.get(ctx, runsURL)
	if err != nil {
		return nil, fmt.Errorf("%s runs: %w", full, err)
	}
	_ = sink.Evidence(c.evidence("actions.runs.list", collect.Scope{Account: c.account, Resource: full}, body))
	var runs runsPage
	if err := json.Unmarshal(body, &runs); err != nil {
		return nil, fmt.Errorf("%s runs: %w", full, err)
	}
	for _, r := range runs.WorkflowRuns {
		out[r.ID] = r.Path
	}
	return out, nil
}

func (c *ArtifactsCollector) evidence(operation string, scope collect.Scope, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GitHub, Service: "artifacts", Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: artifactsCollectorID},
	}
}
