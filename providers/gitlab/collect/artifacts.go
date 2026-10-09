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

// artifactsCollectorID is the stable id this collector is credited with.
const artifactsCollectorID = "collector:gitlab.artifacts"

// ArtifactsCollector reads each project's CI/CD job artifacts and models them as
// artifact nodes built by their pipeline, the pipeline-to-artifact segment of the
// priority path. For each project it lists jobs (GET /projects/:id/jobs), a read-only
// call verified against the GitLab REST reference (v4) that returns job metadata
// including artifact filename and size, no artifact content (the downloadable archive
// is a separate endpoint the read-only gate forbids). It emits one artifact node per
// job that produced a build archive, keyed by "<path_with_namespace>/artifacts/<job_id>",
// with a builds edge from the project's pipeline node.
//
// Because a GitLab project has a single pipeline definition (its ci_config_path), every
// job's artifact is built by that one pipeline node; the builds edge target is
// "<path_with_namespace>/<ci_config_path>", the same id the pipelines collector emits,
// so the two collectors' output joins in one scan. There is no run-to-definition
// ambiguity and so no orphan fallback is needed.
//
// The artifact-to-workload join (which cloud workload an artifact deploys to) is a
// tracked gap (GL-4), the same as for GitHub (EX-2b): the cloud resource's native id is
// not present in read-only CI metadata, so it is grounded cloud-side (an OIDC trust
// policy naming the project) rather than fabricated here.
type ArtifactsCollector struct {
	account string
	api     gitlabAPI
	budget  *collect.Budget
}

// NewArtifactsCollector builds the collector with a client that authenticates with the
// resolved token. budget is the scan's shared call cap (nil is unlimited).
func NewArtifactsCollector(account, token string, budget *collect.Budget) *ArtifactsCollector {
	return &ArtifactsCollector{account: account, api: &gitlabClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newArtifactsCollector(account string, api gitlabAPI) *ArtifactsCollector {
	return &ArtifactsCollector{account: account, api: api}
}

func (c *ArtifactsCollector) ID() string               { return artifactsCollectorID }
func (c *ArtifactsCollector) Provider() model.Provider { return model.GitLab }

func artifactsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GitLab, Profile: permissions.Discovery, Permission: "read_api", By: artifactsCollectorID},
	}
}

func init() {
	for _, r := range artifactsRequirements() {
		permissions.Declare(r)
	}
}

func (c *ArtifactsCollector) Requirements() []permissions.Requirement { return artifactsRequirements() }

// job is the subset of a GitLab job the collector reads: identity, the pipeline it
// belongs to, and its artifact metadata. It reads no artifact content.
type job struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	Stage             string `json:"stage"`
	Status            string `json:"status"`
	Ref               string `json:"ref"`
	ArtifactsExpireAt string `json:"artifacts_expire_at"`
	ArtifactsFile     struct {
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
	} `json:"artifacts_file"`
	Artifacts []struct {
		FileType string `json:"file_type"`
		Size     int64  `json:"size"`
		Filename string `json:"filename"`
	} `json:"artifacts"`
}

// Collect lists projects, then for each project reads its jobs and emits the artifact
// nodes and builds edges. It records one completeness: Complete when every project was
// read, Partial when some project's read was denied or throttled (named in the reason),
// Denied when the project listing itself was denied, never a silent stop.
func (c *ArtifactsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "artifacts"
	scope := collect.Scope{Account: c.account}

	projects, denied := c.listProjects(ctx, sink)
	if denied != "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Denied, Reason: denied})
	}

	artifacts := 0
	degraded := ""
	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: artifacts, Reason: "cancelled"})
			return err
		}
		n, err := c.projectArtifacts(ctx, sink, p)
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

// listProjects enumerates the projects the token is a member of, returning the id, path,
// and CI config path of each. A denied read returns a non-empty reason.
func (c *ArtifactsCollector) listProjects(ctx context.Context, sink collect.Sink) ([]projectRef, string) {
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

// projectArtifacts reads a project's jobs and emits an artifact node with a builds edge
// from the project's pipeline for each job that produced a build archive. It returns the
// count and any read error (denial, throttle, or decode), aggregated by the caller.
func (c *ArtifactsCollector) projectArtifacts(ctx context.Context, sink collect.Sink, ref projectRef) (int, error) {
	cfg := ref.ciConfigPath
	if cfg == "" {
		cfg = defaultCIConfigPath
	}
	pipelineID := ref.path + "/" + cfg
	url := fmt.Sprintf("%s/projects/%d/jobs?per_page=%d", gitlabBaseURL, ref.id, perPage)
	count := 0
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return count, fmt.Errorf("budget exhausted before %s jobs", ref.path)
		}
		body, next, err := c.api.get(ctx, url)
		if err != nil {
			return count, fmt.Errorf("%s jobs: %w", ref.path, err)
		}
		_ = sink.Evidence(c.evidence("jobs.list", collect.Scope{Account: c.account, Resource: ref.path}, body))
		var jobs []job
		if err := json.Unmarshal(body, &jobs); err != nil {
			return count, fmt.Errorf("%s jobs: %w", ref.path, err)
		}
		for _, j := range jobs {
			filename, size, ok := archiveOf(j)
			if !ok {
				continue
			}
			artID := fmt.Sprintf("%s/artifacts/%d", ref.path, j.ID)
			_ = sink.Node(collect.Node{
				Type: model.NodeArtifact, NativeID: artID, Name: filename,
				Attributes: attrs(
					"size_bytes", strconv.FormatInt(size, 10),
					"job", j.Name,
					"stage", j.Stage,
					"ref", j.Ref,
					"expires_at", j.ArtifactsExpireAt,
					"repository", ref.path,
				),
			})
			_ = sink.Link(collect.Link{SourceNativeID: pipelineID, TargetNativeID: artID, Kind: model.EdgeBuilds})
			count++
		}
		if next == "" {
			break
		}
		url = next
	}
	return count, nil
}

// archiveOf returns the build archive's filename and size for a job, and whether the job
// produced one. The archive is the artifacts_file (the downloadable build output); when
// that is absent it falls back to an entry of file_type "archive" in the artifacts array.
// A job with no archive (only reports such as trace or junit, or none) yields no node.
func archiveOf(j job) (filename string, size int64, ok bool) {
	if j.ArtifactsFile.Filename != "" {
		return j.ArtifactsFile.Filename, j.ArtifactsFile.Size, true
	}
	for _, a := range j.Artifacts {
		if a.FileType == "archive" && a.Filename != "" {
			return a.Filename, a.Size, true
		}
	}
	return "", 0, false
}

func (c *ArtifactsCollector) evidence(operation string, scope collect.Scope, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GitLab, Service: "artifacts", Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: scope,
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: "v4", Collector: artifactsCollectorID},
	}
}
