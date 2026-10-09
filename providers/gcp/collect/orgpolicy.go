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

const orgPolicyCollectorID = "collector:gcp.orgpolicy.effective"

const (
	orgPolicyBaseURL    = "https://orgpolicy.googleapis.com/v2"
	orgPolicyAPIVersion = "v2"
	svcOrgPolicy        = "orgpolicy.effectivePolicies"
)

// securityConstraints is the curated set of documented GCP organization policy
// boolean constraints with direct security impact. They are real, published GCP
// constraints (not invented): each, when enforced, closes a common misconfiguration
// (downloadable service-account keys, default networks, public SQL IPs, public
// buckets, and so on). The collector reports each constraint's effective enforcement
// at the project (merged with any inherited org/folder policy); it never invents a
// constraint's meaning or asserts one is "good" or "bad".
var securityConstraints = []string{
	"iam.disableServiceAccountKeyCreation",
	"iam.disableServiceAccountKeyUpload",
	"iam.automaticIamGrantsForDefaultServiceAccounts",
	"compute.requireOsLogin",
	"compute.skipDefaultNetworkCreation",
	"compute.disableSerialPortAccess",
	"sql.restrictPublicIp",
	"storage.publicAccessPrevention",
	"storage.uniformBucketLevelAccess",
}

// OrgPolicyCollector reads the effective organization policy for a curated set of
// security-relevant boolean constraints at the project. The organization policy
// service governs account-wide guardrails (for example disabling downloadable
// service-account keys or default networks); whether each guardrail is effectively
// enforced at the project is posture the resource collectors do not see.
//
// It calls projects.policies.getEffectivePolicy per constraint (orgpolicy.policies.get,
// granted by roles/orgpolicy.policyViewer, doc-verified 2026-10-04): the effective
// policy merges any inherited org/folder policy, so it is the real in-force value,
// not just what is set at the project. Each constraint becomes a control node with
// its effective enforcement; a constraint whose read failed, was unparseable, or
// returned a rule shape this boolean collector does not interpret is enforced
// "unknown", never a silent "false".
//
// Scope: the value reported is the effective policy AT THE PROJECT, which Google
// computes server-side by merging any inherited organization/folder policy; it is
// read with project-level orgpolicy.policies.get. The collector reads the merged
// value but not which ancestor set it: a project-scoped service account cannot read
// the organization- or folder-level policy objects themselves (that needs
// orgpolicy.policies.get at those resources), so the source of an inherited policy
// is not attributed. This is recorded as GCP-ORGPOL-1.
type OrgPolicyCollector struct {
	projectID   string
	api         gcpAPI
	budget      *collect.Budget
	constraints []string
}

// NewOrgPolicyCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3).
func NewOrgPolicyCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *OrgPolicyCollector {
	return &OrgPolicyCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget, constraints: securityConstraints}
}

func newOrgPolicyCollector(projectID string, api gcpAPI, constraints []string) *OrgPolicyCollector {
	return &OrgPolicyCollector{projectID: projectID, api: api, constraints: constraints}
}

func (c *OrgPolicyCollector) ID() string               { return orgPolicyCollectorID }
func (c *OrgPolicyCollector) Provider() model.Provider { return model.GCP }

func orgPolicyRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "orgpolicy.policies.get", By: orgPolicyCollectorID},
	}
}

func init() {
	for _, r := range orgPolicyRequirements() {
		permissions.Declare(r)
	}
}

func (c *OrgPolicyCollector) Requirements() []permissions.Requirement { return orgPolicyRequirements() }

// Collect reads the effective policy for each curated constraint and emits a control
// node. The whole operation is one completeness record (orgpolicy.effectivePolicies);
// a denied or service-disabled read before any constraint is a terminal gap, and a
// per-constraint failure is a recorded Partial reason.
func (c *OrgPolicyCollector) Collect(ctx context.Context, sink collect.Sink) error {
	if c.projectID == "" {
		return sink.Complete(c.gap(collect.Unsupported, 0, "the credential has no associated default project to scope to"))
	}
	emitted := 0
	reason := ""
	for i, constraint := range c.constraints {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(collect.Partial, emitted, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.gap(collect.Partial, emitted, "budget exhausted"))
			return nil
		}
		name := fmt.Sprintf("projects/%s/policies/%s", url.PathEscape(c.projectID), constraint)
		u := fmt.Sprintf("%s/%s:getEffectivePolicy", orgPolicyBaseURL, name)
		body, err := c.api.get(ctx, u)
		if err != nil {
			// A denial or disabled API before any constraint read is terminal for the
			// whole collector (the same answer would repeat for every constraint); on
			// the first constraint, record it as the operation's status and stop.
			if isServiceDisabled(err) || isDenied(err) || isThrottle(err) {
				if i == 0 {
					return sink.Complete(c.gap(c.statusOf(err), emitted, orgReason(err)))
				}
				reason = orgReason(err)
				continue
			}
			return err
		}
		_ = sink.Evidence(c.evidence(body))
		enforced, ok := parseEffectiveEnforce(body)
		c.emit(sink, constraint, enforced, ok)
		emitted++
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	return sink.Complete(c.gap(status, emitted, reason))
}

// parseEffectiveEnforce reads whether a boolean constraint's effective policy
// enforces it. ok is false when the spec is absent or unparseable (unknown), so a
// constraint whose effective value could not be determined is never recorded as
// not-enforced.
func parseEffectiveEnforce(body []byte) (enforced bool, ok bool) {
	var p struct {
		Spec *struct {
			Rules []struct {
				Enforce *bool `json:"enforce"`
			} `json:"rules"`
		} `json:"spec"`
	}
	if json.Unmarshal(body, &p) != nil {
		// An unparseable effective-policy response is unknown, never not-enforced: a
		// garbled read must not read as "this guardrail is off".
		return false, false
	}
	if p.Spec == nil {
		// No spec means no policy is in force for this constraint: effectively not
		// enforced (the documented default), which is a known state, not unknown.
		return false, true
	}
	for _, r := range p.Spec.Rules {
		if r.Enforce != nil {
			return *r.Enforce, true
		}
	}
	// A spec with rules that do not carry an enforce flag is a list-constraint shape
	// this boolean-focused collector does not interpret: unknown rather than guessed.
	if len(p.Spec.Rules) > 0 {
		return false, false
	}
	return false, true
}

func (c *OrgPolicyCollector) emit(sink collect.Sink, constraint string, enforced, ok bool) {
	a := map[string]string{
		"gcp_type":   "org_policy",
		"constraint": "constraints/" + constraint,
	}
	if ok {
		a["enforced"] = strconv.FormatBool(enforced)
	} else {
		a["enforced"] = "unknown"
	}
	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: c.projectID + "/orgpolicy/" + constraint,
		Name: constraint, Attributes: a})
}

func (c *OrgPolicyCollector) statusOf(err error) collect.Status {
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

func orgReason(err error) string {
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

func (c *OrgPolicyCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *OrgPolicyCollector) evidence(body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "orgpolicy", Operation: "getEffectivePolicy", Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: orgPolicyAPIVersion, Collector: orgPolicyCollectorID},
	}
}

func (c *OrgPolicyCollector) gap(status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: svcOrgPolicy, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}
