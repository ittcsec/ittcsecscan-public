package collect

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const credentialReportCollectorID = "collector:aws.iam.credentialReport"

// svcCredentialReport is the completeness service for the credential report.
const svcCredentialReport = "iam.credentialReport" //nolint:gosec // G101: a completeness service name, not a credential

// credReportMaxPolls bounds the generate/poll loop; a report normally completes in a few
// seconds. Beyond this the collector records Partial rather than waiting unbounded.
const credReportMaxPolls = 6

// credentialReportAPI is the read-only IAM surface for the account credential report. The
// report is account-wide metadata (last-used dates, key age, MFA, root use); it carries no
// secret value (AWS "Getting credential reports", verified 2026-10-04).
type credentialReportAPI interface {
	GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

// CredentialReportCollector reads the account's IAM credential report: per IAM user (and the
// root account) the last-used dates, access-key age and last-used, MFA status, and password
// state. It is the authoritative dormant-credential source for IAM users and access keys
// (ADR-0035). It merges its facts onto the user nodes the identity collector already emits
// (same native id, the user ARN), so one user carries both its authorization graph and its
// credential hygiene.
type CredentialReportCollector struct {
	account string
	api     credentialReportAPI
	budget  *collect.Budget
	sleep   func(time.Duration) // injectable; nil uses time.Sleep (no-op in tests that return COMPLETE first)
	now     func() time.Time    // injectable clock; nil uses time.Now
}

func (c *CredentialReportCollector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

// NewCredentialReportCollector builds the collector with a read-only IAM client.
func NewCredentialReportCollector(account string, cfg awssdk.Config, budget *collect.Budget) *CredentialReportCollector {
	return &CredentialReportCollector{account: account, api: iam.NewFromConfig(cfg), budget: budget}
}

// newCredentialReportCollector is the injectable constructor tests use with a stub API.
func newCredentialReportCollector(account string, api credentialReportAPI) *CredentialReportCollector {
	return &CredentialReportCollector{account: account, api: api, sleep: func(time.Duration) {}}
}

func (c *CredentialReportCollector) ID() string               { return credentialReportCollectorID }
func (c *CredentialReportCollector) Provider() model.Provider { return model.AWS }

func credentialReportRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: credentialReportCollectorID}
	}
	return []permissions.Requirement{
		req("iam:GenerateCredentialReport"),
		req("iam:GetCredentialReport"),
	}
}

func init() {
	for _, r := range credentialReportRequirements() {
		permissions.Declare(r)
	}
}

func (c *CredentialReportCollector) Requirements() []permissions.Requirement {
	return credentialReportRequirements()
}

func (c *CredentialReportCollector) napFor(d time.Duration) {
	if c.sleep != nil {
		c.sleep(d)
		return
	}
	time.Sleep(d)
}

// Collect generates and reads the credential report, parses the CSV, and emits one node per
// user (and root) with the credential-hygiene facts. A report that never reaches COMPLETE
// within the bounded polls is Partial; a denial is Denied; a parse failure is Errored. It
// never reports Complete on a report that was not read.
func (c *CredentialReportCollector) Collect(ctx context.Context, sink collect.Sink) error {
	scope := collect.Scope{Account: c.account}
	complete := func(status collect.Status, n int, reason string) error {
		return sink.Complete(collect.Completeness{Service: svcCredentialReport, Region: collect.Global, Scope: scope, Status: status, Collected: n, Reason: reason})
	}

	content, status, reason, err := c.fetchReport(ctx, sink)
	if err != nil {
		return err // a real transport/unexpected error surfaces; the gap is already recorded below
	}
	if status != collect.Complete {
		return complete(status, 0, reason)
	}

	rows, perr := parseCredentialCSV(content)
	if perr != nil {
		return complete(collect.Errored, 0, redact.String(perr.Error()))
	}
	n := 0
	for _, row := range rows {
		arn := row["arn"]
		if arn == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeIdentity, NativeID: arn, Attributes: credentialFacts(row, c.clock())})
		n++
	}
	return complete(collect.Complete, n, "")
}

// fetchReport generates the report if needed and reads it, returning the CSV content and the
// completeness status to record. It records evidence for the read.
func (c *CredentialReportCollector) fetchReport(ctx context.Context, sink collect.Sink) ([]byte, collect.Status, string, error) {
	if !c.budget.Spend() {
		return nil, collect.Partial, "budget exhausted", nil
	}
	if _, err := c.api.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		if ctx.Err() != nil {
			return nil, collect.Partial, "cancelled", ctx.Err()
		}
		if st, done := classifyCredErr(err); done {
			return nil, st, credReason(st, err), nil
		}
		return nil, collect.Errored, redact.String(err.Error()), err
	}
	for attempt := 0; attempt < credReportMaxPolls; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, collect.Partial, "cancelled", err
		}
		if !c.budget.Spend() {
			return nil, collect.Partial, "budget exhausted", nil
		}
		out, err := c.api.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil && out != nil && len(out.Content) > 0 {
			_ = sink.Evidence(c.evidence("GetCredentialReport", out))
			return out.Content, collect.Complete, "", nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, collect.Partial, "cancelled", ctx.Err()
			}
			if st, done := classifyCredErr(err); done {
				return nil, st, credReason(st, err), nil
			}
			if !isReportPending(err) {
				return nil, collect.Errored, redact.String(err.Error()), err
			}
		}
		c.napFor(2 * time.Second) // the report is still generating; bounded wait
	}
	return nil, collect.Partial, "credential report did not complete within the poll budget", nil
}

// isReportPending reports the transient "still generating" or "regenerate" states.
func isReportPending(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "ReportInProgress", "ReportNotPresent", "ReportExpired":
		return true
	}
	return false
}

// classifyCredErr maps a credential-report error to a terminal completeness status. It
// returns done=true for a represented gap (denied, region-not-enabled, throttle, transport),
// done=false for an unexpected error the caller should surface.
func classifyCredErr(err error) (collect.Status, bool) {
	switch {
	case isDenied(err):
		return collect.Denied, true
	case isRegionNotEnabled(err):
		return collect.Unsupported, true
	case isThrottle(err):
		return collect.Partial, true
	case isTransport(err):
		return collect.Partial, true
	}
	return collect.Errored, false
}

func credReason(st collect.Status, err error) string {
	switch st {
	case collect.Denied:
		return "denied"
	case collect.Unsupported:
		return "region not enabled"
	case collect.Partial:
		if isThrottle(err) {
			return "throttled"
		}
		return "unreachable"
	}
	return redact.String(err.Error())
}

// credentialFacts maps a credential-report row to the node facts. The report has no secret
// value; every field is metadata (timestamps, booleans, regions, services).
func credentialFacts(row map[string]string, now time.Time) map[string]string {
	out := map[string]string{"credential_report": "true"}
	// Bulk metadata facts kept for evidence/context; no rule thresholds these, so they
	// are composed in a loop.
	for _, k := range []string{
		"user_creation_time", "password_last_used", "password_last_changed",
		"access_key_1_last_rotated", "access_key_1_last_used_date", "access_key_1_last_used_region", "access_key_1_last_used_service",
		"access_key_2_last_rotated", "access_key_2_last_used_date", "access_key_2_last_used_region", "access_key_2_last_used_service",
		"cert_1_active", "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated",
	} {
		if v := row[k]; v != "" {
			out["cred_"+k] = v
		}
	}
	// Facts the identity-hygiene rules read are emitted with full literal keys, so the
	// rule-groundedness guard (which greps collector source for each fact key) sees them.
	credPut(out, "cred_user", row["user"])
	credPut(out, "cred_password_enabled", row["password_enabled"])
	credPut(out, "cred_mfa_active", row["mfa_active"])
	credPut(out, "cred_access_key_1_active", row["access_key_1_active"])
	credPut(out, "cred_access_key_2_active", row["access_key_2_active"])
	// Per active key, the age and never-used facts, so a rule can threshold key age
	// numerically (fact_num) without parsing dates; the policy (how old is too old) stays
	// in the signed rule. A sentinel ("N/A", "no_information", "not_supported") is not a
	// date: a last-used sentinel means the key was never used, so never_used is set and no
	// last-used age is emitted (unknown, never zero).
	if row["access_key_1_active"] == "true" {
		if t, ok := parseCredTime(row["access_key_1_last_used_date"]); ok {
			out["cred_access_key_1_last_used_age_days"] = strconv.Itoa(ageDays(now, t))
			out["cred_access_key_1_never_used"] = "false"
		} else {
			out["cred_access_key_1_never_used"] = "true"
		}
		if t, ok := parseCredTime(row["access_key_1_last_rotated"]); ok {
			out["cred_access_key_1_age_days"] = strconv.Itoa(ageDays(now, t))
		}
	}
	if row["access_key_2_active"] == "true" {
		if t, ok := parseCredTime(row["access_key_2_last_used_date"]); ok {
			out["cred_access_key_2_last_used_age_days"] = strconv.Itoa(ageDays(now, t))
			out["cred_access_key_2_never_used"] = "false"
		} else {
			out["cred_access_key_2_never_used"] = "true"
		}
		if t, ok := parseCredTime(row["access_key_2_last_rotated"]); ok {
			out["cred_access_key_2_age_days"] = strconv.Itoa(ageDays(now, t))
		}
	}
	return out
}

// credPut sets a non-empty fact.
func credPut(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// parseCredTime parses a credential-report timestamp. Sentinels ("N/A",
// "no_information", "not_supported", "") are not dates and return ok=false.
func parseCredTime(s string) (time.Time, bool) {
	switch s {
	case "", "N/A", "no_information", "not_supported":
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ageDays is whole days between t and now (never negative).
func ageDays(now, t time.Time) int {
	d := int(now.Sub(t).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return d
}

// parseCredentialCSV parses the credential-report CSV into header-keyed rows.
func parseCredentialCSV(content []byte) ([]map[string]string, error) {
	r := csv.NewReader(bytes.NewReader(content))
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	var rows []map[string]string
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		m := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(rec) {
				m[h] = rec[i]
			}
		}
		rows = append(rows, m)
	}
	return rows, nil
}

func (c *CredentialReportCollector) evidence(operation string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "iam", Operation: operation, Region: collect.Global,
		Scope:      collect.Scope{Account: c.account},
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: iamAPIVersion, Collector: credentialReportCollectorID},
	}
}
