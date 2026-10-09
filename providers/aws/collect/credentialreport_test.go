package collect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubCredReport is an offline credentialReportAPI: GenerateCredentialReport may error;
// GetCredentialReport returns ReportInProgress `pending` times, then the content (or getErr).
type stubCredReport struct {
	genErr  error
	getErr  error
	pending int
	content []byte
	gets    int
}

func (s *stubCredReport) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	if s.genErr != nil {
		return nil, s.genErr
	}
	return &iam.GenerateCredentialReportOutput{}, nil
}

func (s *stubCredReport) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	s.gets++
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.gets <= s.pending {
		return nil, apiErr("ReportInProgress")
	}
	return &iam.GetCredentialReportOutput{Content: s.content}, nil
}

const credCSV = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n" +
	"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,2026-09-01T00:00:00+00:00,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n" +
	"ittcsecscan-test,arn:aws:iam::123456789012:user/ittcsecscan-test,2024-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2024-01-02T00:00:00+00:00,2026-09-15T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"

// credNow is the fixed clock the credential-report tests use, so key ages are
// deterministic.
func credNow() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) }

func runCredReport(t *testing.T, api credentialReportAPI) collect.Scan {
	t.Helper()
	c := newCredentialReportCollector(acctID, api)
	c.now = credNow
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestCredentialReportMapsUsers proves the report becomes identity nodes keyed by ARN with
// the credential-hygiene facts (MFA, key last-used/age), for both the root account and a user.
func TestCredentialReportMapsUsers(t *testing.T) {
	s := runCredReport(t, &stubCredReport{content: []byte(credCSV)})
	if c := completenessOf(s, svcCredentialReport); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("%s = %+v, want complete/2", svcCredentialReport, c)
	}
	user, ok := nodeOf(s, model.NodeIdentity, "arn:aws:iam::123456789012:user/ittcsecscan-test")
	if !ok {
		t.Fatal("user not emitted from the credential report")
	}
	for k, v := range map[string]string{ //nolint:gosec // G101: these are fact-name keys, not credentials
		"credential_report": "true", "cred_mfa_active": "false", "cred_access_key_1_active": "true",
		"cred_access_key_1_last_used_date": "2026-09-15T00:00:00+00:00", "cred_access_key_1_last_used_service": "iam",
		// now=2026-10-05: last used 2026-09-15 is 20 days ago; rotated 2024-01-02 is 1007 days ago.
		"cred_access_key_1_never_used": "false", "cred_access_key_1_last_used_age_days": "20", "cred_access_key_1_age_days": "1007",
	} {
		if user.Attributes[k] != v {
			t.Errorf("user fact %s = %q, want %q", k, user.Attributes[k], v)
		}
	}
	if _, ok := nodeOf(s, model.NodeIdentity, "arn:aws:iam::123456789012:root"); !ok {
		t.Error("root account not emitted from the credential report")
	}
}

// TestCredentialReportDeniedIsGap proves a denied generate is an honest Denied gap, no nodes.
func TestCredentialReportDeniedIsGap(t *testing.T) {
	s := runCredReport(t, &stubCredReport{genErr: apiErr("AccessDenied")})
	if statusOf(s, svcCredentialReport) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcCredentialReport, statusOf(s, svcCredentialReport))
	}
	if nodesByType(s)[model.NodeIdentity] != 0 {
		t.Error("no nodes should be emitted when the report is denied")
	}
}

// TestCredentialReportPendingThenComplete proves the generate/poll loop waits out the
// in-progress state and then parses the report.
func TestCredentialReportPendingThenComplete(t *testing.T) {
	s := runCredReport(t, &stubCredReport{pending: 2, content: []byte(credCSV)})
	if statusOf(s, svcCredentialReport) != collect.Complete {
		t.Errorf("%s = %s, want complete after polling", svcCredentialReport, statusOf(s, svcCredentialReport))
	}
}

// TestCredentialReportNeverCompletes proves an endlessly-in-progress report is Partial, not a
// false empty-complete.
func TestCredentialReportNeverCompletes(t *testing.T) {
	s := runCredReport(t, &stubCredReport{pending: 1000, content: []byte(credCSV)})
	if c := completenessOf(s, svcCredentialReport); c.Status != collect.Partial {
		t.Errorf("%s = %+v, want partial (never completed)", svcCredentialReport, c)
	}
	if nodesByType(s)[model.NodeIdentity] != 0 {
		t.Error("no nodes should be emitted when the report never completed")
	}
}

// TestCredentialReportNoKeyIdInEvidence proves no access-key id leaks into evidence (the
// report carries no key material, but this is the belt-and-braces check every AWS collector has).
func TestCredentialReportNoKeyIdInEvidence(t *testing.T) {
	s := runCredReport(t, &stubCredReport{content: []byte(credCSV)})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
}
