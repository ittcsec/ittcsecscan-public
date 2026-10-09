package collect

import (
	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// Collectors builds the GCP read-only collectors for one scan, each with a REST
// client that authenticates with a token from the adapter's resolved credential
// (ADR-0018 §3). It is the single place the GCP collector set is enumerated, so
// adding a collector (the project IAM policy graph, resources, and so on) is one
// line here and the scan command picks it up unchanged. The project id comes from
// the identity adapter's resolved identity and may be empty, which the collector
// records as a gap.
func Collectors(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewIdentityCollector(projectID, tokens, budget),
		NewServiceAccountKeyCollector(projectID, tokens, budget),
		NewWorkloadIdentityCollector(projectID, tokens, budget),
		NewOrgPolicyCollector(projectID, tokens, budget),
		NewPolicyCollector(projectID, tokens, budget),
		NewGroupMembershipCollector(projectID, tokens, budget),
		NewStorageCollector(projectID, tokens, budget),
		NewInstanceCollector(projectID, tokens, budget),
		NewNetworkCollector(projectID, tokens, budget),
		NewCloudSQLCollector(projectID, tokens, budget),
		NewCloudKMSCollector(projectID, tokens, budget),
		NewLoggingCollector(projectID, tokens, budget),
		NewSCCCollector(projectID, tokens, budget),
		NewHierarchyCollector(projectID, tokens, budget),
	}
}
