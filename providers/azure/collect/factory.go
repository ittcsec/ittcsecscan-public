package collect

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// Collectors builds the Azure read-only collectors for one scan, each with a
// Graph client that mints tokens from the adapter's resolved credential
// (ADR-0018 §3). It is the single place the Azure collector set is enumerated, so
// adding a collector (Azure RBAC role assignments, resources, and so on) is one
// line here and the scan command picks it up unchanged. The tenant id comes from
// the identity adapter's resolved identity.
func Collectors(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewIdentityCollector(tenantID, cred, budget),
		NewAppCredentialCollector(tenantID, cred, budget),
		NewAppRoleAssignmentCollector(tenantID, cred, budget),
		NewRBACCollector(tenantID, cred, budget),
		NewStorageCollector(tenantID, cred, budget),
		NewComputeCollector(tenantID, cred, budget),
		NewNetworkCollector(tenantID, cred, budget),
		NewKeyVaultCollector(tenantID, cred, budget),
		NewDatabaseCollector(tenantID, cred, budget),
		NewLoggingCollector(tenantID, cred, budget),
		NewDefenderCollector(tenantID, cred, budget),
		NewSecurityDefaultsCollector(tenantID, cred, budget),
		NewConditionalAccessCollector(tenantID, cred, budget),
		NewManagementGroupCollector(tenantID, cred, budget),
	}
}
