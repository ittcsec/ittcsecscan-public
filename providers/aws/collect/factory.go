package collect

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// Collectors builds the AWS read-only collectors for one scan, each with a
// read-only client from the adapter's authenticated config (ADR-0018 §3). It is
// the single place the AWS collector set is enumerated, so adding a collector
// (S3, EC2, and so on) is one line here and the scan command picks it up
// unchanged. The account id comes from the identity adapter's resolved identity.
func Collectors(account string, cfg awssdk.Config, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewIdentityCollector(account, cfg, budget),
		NewCredentialReportCollector(account, cfg, budget),
		NewStorageCollector(account, cfg, budget),
		NewS3AccessPointCollector(account, cfg, budget),
		NewInstanceCollector(account, cfg, budget),
		NewNetworkCollector(account, cfg, budget),
		NewVPCEndpointCollector(account, cfg, budget),
		NewEBSSnapshotCollector(account, cfg, budget),
		NewLambdaCollector(account, cfg, budget),
		NewRDSCollector(account, cfg, budget),
		NewKMSCollector(account, cfg, budget),
		NewLoggingCollector(account, cfg, budget),
		NewSecurityServicesCollector(account, cfg, budget),
		NewOrganizationsCollector(account, cfg, budget),
		NewBedrockAgentsCollector(account, cfg, budget),
	}
}
