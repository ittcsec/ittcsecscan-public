package collect

// regionSetVersion identifies the declared region set below (ADR-0019 §1). Bump
// it whenever the set changes, so a scan's region coverage is traceable to the
// reviewed list it used.
const regionSetVersion = "aws-commercial-regions/2026-09-19"

// defaultRegions is the static, versioned set of AWS commercial (aws partition)
// Regions a regional collector enumerates (ADR-0019 §1). It is the full commercial
// set: both the Regions enabled by default and the opt-in Regions, as listed in
// the AWS global-infrastructure reference ("AWS Regions", verified 2026-09-19).
//
// The full set is deliberate (owner decision, "completeness over noise"): a
// Region a customer has actually enabled must never fall silently outside the
// tool's view. A Region the account has not opted into answers an EC2 Describe
// with OptInRequired/AuthFailure, which a regional collector records as an honest
// Unsupported gap ("region not enabled"), not a silent skip and not a false empty
// (see isRegionNotEnabled). The aws-cn and aws-us-gov partitions are separate
// account types unreachable from an aws-partition credential and are documented
// blind spots (docs/known-limitations.md), not part of this set.
//
// Regions are enumerated sequentially in this order (ADR-0019 §1), so a scan is
// deterministic.
var defaultRegions = []string{
	// Enabled by default.
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"ap-south-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-northeast-3",
	"ap-southeast-1",
	"ap-southeast-2",
	"ca-central-1",
	"eu-central-1",
	"eu-north-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"sa-east-1",
	// Opt-in (disabled unless the account enabled them; a not-enabled Region is
	// recorded Unsupported "region not enabled").
	"af-south-1",
	"ap-east-1",
	"ap-east-2",
	"ap-south-2",
	"ap-southeast-3",
	"ap-southeast-4",
	"ap-southeast-5",
	"ap-southeast-6",
	"ap-southeast-7",
	"ca-west-1",
	"eu-central-2",
	"eu-south-1",
	"eu-south-2",
	"il-central-1",
	"me-central-1",
	"me-south-1",
	"mx-central-1",
}
