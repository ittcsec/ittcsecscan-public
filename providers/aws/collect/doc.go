// Package collect holds the AWS collectors: read-only readers that turn AWS
// resources into the provider-neutral graph, evidence, and completeness the
// collection framework defines (internal/collect, ADR-0018). Each collector is
// built with a read-only AWS client from the identity adapter's resolved config
// (providers/aws, ADR-0018 §3), so the AWS SDK stays confined here.
//
// The read-only API calls each collector makes are verified against the AWS API
// reference before they ship: they retrieve metadata and
// configuration only, never a secret value or object content, and never write.
package collect
