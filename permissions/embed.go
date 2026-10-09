// Package permissions is the least-privilege permission-template contract
// (ADR-0016 §3). It holds the checked-in, schema-validated
// template files (one per provider per profile), the Go types that load them,
// the mechanism by which collectors declare the permissions they need, and the
// verification gate that keeps a template from claiming it is verified without
// evidence.
//
// The templates are deliberately empty until the collectors declare their needs: a least-privilege
// permission is justified by the collector or rule that needs it, and those do
// not exist yet. This package proves the mechanism against that empty state, the
// way the migration framework and the encryption counter were proven against
// placeholder data before real complexity existed. It imports no cloud SDK and
// makes no provider call; the live verification harness is a separate, maintainer-run
// build.
package permissions

import "embed"

// FS holds the checked-in template files, addressed by "<provider>/<profile>.json".
//
//go:embed aws azure gcp github gitlab kubernetes okta google_workspace mcp
var FS embed.FS
