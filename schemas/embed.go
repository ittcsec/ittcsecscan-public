// Package schemas embeds the versioned JSON Schemas that define ittcsecscan's
// external contracts. The files are the source of truth; Go types are checked
// against them in tests. See README.md for the compatibility policy.
package schemas

import "embed"

// FS holds every schema, addressed by its path relative to this directory,
// for example "config/v1/config.schema.json".
//
//go:embed config cli model permissions collect
var FS embed.FS
