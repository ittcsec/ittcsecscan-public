// Package live holds the maintainer-run live verification harness for the permission
// templates (ADR-0016 §3). Its tests build only under the "live" tag, so CI,
// which never holds cloud credentials, never compiles or runs them.
//
// It is a separate package, not a test file inside permissions, so it can import
// both the permission templates and the provider adapters without the import
// cycle that would appear once the collectors import permissions to
// declare their requirements.
package live
