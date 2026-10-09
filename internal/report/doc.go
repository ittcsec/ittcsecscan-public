// Package report renders JSON, SARIF, HTML, PDF, and DOCX from one immutable
// report model.
//
// Status: not implemented.
//
// Invariants this package must uphold:
//   - All five formats are generated from the same frozen model; templates
//     contain no finding logic, and every format carries the same finding IDs
//     and severities.
//   - Coverage and blind spots precede findings.
//   - Untrusted strings (resource names, tags) are escaped for each output
//     format and redaction profiles are applied before rendering.
//   - Every report is hashed and linked to the scan manifest by a receipt.
package report
