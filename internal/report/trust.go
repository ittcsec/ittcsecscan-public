package report

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// ITTCsecTrust (item 9): a shareable, independently verifiable trust report. A scan's
// immutable report model is serialized to JSON (the authoritative format), and the operator
// signs those exact bytes offline with their own key, in a namespace dedicated to reports.
// Anyone the operator hands the report, its signature, and the operator's public key to can
// verify, with this tool or with stock ssh-keygen, that the report is authentic and
// unaltered: independently verifiable proof of a scan's results, with no server.
//
// Signing stays an offline ceremony with ssh-keygen, exactly as release, pack, and update
// signing do; the product never handles a signing key, it only verifies. Verification is
// in-process and fail closed.

// TrustNamespace is the sshsig namespace for signed trust reports. It is distinct from the
// release, pack, and update namespaces, so a signature made for one purpose can never be
// replayed as another.
const TrustNamespace = "ittcsecscan-report"

// ErrReportHashMismatch is returned when a report's embedded content hash does not match a
// recomputation over its own fields: the JSON was altered after the model was frozen, so it
// is not the report that was signed.
var ErrReportHashMismatch = errors.New("report content hash does not match the report body")

// SignableBytes returns the exact bytes that are signed for a trust report: the
// authoritative indented JSON serialization (the same bytes written to report.json). The
// operator signs these; a verifier checks the signature over them.
func SignableBytes(r Report) ([]byte, error) { return JSON(r) }

// CheckSelfConsistent parses report JSON and confirms its embedded hash matches a
// recomputation over the body, so a tampered report is caught before any signature is even
// considered. It returns the parsed report on success.
func CheckSelfConsistent(reportJSON []byte) (Report, error) {
	var r Report
	if err := json.Unmarshal(reportJSON, &r); err != nil {
		return Report{}, fmt.Errorf("parse report: %w", err)
	}
	if r.Hash == "" {
		return Report{}, errors.New("report has no content hash")
	}
	if contentHash(r) != r.Hash {
		return Report{}, ErrReportHashMismatch
	}
	return r, nil
}

// VerifyTrustReport is the independent verification an auditor runs: it confirms the report
// JSON is self-consistent (its embedded hash matches its body) and that sig is a valid
// signature over those exact bytes by signer, in the trust-report namespace. It is fail
// closed: any mismatch, wrong key, wrong namespace, or malformed input is an error, never a
// silent pass. On success it returns the verified report.
func VerifyTrustReport(reportJSON, sig []byte, signer ed25519.PublicKey) (Report, error) {
	r, err := CheckSelfConsistent(reportJSON)
	if err != nil {
		return Report{}, err
	}
	if _, err := sshsig.Verify([]ed25519.PublicKey{signer}, TrustNamespace, reportJSON, sig); err != nil {
		return Report{}, fmt.Errorf("signature verification failed: %w", err)
	}
	return r, nil
}
