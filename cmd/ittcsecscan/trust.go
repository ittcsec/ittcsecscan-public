package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/report"
	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

var trustSpec = commandSpec{
	name:     "trust",
	synopsis: "ittcsecscan trust --report <report.json> (--sig <file> --signer <key.pub> | --attest) [--json]",
	description: "ITTCsecProof trust report: verify, or prepare, a signed and independently\n" +
		"verifiable scan report (ADR-0028). A report is the immutable JSON model; the\n" +
		"operator signs those exact bytes offline with their own key in the\n" +
		"ittcsecscan-report namespace, and anyone they hand the report, the signature, and\n" +
		"their public key to can verify it here, or with stock ssh-keygen, with no server.\n\n" +
		"--sig and --signer verify a signed report (fail closed: a tampered report, a wrong\n" +
		"key, or a wrong namespace is an error, never a pass). --attest checks the report is\n" +
		"self-consistent and prints how to sign and verify it. Signing itself is an offline\n" +
		"ceremony with ssh-keygen; this tool never handles a signing key.",
}

func runTrust(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(trustSpec.name)
	reportPath := fs.String("report", "", "the report.json to verify or attest (required)")
	sigPath := fs.String("sig", "", "the detached signature file (verify mode)")
	signerPath := fs.String("signer", "", "the signer's public key file, e.g. key.pub (verify mode)")
	attest := fs.Bool("attest", false, "check the report is self-consistent and print how to sign and verify it")
	asJSON := fs.Bool("json", false, "print JSON")
	if done, err := parse(fs, inv, trustSpec, args); done {
		return err
	}
	if *reportPath == "" {
		return exitcode.Errorf(exitcode.Usage, "trust: a --report file is required")
	}
	reportJSON, err := os.ReadFile(*reportPath)
	if err != nil {
		return err
	}

	switch {
	case *sigPath != "" && *signerPath != "":
		return trustVerify(inv.out, *asJSON, reportJSON, *sigPath, *signerPath)
	case *attest:
		return trustAttest(inv.out, *asJSON, reportJSON)
	default:
		return exitcode.Errorf(exitcode.Usage, "trust: give either --sig and --signer (to verify) or --attest (to prepare)")
	}
}

// trustVerify runs the independent verification an auditor performs.
func trustVerify(w io.Writer, asJSON bool, reportJSON []byte, sigPath, signerPath string) error {
	sig, err := os.ReadFile(sigPath) //nolint:gosec // G304: operator-supplied signature path
	if err != nil {
		return err
	}
	keyBytes, err := os.ReadFile(signerPath) //nolint:gosec // G304: operator-supplied public-key path
	if err != nil {
		return err
	}
	signer, err := sshsig.ParseAuthorizedKey(firstKeyLine(string(keyBytes)))
	if err != nil {
		return fmt.Errorf("parse signer public key: %w", err)
	}
	r, verr := report.VerifyTrustReport(reportJSON, sig, signer)
	if asJSON {
		out := trustVerifyOut{Verified: verr == nil, Namespace: report.TrustNamespace}
		if verr != nil {
			out.Error = verr.Error()
		} else {
			out.Tenant, out.ToolVersion, out.Hash = r.Tenant, r.ToolVersion, r.Hash
			out.Started, out.Completed = r.Started, r.Completed
		}
		if werr := writeJSON(w, out); werr != nil {
			return werr
		}
		return verr
	}
	if verr != nil {
		_, _ = fmt.Fprintf(w, "TRUST REPORT VERIFICATION FAILED: %v\n", verr)
		return verr
	}
	var b strings.Builder
	b.WriteString("TRUST REPORT VERIFIED (signature valid, report unaltered)\n")
	fmt.Fprintf(&b, "  tenant:   %s\n", r.Tenant)
	fmt.Fprintf(&b, "  tool:     %s\n", r.ToolVersion)
	if r.Started != "" {
		fmt.Fprintf(&b, "  scan:     %s to %s\n", r.Started, r.Completed)
	}
	fmt.Fprintf(&b, "  hash:     %s\n", r.Hash)
	fmt.Fprintf(&b, "  namespace: %s\n", report.TrustNamespace)
	return writeText(w, b.String())
}

// trustAttest checks the report is self-consistent and prints how to sign and verify it. It
// does not sign: signing is an offline ceremony with the operator's own key.
func trustAttest(w io.Writer, asJSON bool, reportJSON []byte) error {
	r, err := report.CheckSelfConsistent(reportJSON)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSON(w, trustAttestOut{
			Tenant: r.Tenant, ToolVersion: r.ToolVersion, Started: r.Started, Completed: r.Completed,
			Hash: r.Hash, Namespace: report.TrustNamespace,
			SignCommand:   "ssh-keygen -Y sign -n " + report.TrustNamespace + " -f <your-signing-key> report.json",
			VerifyCommand: "ittcsecscan trust --report report.json --sig report.json.sig --signer <your-signing-key>.pub",
		})
	}
	var b strings.Builder
	b.WriteString("ITTCsecProof trust report (self-consistent; ready to sign)\n")
	fmt.Fprintf(&b, "  tenant:   %s\n", r.Tenant)
	fmt.Fprintf(&b, "  tool:     %s\n", r.ToolVersion)
	if r.Started != "" {
		fmt.Fprintf(&b, "  scan:     %s to %s\n", r.Started, r.Completed)
	}
	fmt.Fprintf(&b, "  hash:     %s\n", r.Hash)
	b.WriteString("\nSign it offline with your own key (the key never enters this tool):\n")
	b.WriteString("  ssh-keygen -Y sign -n " + report.TrustNamespace + " -f <your-signing-key> report.json\n")
	b.WriteString("\nHand report.json, report.json.sig, and your public key to the recipient. They verify:\n")
	b.WriteString("  ittcsecscan trust --report report.json --sig report.json.sig --signer <your-signing-key>.pub\n")
	b.WriteString("or with stock ssh-keygen and an allowed_signers file:\n")
	b.WriteString("  ssh-keygen -Y verify -n " + report.TrustNamespace + " -s report.json.sig -I <identity> -f allowed_signers < report.json\n")
	return writeText(w, b.String())
}

type trustVerifyOut struct {
	Verified    bool   `json:"verified"`
	Namespace   string `json:"namespace"`
	Tenant      string `json:"tenant,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	Started     string `json:"started,omitempty"`
	Completed   string `json:"completed,omitempty"`
	Hash        string `json:"hash,omitempty"`
	Error       string `json:"error,omitempty"`
}

type trustAttestOut struct {
	Tenant        string `json:"tenant"`
	ToolVersion   string `json:"tool_version"`
	Started       string `json:"started,omitempty"`
	Completed     string `json:"completed,omitempty"`
	Hash          string `json:"hash"`
	Namespace     string `json:"namespace"`
	SignCommand   string `json:"sign_command"`
	VerifyCommand string `json:"verify_command"`
}
