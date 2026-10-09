// Command ittcsecscan is the command-line entry point.
//
// main only wires process concerns — signals, standard streams, the process
// environment, and the exit status — into run, which is fully testable.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	awsprovider "github.com/ittcsec/ittcsecscan/providers/aws"
	azureprovider "github.com/ittcsec/ittcsecscan/providers/azure"
	gcpprovider "github.com/ittcsec/ittcsecscan/providers/gcp"
	githubprovider "github.com/ittcsec/ittcsecscan/providers/github"
	gitlabprovider "github.com/ittcsec/ittcsecscan/providers/gitlab"
	gwsprovider "github.com/ittcsec/ittcsecscan/providers/gworkspace"
	k8sprovider "github.com/ittcsec/ittcsecscan/providers/k8s"
	mcpprovider "github.com/ittcsec/ittcsecscan/providers/mcp"
	oktaprovider "github.com/ittcsec/ittcsecscan/providers/okta"
)

func main() {
	// SIGINT (Ctrl+C) and SIGTERM (on Windows also console close, logoff, and
	// shutdown) cancel the context. After the first signal default handling is
	// restored, so a second Ctrl+C terminates immediately.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()

	// The production resolver. Credential adapters register here (ADR-0017); a
	// provider with no adapter fails closed. Azure and GCP arrive in later PRs.
	resolver := auth.NewRegistry()
	resolver.Register(model.AWS, awsprovider.New())
	resolver.Register(model.Azure, azureprovider.New())
	resolver.Register(model.GCP, gcpprovider.New())
	resolver.Register(model.GitHub, githubprovider.New(os.LookupEnv))
	resolver.Register(model.GitLab, gitlabprovider.New(os.LookupEnv))
	resolver.Register(model.Kubernetes, k8sprovider.New(os.LookupEnv))
	resolver.Register(model.Okta, oktaprovider.New(os.LookupEnv))
	resolver.Register(model.GoogleWorkspace, gwsprovider.New(os.LookupEnv))
	resolver.Register(model.MCP, mcpprovider.New(os.LookupEnv))

	code := run(ctx, os.Args[1:], streams{out: os.Stdout, err: os.Stderr}, os.LookupEnv, ttyReadSecret, resolver)
	stop()
	os.Exit(int(code))
}

// ttyReadSecret reads a passphrase from the terminal without echoing it. The
// prompt goes to stderr, so stdout stays machine-readable. Without a terminal
// (a pipe, a service, CI) it refuses rather than reading a secret from a stream
// that might be logged or redirected.
func ttyReadSecret(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no terminal available to read a passphrase; run this command interactively")
	}
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return secret, err
}
