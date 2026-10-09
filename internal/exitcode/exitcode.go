// Package exitcode defines the process exit codes of ittcsecscan.
//
// Exit codes are a public, stable contract: automation branches on them. A code
// may be added but never renumbered, reused, or given a different meaning. The
// table is mirrored in docs/cli.md and pinned by TestCodesAreStable.
package exitcode

import (
	"context"
	"errors"
	"fmt"
)

// Code is a process exit status.
type Code int

// Exit codes. Codes marked reserved are not produced yet; they are defined now
// so that later phases cannot allocate them differently.
const (
	// OK means the command did everything it was asked to do.
	OK Code = 0
	// Internal is an unexpected failure. It is also the fallback for errors
	// that carry no explicit code.
	Internal Code = 1
	// Usage means invalid command-line syntax: unknown command, bad flag,
	// unexpected argument.
	Usage Code = 2
	// Config means the configuration could not be loaded or failed validation.
	Config Code = 3
	// DoctorFailed means at least one doctor check failed (or, with --strict,
	// warned or could not be evaluated).
	DoctorFailed Code = 4
	// ScanIncomplete means the requested scope was not fully accounted for: a
	// scan finished with a coverage gap (a partial, denied, or unsupported
	// enumeration, or a provider that could not authenticate while others did). A
	// scan that completed with gaps is never reported as OK.
	ScanIncomplete Code = 5
	// FindingsAtThreshold (reserved) means findings at or above the configured
	// failure threshold were produced.
	FindingsAtThreshold Code = 6
	// AuthFailed means a provider could not authenticate: credentials were
	// missing, expired, or denied (produced by 'auth plan').
	AuthFailed Code = 7
	// IntegrityFailed (reserved) means a signature, digest, or trust-metadata
	// verification failed.
	IntegrityFailed Code = 8
	// Interrupted means the command was cancelled by SIGINT/SIGTERM
	// (Ctrl+C / console close on Windows). 128+2 by shell convention.
	Interrupted Code = 130
)

var names = map[Code]string{
	OK:                  "ok",
	Internal:            "internal",
	Usage:               "usage",
	Config:              "config",
	DoctorFailed:        "doctor-failed",
	ScanIncomplete:      "scan-incomplete",
	FindingsAtThreshold: "findings-at-threshold",
	AuthFailed:          "auth-failed",
	IntegrityFailed:     "integrity-failed",
	Interrupted:         "interrupted",
}

// String returns the stable symbolic name of c.
func (c Code) String() string {
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("code-%d", int(c))
}

// Error attaches an exit code to an error.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code.String()
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Wrap returns err annotated with code, or nil if err is nil.
func Wrap(code Code, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Code: code, Err: err}
}

// Errorf formats an error annotated with code.
func Errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// From maps an error to its exit code. Cancellation takes precedence over any
// explicit code because the operator's interrupt is the reason the command
// stopped. Errors without a code are Internal: an unclassified failure must
// never look like success.
func From(err error) Code {
	if err == nil {
		return OK
	}
	if errors.Is(err, context.Canceled) {
		return Interrupted
	}
	var e *Error
	if errors.As(err, &e) {
		if e.Code == OK {
			return Internal
		}
		return e.Code
	}
	return Internal
}
