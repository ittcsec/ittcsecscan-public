//go:build !remediation

package execute

import "context"

// Enabled reports whether provider-write execution is compiled in. In the default
// build it is false: the executor cannot make any provider change.
const Enabled = false

// DefaultWriter returns the disabled writer for the default build. It always
// refuses, so a normal binary can never mutate a cloud even when every guard in
// Apply has passed.
func DefaultWriter() Writer { return disabledWriter{} }

type disabledWriter struct{}

func (disabledWriter) Apply(context.Context, Operation) (WriteResult, error) {
	return WriteResult{}, ErrExecutionDisabled
}
