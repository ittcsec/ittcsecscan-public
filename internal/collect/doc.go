// Package collect schedules provider collectors and enforces API budgets,
// pagination, retries, throttling, regional enumeration, and cancellation.
//
// Status: not implemented.
//
// Invariants this package must uphold:
//   - Partial collection is explicit: every collector reports completeness,
//     and a denied or failed API call is recorded as unknown or error, never
//     as an empty (passing) result.
//   - Secret values and object contents are never retrieved.
//   - Every call honours context cancellation and a bounded budget.
package collect
