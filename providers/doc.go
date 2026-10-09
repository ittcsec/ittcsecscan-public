// Package providers is the aggregation point for the provider adapters and
// collectors. Its only job today is to link every collector so that the
// whole-repo permission reconciliation can see every declared requirement (see
// the test); the adapters and collectors themselves live in its subpackages.
package providers
