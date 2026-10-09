package aws

import (
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// TestCollectionConfigIsBounded proves the single-resolution seam carries the
// fast-fail configuration: the resolved config uses the bounded buildable HTTP
// client and a bounded retry attempt count, so every AWS client built from it
// (the STS identity call and every regional collector) inherits them without each
// collector configuring anything (ADR-0018 §4).
func TestCollectionConfigIsBounded(t *testing.T) {
	var lo awsconfig.LoadOptions
	for _, opt := range collectionLoadOptions() {
		if err := opt(&lo); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	if lo.RetryMaxAttempts != collectionMaxAttempts {
		t.Errorf("RetryMaxAttempts = %d, want %d", lo.RetryMaxAttempts, collectionMaxAttempts)
	}
	if lo.HTTPClient == nil {
		t.Fatal("no HTTP client set; an unreachable region would use the default ~30s dial")
	}
	if _, ok := lo.HTTPClient.(*awshttp.BuildableClient); !ok {
		t.Errorf("HTTP client is %T, want the bounded *awshttp.BuildableClient", lo.HTTPClient)
	}
	// The bounded client is constructible and non-nil.
	if boundedHTTPClient() == nil {
		t.Error("boundedHTTPClient returned nil")
	}
}
