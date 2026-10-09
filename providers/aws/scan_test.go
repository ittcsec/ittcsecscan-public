package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestSourceCollectorsResolveConfigOnce is the regression guard for the
// double-resolution finding: Source.Collectors must resolve the credential chain
// exactly once, so the reported identity and the collector clients are built from
// the same resolution and cannot drift across a token rotation. It counts
// loadConfig calls rather than asserting today's call sites, so the guarantee
// holds even if the collector wiring is refactored later.
func TestSourceCollectorsResolveConfigOnce(t *testing.T) {
	calls := 0
	s := &Source{adapter: &Adapter{
		loadConfig: func(context.Context) (awssdk.Config, error) {
			calls++
			return awssdk.Config{Region: "us-east-1"}, nil
		},
		newClient: func(awssdk.Config) identityAPI {
			return stubSTS{out: &sts.GetCallerIdentityOutput{
				Account: str("123456789012"), Arn: str("arn:aws:iam::123456789012:user/example"),
			}}
		},
	}}

	account, collectors, err := s.Collectors(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collectors: %v", err)
	}
	if calls != 1 {
		t.Fatalf("loadConfig used %d times; a scan must resolve the credential chain exactly once", calls)
	}
	if account != "123456789012" {
		t.Errorf("account = %q, want 123456789012", account)
	}
	if len(collectors) == 0 {
		t.Error("no collectors built")
	}
	if s.Provider() != model.AWS {
		t.Errorf("provider = %q, want aws", s.Provider())
	}
}

// TestSourceCollectorsPropagatesAuthFailure proves an authentication failure is
// surfaced as an error, never as an empty (and therefore silently clean) set of
// collectors.
func TestSourceCollectorsPropagatesAuthFailure(t *testing.T) {
	s := &Source{adapter: &Adapter{
		loadConfig: func(context.Context) (awssdk.Config, error) { return awssdk.Config{}, nil },
		newClient: func(awssdk.Config) identityAPI {
			return stubSTS{err: apiErr("ExpiredToken")}
		},
	}}

	if _, _, err := s.Collectors(context.Background(), nil); err == nil {
		t.Fatal("Collectors: want an error on auth failure, got nil")
	}
}
