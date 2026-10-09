package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// stubSTS is an offline identityAPI. It returns out/err verbatim, so a test
// drives resolved, expired, denied, and token-bearing failures with no network
// and no real SDK.
type stubSTS struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (s stubSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return s.out, s.err
}

// adapterWith builds an Adapter whose config load is a no-op and whose STS
// client is the given stub, so Resolve is fully hermetic.
func adapterWith(api identityAPI) *Adapter {
	return &Adapter{
		loadConfig: func(context.Context) (awssdk.Config, error) { return awssdk.Config{}, nil },
		newClient:  func(awssdk.Config) identityAPI { return api },
	}
}

func str(s string) *string { return &s }

func apiErr(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "message from provider"}
}

func TestAdapterResolvesIdentity(t *testing.T) {
	a := adapterWith(stubSTS{out: &sts.GetCallerIdentityOutput{
		Account: str("123456789012"),
		Arn:     str("arn:aws:iam::123456789012:user/example"),
		UserId:  str("AIDAEXAMPLE"),
	}})
	id, err := a.Resolve(context.Background(), model.AWS, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.Provider != model.AWS || id.Account != "123456789012" ||
		id.Principal != "arn:aws:iam::123456789012:user/example" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestAdapterClassifiesFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want auth.Kind
	}{
		{"expired token", apiErr("ExpiredToken"), auth.KindExpired},
		{"expired exception", apiErr("ExpiredTokenException"), auth.KindExpired},
		{"access denied", apiErr("AccessDenied"), auth.KindDenied},
		{"unauthorized operation", apiErr("UnauthorizedOperation"), auth.KindDenied},
		{"other api error", apiErr("ServiceUnavailable"), auth.KindUnknown},
		{"plain error", errors.New("dial tcp: timeout"), auth.KindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := adapterWith(stubSTS{err: tc.err}).Resolve(context.Background(), model.AWS, auth.Discovery)
			if err == nil || !id.IsZero() {
				t.Fatalf("want failure with zero identity, got id=%+v err=%v", id, err)
			}
			var ae *auth.Error
			if !errors.As(err, &ae) {
				t.Fatalf("error is not *auth.Error: %T", err)
			}
			if ae.Kind != tc.want {
				t.Fatalf("kind = %v, want %v", ae.Kind, tc.want)
			}
		})
	}
}

func TestAdapterConfigLoadFailureFailsClosed(t *testing.T) {
	a := &Adapter{
		loadConfig: func(context.Context) (awssdk.Config, error) {
			return awssdk.Config{}, errors.New("no credentials found in the chain")
		},
		newClient: func(awssdk.Config) identityAPI { return stubSTS{} },
	}
	id, err := a.Resolve(context.Background(), model.AWS, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("config load failure did not fail closed: id=%+v err=%v", id, err)
	}
}

func TestAdapterRejectsNonAWSProvider(t *testing.T) {
	id, err := adapterWith(stubSTS{}).Resolve(context.Background(), model.GCP, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("adapter resolved a non-aws provider: id=%+v err=%v", id, err)
	}
}

// TestAdapterNeverLeaksTokenThroughError proves the no-leak guarantee at the
// adapter boundary: an STS error whose message embeds a token must not surface
// the token, because the adapter routes every failure through auth.Fail.
func TestAdapterNeverLeaksTokenThroughError(t *testing.T) {
	token := "ya29." + strings.Repeat("C", 40)
	stsErr := &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied with session " + token}
	_, err := adapterWith(stubSTS{err: stsErr}).Resolve(context.Background(), model.AWS, auth.Discovery)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("adapter leaked the token: %q", err.Error())
	}
	if !strings.Contains(err.Error(), redact.Placeholder) {
		t.Errorf("adapter error was not scrubbed: %q", err.Error())
	}
}

// TestResolveConfigResolvesOnce proves the client-factory seam (ADR-0018 §3)
// does one credential resolution: resolveConfig loads the chain a single time and
// returns both the identity and that same config, so the reported identity and
// the collector clients cannot come from two different resolutions.
func TestResolveConfigResolvesOnce(t *testing.T) {
	calls := 0
	a := &Adapter{
		loadConfig: func(context.Context) (awssdk.Config, error) {
			calls++
			return awssdk.Config{Region: "eu-west-1"}, nil
		},
		newClient: func(awssdk.Config) identityAPI {
			return stubSTS{out: &sts.GetCallerIdentityOutput{Account: str("123456789012"), Arn: str("arn:aws:iam::123456789012:user/example")}}
		},
	}
	id, cfg, err := a.resolveConfig(context.Background(), model.AWS, auth.Discovery)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if calls != 1 {
		t.Fatalf("loadConfig used %d times; one resolution must serve both identity and clients", calls)
	}
	if id.Account != "123456789012" {
		t.Errorf("account = %q, want 123456789012", id.Account)
	}
	if cfg.Region != "eu-west-1" {
		t.Errorf("returned config Region = %q, want the resolved eu-west-1", cfg.Region)
	}
}

// TestAdapterViaRegistry proves the adapter plugs into the production registry
// and resolves through it.
func TestAdapterViaRegistry(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(model.AWS, adapterWith(stubSTS{out: &sts.GetCallerIdentityOutput{
		Account: str("123456789012"), Arn: str("arn:aws:iam::123456789012:role/example"),
	}}))
	id, err := reg.Resolve(context.Background(), model.AWS, auth.Discovery)
	if err != nil || id.Account != "123456789012" {
		t.Fatalf("registry resolve: id=%+v err=%v", id, err)
	}
}
