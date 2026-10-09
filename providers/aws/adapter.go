package aws

import (
	"context"
	"errors"
	"net/http"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	// dialTimeout and tlsHandshakeTimeout bound how long a client will wait to
	// establish a connection to a Region's endpoint. A Region whose endpoint does
	// not answer (an opt-in Region not enabled, or one unreachable from the run
	// environment) is then rejected in seconds rather than after the SDK default
	// ~30s dial multiplied by the retry count. The response body read is
	// deliberately left unbounded, so a legitimately large paginated response from
	// a working Region is never cut off (ADR-0018 §4).
	dialTimeout         = 5 * time.Second
	tlsHandshakeTimeout = 5 * time.Second
	// collectionMaxAttempts bounds retries. A transport failure is a non-fatal
	// Partial "unreachable" gap and a throttle is a Partial gap, so a bounded
	// attempt count never turns into a crash or a false pass (ADR-0018 §4); it
	// keeps a wide multi-Region sweep from spending minutes per unreachable Region.
	collectionMaxAttempts = 2
)

// identityAPI is the single STS call the adapter makes. It is an interface so
// tests inject a stub and never touch the network or the real SDK.
type identityAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Adapter implements auth.Resolver for AWS.
type Adapter struct {
	// loadConfig loads the AWS default credential chain (environment, shared
	// config and SSO, web-identity/OIDC, container, and IMDS). Overridable in
	// tests.
	loadConfig func(context.Context) (awssdk.Config, error)
	// newClient builds the STS identity client from a resolved config.
	// Overridable in tests.
	newClient func(awssdk.Config) identityAPI
}

// New returns an AWS adapter that authenticates through the SDK default
// credential chain. It performs no I/O; the credential chain is resolved lazily
// on each Resolve.
func New() *Adapter {
	return &Adapter{
		loadConfig: func(ctx context.Context) (awssdk.Config, error) {
			return awsconfig.LoadDefaultConfig(ctx, collectionLoadOptions()...)
		},
		newClient: func(cfg awssdk.Config) identityAPI {
			return sts.NewFromConfig(cfg)
		},
	}
}

// boundedHTTPClient returns an AWS HTTP client that fails fast on an unreachable
// endpoint: a short dial and TLS-handshake timeout, with the response body read
// left unbounded (see dialTimeout).
func boundedHTTPClient() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().
		WithTransportOptions(func(tr *http.Transport) {
			tr.TLSHandshakeTimeout = tlsHandshakeTimeout
			// Route the dial through the shared audited dialer (with the same bounded
			// timeout) so the zero-egress audit observes AWS egress exactly as it does the
			// plain-HTTP providers. This replaces the BuildableClient's own dialer, so the
			// dial timeout is carried here rather than via WithDialerOptions.
			tr.DialContext = collect.AuditedDialContext(dialTimeout)
		})
}

// collectionLoadOptions bound the one resolved config so every AWS client built
// from it (the STS identity call and every read-only regional collector) fails
// fast on an unreachable Region and retries a bounded number of times
// (ADR-0018 §4). The single-resolution seam carries this, so no collector has to
// configure timeouts or retries itself.
func collectionLoadOptions() []func(*awsconfig.LoadOptions) error {
	return []func(*awsconfig.LoadOptions) error{
		awsconfig.WithHTTPClient(boundedHTTPClient()),
		awsconfig.WithRetryMaxAttempts(collectionMaxAttempts),
	}
}

// Resolve implements auth.Resolver. It establishes the caller's identity with
// sts:GetCallerIdentity, which needs no IAM permission and performs no write
// (AWS STS API reference, verified 2026-09-17), and returns a non-secret
// Identity naming the account and the caller ARN. Every failure is routed
// through auth.Fail, so no credential material escapes in an error.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolveConfig(ctx, p, prof)
	return id, err
}

// resolveConfig resolves the AWS credential chain exactly once and establishes
// the caller's identity from that same configuration, returning both. One
// resolution serves both the reported identity and the read-only collector
// clients, so what identity reports and what collection actually runs under can
// never diverge (a rotated or expired token between two separate resolutions
// could otherwise report one principal while collecting as another). The
// read-only service clients themselves are built in the AWS collectors from the
// returned config, which add their service SDK modules under ADR-0017's
// per-service intake; the SDK stays confined to providers/aws (ADR-0018 §3).
// Every failure is routed through auth.Fail, so no credential material escapes
// in an error.
func (a *Adapter) resolveConfig(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, awssdk.Config, error) {
	if p != model.AWS {
		return auth.Identity{}, awssdk.Config{}, auth.Fail(p, prof, auth.KindUnknown,
			errors.New("aws adapter asked to resolve a non-aws provider"))
	}
	cfg, err := a.loadConfig(ctx)
	if err != nil {
		return auth.Identity{}, awssdk.Config{}, auth.Fail(p, prof, classify(err), err)
	}
	out, err := a.newClient(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return auth.Identity{}, awssdk.Config{}, auth.Fail(p, prof, classify(err), err)
	}
	return auth.Identity{
		Provider:  model.AWS,
		Account:   deref(out.Account),
		Principal: deref(out.Arn),
	}, cfg, nil
}

// classify maps an AWS/STS error to a seam Kind. Expired credentials are
// KindExpired; an explicit access denial is KindDenied; everything else,
// including an unresolved credential chain, is KindUnknown, so an unclassified
// failure fails closed. The string codes are AWS's own, read from the smithy
// APIError; a cancelled or timed-out context is unknown, not a provider denial.
func classify(err error) auth.Kind {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return auth.KindUnknown
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired":
			return auth.KindExpired
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return auth.KindDenied
		}
	}
	return auth.KindUnknown
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
