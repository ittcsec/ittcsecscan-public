package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/logging"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// resolved is a stub that authenticates successfully as the given identity.
func resolved(id Identity) StubResolver {
	return StubResolver{Outcomes: map[model.Provider]Outcome{id.Provider: {Identity: id}}}
}

// failing is a stub that fails for p with the given kind and cause.
func failing(p model.Provider, kind Kind, cause error) StubResolver {
	return StubResolver{Outcomes: map[model.Provider]Outcome{p: {Fail: &stubFail{Kind: kind, Cause: cause}}}}
}

// --- Fail-closed contract -------------------------------------------------

// TestResolveSucceedsOnlyWithIdentityAndNilError proves the two halves of the
// contract that must hold together: success yields a populated Identity and a
// nil error, and every failure yields the zero Identity and a non-nil *Error.
// A mutation that returns the identity alongside an error, or a nil error on a
// failure, breaks this.
func TestResolveSucceedsOnlyWithIdentityAndNilError(t *testing.T) {
	want := Identity{Provider: model.AWS, Account: "425046147213", Principal: "arn:aws:iam::425046147213:user/ittcsecscan-test"}

	cases := []struct {
		name    string
		res     Resolver
		wantErr bool
		wantID  Identity
		kind    Kind
	}{
		{"resolved", resolved(want), false, want, KindUnknown},
		{"denied", failing(model.AWS, KindDenied, errors.New("AccessDenied: not authorized")), true, Identity{}, KindDenied},
		{"expired", failing(model.AWS, KindExpired, errors.New("ExpiredToken: the security token is expired")), true, Identity{}, KindExpired},
		{"unclassified", failing(model.AWS, KindUnknown, errors.New("dial tcp: timeout")), true, Identity{}, KindUnknown},
		{"unconfigured provider", StubResolver{}, true, Identity{}, KindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := tc.res.Resolve(context.Background(), model.AWS, Discovery)

			// The paired invariant: err is nil exactly when an identity resolved.
			if (err == nil) != !id.IsZero() {
				t.Fatalf("contract broken: err=%v id=%+v (a nil error must accompany a populated identity and vice versa)", err, id)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want failure, got success with id=%+v", id)
				}
				if !id.IsZero() {
					t.Fatalf("failure returned a non-zero identity: %+v", id)
				}
				var ae *Error
				if !errors.As(err, &ae) {
					t.Fatalf("failure error is not *Error: %T", err)
				}
				if ae.Kind != tc.kind {
					t.Fatalf("kind = %v, want %v", ae.Kind, tc.kind)
				}
				return
			}
			if err != nil {
				t.Fatalf("want success, got %v", err)
			}
			if id != tc.wantID {
				t.Fatalf("identity = %+v, want %+v", id, tc.wantID)
			}
		})
	}
}

// TestCancelledContextFailsClosed proves a cancelled context is a failure, not a
// pass: the seam must never report an identity it did not actually resolve.
func TestCancelledContextFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id, err := resolved(Identity{Provider: model.AWS, Account: "1"}).Resolve(ctx, model.AWS, Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("cancelled context did not fail closed: id=%+v err=%v", id, err)
	}
	var ae *Error
	if !errors.As(err, &ae) || ae.Kind != KindUnknown {
		t.Fatalf("cancelled context should fail as unknown, got %v", err)
	}
}

// TestKindZeroValueIsUnknown proves the fail-closed default: a Kind that is
// never set classifies as unknown, so forgetting to classify cannot yield a
// pass or a benign-looking category.
func TestKindZeroValueIsUnknown(t *testing.T) {
	var k Kind
	if k != KindUnknown || k.String() != "unknown" {
		t.Fatalf("zero Kind = %v (%q), want KindUnknown (\"unknown\")", k, k.String())
	}
}

// TestErrorDoesNotUnwrapToCause proves the raw cause is not retained: an error
// chain cannot be walked back to token-bearing material. A mutation that adds
// Unwrap returning the cause breaks this.
func TestErrorDoesNotUnwrapToCause(t *testing.T) {
	cause := errors.New("boom ya29." + strings.Repeat("Z", 40))
	_, err := failing(model.GCP, KindDenied, cause).Resolve(context.Background(), model.GCP, Discovery)
	if errors.Unwrap(err) != nil {
		t.Fatalf("error unwraps to a cause; it must not retain one")
	}
	if errors.Is(err, cause) {
		t.Fatalf("error still identifies with its raw cause")
	}
}

// --- No-leak guarantee ----------------------------------------------------

// leakTokens are realistic, non-real credential shapes, one per provider path.
// Each is assembled so a secret scanner does not flag this file.
var leakTokens = map[string]string{
	"aws-sigv4":   "Signature=" + strings.Repeat("fe5f80f7", 8),
	"gcp-access":  "ya29." + strings.Repeat("C", 40),
	"gcp-refresh": "1//" + strings.Repeat("R", 40),
	"azure-jwt":   "eyJ" + "hbGciOiJSUzI1NiJ9" + ".eyJ" + "hdWQiOiJhcm0ifQ" + ".c2ln",
	"bearer":      "Bearer " + strings.Repeat("a1b2c3d4", 4),
}

// TestErrorNeverLeaksTokenThroughAnySurface is the adversarial no-leak proof.
// For every provider token shape and every failure kind, it deliberately embeds
// the token in the resolver's underlying cause and then confirms the token
// escapes through none of the surfaces the seam exposes: the error string, its
// fmt verbs, and a record logged through the real redacting handler. A leak here
// is as serious as a fabricated key, so it is tested like one.
func TestErrorNeverLeaksTokenThroughAnySurface(t *testing.T) {
	kinds := []Kind{KindDenied, KindExpired, KindUnknown}
	for shape, token := range leakTokens {
		for _, kind := range kinds {
			t.Run(shape+"/"+kind.String(), func(t *testing.T) {
				cause := fmt.Errorf("provider call failed: %s (context follows)", token)
				_, err := failing(model.AWS, kind, cause).Resolve(context.Background(), model.AWS, Discovery)
				if err == nil {
					t.Fatal("expected a failure")
				}

				// Surface 1: the error string and its fmt verbs.
				surfaces := []string{
					err.Error(),
					fmt.Sprintf("%v", err),
					fmt.Sprintf("%+v", err),
					fmt.Sprintf("%s", err),
				}
				// Surface 2: a record logged through the redacting handler,
				// both as an attribute and inside the message.
				surfaces = append(surfaces, logged(t, err))

				for i, s := range surfaces {
					if strings.Contains(s, token) {
						t.Fatalf("surface %d leaked token %q: %q", i, token, s)
					}
					if !strings.Contains(s, redact.Placeholder) {
						t.Fatalf("surface %d has no redaction placeholder, so nothing was scrubbed: %q", i, s)
					}
				}
			})
		}
	}
}

// TestMisusedIdentityFieldIsScrubbedAtLog proves defence in depth: even if a
// token-shaped string is wrongly placed in an Identity field (which the contract
// forbids), logging it through the redacting handler still scrubs it. The seam's
// own guarantee is that it never puts one there; this shows the log boundary is a
// second net.
func TestMisusedIdentityFieldIsScrubbedAtLog(t *testing.T) {
	token := leakTokens["gcp-access"]
	id := Identity{Provider: model.GCP, Account: "proj", Principal: token}

	var buf bytes.Buffer
	log := logging.New(&buf, slog.LevelInfo, logging.FormatJSON)
	log.Info("resolved identity", "principal", id.Principal, "account", id.Account)

	out := buf.String()
	if strings.Contains(out, token) {
		t.Fatalf("token leaked through a logged identity field: %q", out)
	}
	if !strings.Contains(out, redact.Placeholder) {
		t.Fatalf("identity field was not scrubbed: %q", out)
	}
}

// logged renders err through the real redacting JSON handler and returns the
// output, exercising both the error-attribute path and the message path.
func logged(t *testing.T, err error) string {
	t.Helper()
	var buf bytes.Buffer
	log := logging.New(&buf, slog.LevelError, logging.FormatJSON)
	log.Error(err.Error(), "err", err)
	return buf.String()
}

// TestExportedFailScrubsAndDropsCause proves the adapter-facing constructor has
// the same no-leak property as the internal one: it scrubs the cause and does
// not retain it.
func TestExportedFailScrubsAndDropsCause(t *testing.T) {
	token := "ya29." + strings.Repeat("Z", 40)
	err := Fail(model.AWS, Discovery, KindDenied, fmt.Errorf("sts said %s", token))
	if strings.Contains(err.Error(), token) {
		t.Fatalf("Fail leaked the token: %q", err.Error())
	}
	if !strings.Contains(err.Error(), redact.Placeholder) {
		t.Errorf("Fail did not scrub: %q", err.Error())
	}
	if errors.Unwrap(err) != nil {
		t.Errorf("Fail retained an unwrappable cause")
	}
	var ae *Error
	if !errors.As(err, &ae) || ae.Kind != KindDenied {
		t.Errorf("Fail did not carry KindDenied")
	}
}

// --- Model boundary -------------------------------------------------------

// TestIdentityExposesNoCredentialField mirrors ADR-0014 §4 for the auth seam:
// Identity may hold only plain, non-secret string identifiers. A byte slice, a
// redact.Secret, or a field named like a credential would let secret material be
// carried out of the seam in a typed value, so it is forbidden by reflection.
func TestIdentityExposesNoCredentialField(t *testing.T) {
	tp := reflect.TypeOf(Identity{})
	secretType := reflect.TypeOf(redact.Secret{})
	for i := range tp.NumField() {
		f := tp.Field(i)
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("Identity.%s is a byte slice, which could carry raw credential material", f.Name)
		}
		if f.Type == secretType {
			t.Errorf("Identity.%s is a redact.Secret; the seam must not carry secrets in its result", f.Name)
		}
		if redact.Key(f.Name) {
			t.Errorf("Identity.%s has a secret-bearing field name", f.Name)
		}
	}
}

// TestProfileValid checks the profile vocabulary.
func TestProfileValid(t *testing.T) {
	for _, p := range Profiles {
		if !p.Valid() {
			t.Errorf("Profiles contains %q but Valid rejects it", p)
		}
	}
	if Profile("root").Valid() {
		t.Error("unknown profile reported valid")
	}
	if len(Profiles) != 3 {
		t.Errorf("want discovery, deep-evidence, remediation; got %v", Profiles)
	}
}
