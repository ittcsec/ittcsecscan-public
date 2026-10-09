package auth

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestEmptyRegistryFailsClosed proves the production pre-adapter state: an empty
// registry authenticates nothing and reports every provider as unresolved with
// KindUnknown, never a pass.
func TestEmptyRegistryFailsClosed(t *testing.T) {
	r := NewRegistry()
	for _, p := range model.Providers {
		id, err := r.Resolve(context.Background(), p, Discovery)
		if err == nil || !id.IsZero() {
			t.Fatalf("%s: empty registry resolved something: id=%+v err=%v", p, id, err)
		}
		var ae *Error
		if !errors.As(err, &ae) || ae.Kind != KindUnknown {
			t.Fatalf("%s: want KindUnknown *Error, got %v", p, err)
		}
	}
	if len(r.Providers()) != 0 {
		t.Fatalf("empty registry lists providers: %v", r.Providers())
	}
}

// TestRegistryDelegatesToAdapter proves a registered adapter is used for its
// provider and only for its provider.
func TestRegistryDelegatesToAdapter(t *testing.T) {
	want := Identity{Provider: model.AWS, Account: "425046147213", Principal: "arn:aws:iam::425046147213:user/ittcsecscan-test"}
	r := NewRegistry()
	r.Register(model.AWS, resolved(want))

	id, err := r.Resolve(context.Background(), model.AWS, Discovery)
	if err != nil || id != want {
		t.Fatalf("registered adapter not used: id=%+v err=%v", id, err)
	}

	// A different provider still fails closed.
	if _, err := r.Resolve(context.Background(), model.GCP, Discovery); err == nil {
		t.Fatal("gcp resolved though only aws was registered")
	}

	if got := r.Providers(); !reflect.DeepEqual(got, []model.Provider{model.AWS}) {
		t.Fatalf("Providers() = %v, want [aws]", got)
	}
}

// TestRegistryPropagatesAdapterFailure proves a registered adapter's failure is
// returned unchanged (still a failure, still fail-closed), not swallowed.
func TestRegistryPropagatesAdapterFailure(t *testing.T) {
	r := NewRegistry()
	r.Register(model.AWS, failing(model.AWS, KindDenied, errors.New("AccessDenied")))

	id, err := r.Resolve(context.Background(), model.AWS, Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("adapter failure was swallowed: id=%+v err=%v", id, err)
	}
	var ae *Error
	if !errors.As(err, &ae) || ae.Kind != KindDenied {
		t.Fatalf("want KindDenied, got %v", err)
	}
}

// TestRegistryProvidersInModelOrder checks enumeration order is stable.
func TestRegistryProvidersInModelOrder(t *testing.T) {
	r := NewRegistry()
	r.Register(model.GCP, resolved(Identity{Provider: model.GCP}))
	r.Register(model.AWS, resolved(Identity{Provider: model.AWS}))
	if got := r.Providers(); !reflect.DeepEqual(got, []model.Provider{model.AWS, model.GCP}) {
		t.Fatalf("Providers() = %v, want [aws gcp] in model order", got)
	}
}

// TestRegistryCancelledContextFailsClosed proves cancellation is a failure, not
// a pass, even before any adapter is consulted.
func TestRegistryCancelledContextFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := NewRegistry()
	r.Register(model.AWS, resolved(Identity{Provider: model.AWS, Account: "1"}))
	if id, err := r.Resolve(ctx, model.AWS, Discovery); err == nil || !id.IsZero() {
		t.Fatalf("cancelled context did not fail closed: id=%+v err=%v", id, err)
	}
}
