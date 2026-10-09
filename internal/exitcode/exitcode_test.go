package exitcode

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestCodesAreStable pins the public exit-code contract. If this test fails,
// you are renumbering a published code: add a new code instead.
func TestCodesAreStable(t *testing.T) {
	want := map[Code]int{
		OK:                  0,
		Internal:            1,
		Usage:               2,
		Config:              3,
		DoctorFailed:        4,
		ScanIncomplete:      5,
		FindingsAtThreshold: 6,
		AuthFailed:          7,
		IntegrityFailed:     8,
		Interrupted:         130,
	}
	if len(want) != len(names) {
		t.Fatalf("names has %d entries, contract has %d: document every new code here and in docs/cli.md", len(names), len(want))
	}
	for c, n := range want {
		if int(c) != n {
			t.Errorf("%s = %d, contract says %d", c, int(c), n)
		}
	}
}

func TestFrom(t *testing.T) {
	base := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want Code
	}{
		{"nil", nil, OK},
		{"plain error is internal", base, Internal},
		{"wrapped code", Wrap(Config, base), Config},
		{"code survives fmt wrapping", fmt.Errorf("loading: %w", Wrap(Usage, base)), Usage},
		{"canceled", context.Canceled, Interrupted},
		{"canceled beats explicit code", Wrap(Config, fmt.Errorf("read: %w", context.Canceled)), Interrupted},
		{"explicit OK on an error is not success", &Error{Code: OK, Err: base}, Internal},
		{"errorf", Errorf(DoctorFailed, "x %d", 1), DoctorFailed},
	}
	for _, tt := range tests {
		if got := From(tt.err); got != tt.want {
			t.Errorf("%s: From = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWrapNil(t *testing.T) {
	if Wrap(Config, nil) != nil {
		t.Fatal("Wrap(nil) must be nil")
	}
}

func TestString(t *testing.T) {
	if Usage.String() != "usage" || Code(99).String() != "code-99" {
		t.Fatalf("unexpected names: %s %s", Usage, Code(99))
	}
}
