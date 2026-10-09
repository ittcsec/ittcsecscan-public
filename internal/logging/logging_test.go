package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/redact"
)

var awsKeyID = "AKIA" + "Z7CANARY0000TEST"

type leakyValuer struct{}

func (leakyValuer) LogValue() slog.Value { return slog.StringValue("token=valuer-canary") }

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, b)
	}
	return rec
}

func assertNoLeak(t *testing.T, out string, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(out, c) {
			t.Errorf("log output leaked %q:\n%s", c, out)
		}
	}
}

func TestRedactsRecord(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelDebug, FormatJSON)
	log.Info("using key "+awsKeyID,
		"password", "pw-canary",
		"region", "eu-west-1",
		"count", 3,
		"err", errors.New("refresh failed: token=err-canary"),
		"wrapped", redact.NewSecret("secret-canary"),
		"valuer", leakyValuer{},
		slog.Group("provider", "client_secret", "cs-canary", "name", "prod"),
		slog.Group("credentials", "user", "group-canary"),
		"blob", []byte("bytes-canary"),
		"obj", struct{ Field string }{"struct-canary"},
		"list", []string{"a", "password=list-canary"},
	)
	out := buf.String()
	assertNoLeak(t, out, awsKeyID, "pw-canary", "err-canary", "secret-canary", "valuer-canary",
		"cs-canary", "group-canary", "bytes-canary", "struct-canary", "list-canary")

	rec := decode(t, buf.Bytes())
	checks := map[string]any{
		"msg":         "using key " + redact.Placeholder,
		"password":    redact.Placeholder,
		"region":      "eu-west-1",
		"count":       float64(3),
		"err":         "refresh failed: token=" + redact.Placeholder,
		"wrapped":     redact.Placeholder,
		"valuer":      "token=" + redact.Placeholder,
		"credentials": redact.Placeholder,
		"blob":        "[12 bytes omitted]",
		"obj":         "[unloggable struct { Field string }]",
	}
	for k, want := range checks {
		if rec[k] != want {
			t.Errorf("%s = %#v, want %#v", k, rec[k], want)
		}
	}
	provider, ok := rec["provider"].(map[string]any)
	if !ok || provider["name"] != "prod" || provider["client_secret"] != redact.Placeholder {
		t.Errorf("provider group = %#v", rec["provider"])
	}
}

func TestWithAttrsAndSensitiveGroup(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelDebug, FormatJSON).
		With("api_key", "with-canary", "tenant", "t1").
		WithGroup("session").
		With("id", "sid-canary")
	log.Info("hello", "nested", "nested-canary")
	out := buf.String()
	assertNoLeak(t, out, "with-canary", "sid-canary", "nested-canary")
	rec := decode(t, buf.Bytes())
	if rec["tenant"] != "t1" {
		t.Errorf("tenant = %#v", rec["tenant"])
	}
}

func TestTextFormatEscapesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, slog.LevelInfo, FormatText).Info("resource", "name", "\x1b[2Jbucket\u202e")
	if strings.ContainsAny(buf.String(), "\x1b\u202e") {
		t.Errorf("raw control characters reached the terminal: %q", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelWarn, FormatText)
	log.Info("hidden")
	log.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Errorf("unexpected output: %q", buf.String())
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "INFO", "trace", "warning"} {
		if _, err := ParseLevel(bad); err == nil {
			t.Errorf("ParseLevel(%q) accepted", bad)
		}
	}
	if f, err := ParseFormat("json"); err != nil || f != FormatJSON {
		t.Errorf("ParseFormat(json) = %v, %v", f, err)
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(yaml) accepted")
	}
}

func TestNewRedactingHandlerDoesNotDoubleWrap(t *testing.T) {
	h := NewRedactingHandler(slog.DiscardHandler)
	if NewRedactingHandler(h) != h {
		t.Error("wrapping twice created a second layer")
	}
}

func TestDiscard(t *testing.T) {
	Discard().Info("dropped", "password", "x")
}
