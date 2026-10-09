// Package logging builds the structured logger used by every ittcsecscan
// component.
//
// All records pass through a redacting slog.Handler before they reach an
// encoder. There is no supported way to obtain an unredacted logger, and the
// standard library "log" package is banned by the linter configuration so that
// nothing bypasses this path.
//
// Redaction rules, in order:
//   - An attribute whose key names secret material (redact.Key) has its whole
//     value replaced, including every attribute nested inside a group.
//   - A group opened with WithGroup under a sensitive name redacts everything
//     logged inside it.
//   - String values and the message are scrubbed of recognised credential
//     patterns (redact.String).
//   - Arbitrary values (slog.Any) are rendered only if they are errors or
//     fmt.Stringers, and are then scrubbed. Anything else is replaced by a type
//     placeholder: an unknown struct could hold a secret field. Log such values
//     as explicit attributes or implement slog.LogValuer.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// Format selects the log encoding.
type Format string

// Supported formats.
const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// ParseLevel converts a configuration level name to a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, warn, or error)", s)
}

// ParseFormat converts a configuration format name to a Format.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatText, FormatJSON:
		return Format(s), nil
	}
	return "", fmt.Errorf("unknown log format %q (want text or json)", s)
}

// New returns a logger that writes redacted records to w.
func New(w io.Writer, level slog.Level, format Format) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	var inner slog.Handler
	if format == FormatJSON {
		inner = slog.NewJSONHandler(w, opts)
	} else {
		inner = slog.NewTextHandler(w, opts)
	}
	return slog.New(NewRedactingHandler(inner))
}

// Discard returns a logger that drops every record.
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// NewRedactingHandler wraps inner so that every record is redacted first.
func NewRedactingHandler(inner slog.Handler) slog.Handler {
	if h, ok := inner.(*redactingHandler); ok {
		return h
	}
	return &redactingHandler{inner: inner}
}

type redactingHandler struct {
	inner slog.Handler
	// redactAll is set once any enclosing group name is itself sensitive.
	redactAll bool
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, redact.String(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactAttr(a, h.redactAll))
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		red = append(red, redactAttr(a, h.redactAll))
	}
	return &redactingHandler{inner: h.inner.WithAttrs(red), redactAll: h.redactAll}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &redactingHandler{
		inner:     h.inner.WithGroup(name),
		redactAll: h.redactAll || redact.Key(name),
	}
}

func redactAttr(a slog.Attr, all bool) slog.Attr {
	if a.Equal(slog.Attr{}) {
		return a
	}
	a.Value = a.Value.Resolve()
	if all || redact.Key(a.Key) {
		return slog.String(a.Key, redact.Placeholder)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redact.String(a.Value.String()))
	case slog.KindGroup:
		group := a.Value.Group()
		out := make([]slog.Attr, 0, len(group))
		for _, g := range group {
			out = append(out, redactAttr(g, false))
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindAny:
		return slog.String(a.Key, renderAny(a.Value.Any()))
	default:
		// Bool, numeric, duration, and time values cannot carry text.
		return a
	}
}

func renderAny(v any) string {
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case error:
		return redact.String(x.Error())
	case fmt.Stringer:
		return redact.String(x.String())
	case []string:
		return redact.String(strings.Join(x, ","))
	case []byte:
		return fmt.Sprintf("[%d bytes omitted]", len(x))
	default:
		return fmt.Sprintf("[unloggable %T]", v)
	}
}
