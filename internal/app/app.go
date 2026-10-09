// Package app assembles the runtime for one command invocation: effective
// configuration, the redacting logger, and build identity.
//
// Commands receive everything through *App; nothing reads global state, so each
// command is testable with an injected environment and output streams.
package app

import (
	"io"
	"log/slog"

	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/logging"
	"github.com/ittcsec/ittcsecscan/internal/version"
)

// Options are the inputs to New and NewLenient.
type Options struct {
	Overrides config.Overrides
	LookupEnv config.LookupEnv
	// Stderr receives log output.
	Stderr io.Writer
}

// App is the assembled runtime.
type App struct {
	Config       config.Config
	ConfigSource config.Source
	// ConfigErr is non-nil only for NewLenient, when configuration failed to
	// load and built-in defaults are in effect instead. ConfigSource then still
	// names the file that failed, so doctor can inspect its permissions.
	ConfigErr error
	Logger    *slog.Logger
	Build     version.Info
}

// New assembles the runtime. A configuration problem is returned as an
// exitcode.Config error: commands that act on configuration must not run on a
// guess.
func New(o Options) (*App, error) {
	a := NewLenient(o)
	if a.ConfigErr != nil {
		return nil, exitcode.Wrap(exitcode.Config, a.ConfigErr)
	}
	return a, nil
}

// NewLenient assembles the runtime even when configuration is invalid, falling
// back to defaults and recording the error in ConfigErr. Only diagnostic
// commands (doctor) use it, so they can report the problem.
func NewLenient(o Options) *App {
	cfg, src, err := config.Load(o.Overrides, o.LookupEnv)
	if err != nil {
		cfg = config.Defaults(o.LookupEnv) // src still names the attempted file
	}
	level, lerr := logging.ParseLevel(cfg.Log.Level)
	format, ferr := logging.ParseFormat(cfg.Log.Format)
	if lerr != nil || ferr != nil {
		// Unreachable after schema validation; fall back rather than panic.
		level, format = slog.LevelInfo, logging.FormatText
	}
	return &App{
		Config:       cfg,
		ConfigSource: src,
		ConfigErr:    err,
		Logger:       logging.New(o.Stderr, level, format),
		Build:        version.Get(),
	}
}
