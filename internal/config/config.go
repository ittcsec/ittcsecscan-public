// Package config loads ittcsecscan configuration.
//
// Sources, in increasing precedence:
//
//  1. Built-in defaults.
//  2. A JSON file: --config, else $ITTCSECSCAN_CONFIG, else the per-user
//     default location if a file exists there.
//  3. Environment variables (ITTCSECSCAN_LOG_LEVEL, ITTCSECSCAN_LOG_FORMAT,
//     ITTCSECSCAN_DATA_DIR).
//  4. Command-line flags.
//
// The file is validated against the embedded JSON Schema
// (schemas/config/v1/config.schema.json) before it is decoded, and the result
// is revalidated after each layer so that a bad value is reported against the
// layer that introduced it.
//
// Configuration never contains credentials. Cloud access always comes from the
// provider's native credential chain. The schema rejects unknown keys, so a
// secret pasted into the file is an error rather than a silently kept value.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/schema"
)

// SchemaVersion is the configuration schema version this build understands.
const SchemaVersion = 1

// FileName is the configuration file name in the default location.
const FileName = "config.json"

// MaxFileSize bounds how much of a configuration file is read.
const MaxFileSize = 1 << 20

// maxDepth bounds JSON nesting in the configuration file.
const maxDepth = 32

// Environment variables read by Load.
const (
	EnvConfig        = "ITTCSECSCAN_CONFIG"
	EnvLogLevel      = "ITTCSECSCAN_LOG_LEVEL"
	EnvLogFormat     = "ITTCSECSCAN_LOG_FORMAT"
	EnvDataDir       = "ITTCSECSCAN_DATA_DIR"
	EnvMasterKeyFile = "ITTCSECSCAN_MASTER_KEY_FILE"
)

// Config is the effective configuration. Its JSON encoding is the v1 schema.
type Config struct {
	SchemaVersion int    `json:"schema_version"`
	Log           Log    `json:"log"`
	DataDir       string `json:"data_dir,omitempty"`
	// MasterKeyFile is the absolute path of the operator's passphrase-wrapped
	// master-key file (ADR-0015). It holds the path only, never the key, and
	// must lie outside the data directory. Empty means no key file is
	// configured; a command that must open the store then fails closed.
	MasterKeyFile string `json:"master_key_file,omitempty"`
}

// Log configures diagnostic logging.
type Log struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// LookupEnv reads an environment variable. Load never reads the process
// environment directly.
type LookupEnv func(key string) (string, bool)

// Overrides are command-line values. Empty fields are unset.
type Overrides struct {
	ConfigPath    string
	LogLevel      string
	LogFormat     string
	DataDir       string
	MasterKeyFile string
}

// Source records where the configuration file came from.
type Source struct {
	// File is the configuration file that was loaded, or "" if none was.
	File string
	// Explicit is true when File was named by --config or ITTCSECSCAN_CONFIG.
	Explicit bool
}

func (s Source) String() string {
	if s.File == "" {
		return "built-in defaults (no configuration file)"
	}
	return s.File
}

// Defaults returns the built-in configuration. DataDir is empty when the
// platform data directory cannot be determined.
func Defaults(lookup LookupEnv) Config {
	_, dataDir, err := platformDirs(runtime.GOOS, lookup)
	if err != nil || !filepath.IsAbs(dataDir) {
		dataDir = ""
	}
	return Config{
		SchemaVersion: SchemaVersion,
		Log:           Log{Level: "info", Format: "text"},
		DataDir:       dataDir,
	}
}

// Load builds the effective configuration. On error, the returned Source still
// names the configuration file that was attempted, so diagnostics can inspect
// its permissions.
func Load(o Overrides, lookup LookupEnv) (Config, Source, error) {
	cfg := Defaults(lookup)

	src, err := locate(o, lookup)
	if err != nil {
		return Config{}, Source{}, err
	}
	if src.File != "" {
		if err := loadFile(src.File, &cfg); err != nil {
			return Config{}, src, fmt.Errorf("configuration file %s: %w", src.File, err)
		}
	}
	if applyEnv(&cfg, lookup) {
		if err := validate(cfg); err != nil {
			return Config{}, src, fmt.Errorf("environment variables: %w", err)
		}
	}
	if applyOverrides(&cfg, o) {
		if err := validate(cfg); err != nil {
			return Config{}, src, fmt.Errorf("command-line flags: %w", err)
		}
	}
	if err := validate(cfg); err != nil {
		return Config{}, src, fmt.Errorf("effective configuration: %w", err)
	}
	return cfg, src, nil
}

func locate(o Overrides, lookup LookupEnv) (Source, error) {
	if o.ConfigPath != "" {
		return Source{File: o.ConfigPath, Explicit: true}, nil
	}
	if v, ok := lookup(EnvConfig); ok && v != "" {
		return Source{File: v, Explicit: true}, nil
	}
	p, ok := defaultConfigPath(lookup)
	if !ok {
		return Source{}, nil
	}
	_, err := os.Stat(p)
	switch {
	case err == nil:
		return Source{File: p}, nil
	case errors.Is(err, fs.ErrNotExist):
		return Source{}, nil
	default:
		// A file we cannot inspect is an error, never silently skipped.
		return Source{}, fmt.Errorf("configuration file %s: %w", p, err)
	}
}

// defaultConfigPath returns the per-user configuration file location. It
// reports false when no location can be determined (for example $HOME is
// unset); there is then no default file, and doctor reports the missing data
// directory separately.
func defaultConfigPath(lookup LookupEnv) (string, bool) {
	configDir, _, err := platformDirs(runtime.GOOS, lookup)
	if err != nil {
		return "", false
	}
	return filepath.Join(configDir, FileName), true
}

func loadFile(path string, into *Config) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	if err := decode(data, into); err != nil {
		return err
	}
	return validate(*into)
}

func readFile(path string) ([]byte, error) {
	// Stat before open: opening a FIFO or device could block or have side
	// effects.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("larger than %d bytes", MaxFileSize)
	}
	f, err := os.Open(path) //nolint:gosec // G304: opening the operator-selected configuration file is this function's purpose; it is stat-checked, regular, and size-bounded.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("larger than %d bytes", MaxFileSize)
	}
	return data, nil
}

// decode validates raw file content and decodes it on top of into.
func decode(data []byte, into *Config) error {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM written by some editors
	if err := checkStructure(data); err != nil {
		return err
	}
	doc, err := schema.Decode(data)
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := schema.Validate(schema.Config, doc); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("decoding: %w", err)
	}
	return nil
}

// checkStructure rejects JSON that the schema validator would accept but that
// is ambiguous or abusive: duplicate object keys (parsers disagree on which one
// wins), excessive nesting, and trailing data after the top-level value.
func checkStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walk(dec, "", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON: unexpected data after the top-level value")
	}
	return nil
}

func walk(dec *json.Decoder, ptr string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("invalid JSON: nested deeper than %d levels", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}
			key, ok := kt.(string)
			if !ok {
				return errors.New("invalid JSON: object key is not a string")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate key %q at %s", key, pointer(ptr))
			}
			seen[key] = struct{}{}
			if err := walk(dec, ptr+"/"+escapePointer(key), depth+1); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walk(dec, ptr+"/"+strconv.Itoa(i), depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON: unexpected %q", delim)
	}
	if _, err := dec.Token(); err != nil { // closing delimiter
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func pointer(p string) string {
	if p == "" {
		return "the top level"
	}
	return "'" + p + "'"
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func applyEnv(c *Config, lookup LookupEnv) bool {
	changed := false
	set := func(dst *string, key string) {
		if v, ok := lookup(key); ok && v != "" {
			*dst = v
			changed = true
		}
	}
	set(&c.Log.Level, EnvLogLevel)
	set(&c.Log.Format, EnvLogFormat)
	set(&c.DataDir, EnvDataDir)
	set(&c.MasterKeyFile, EnvMasterKeyFile)
	return changed
}

func applyOverrides(c *Config, o Overrides) bool {
	changed := false
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
			changed = true
		}
	}
	set(&c.Log.Level, o.LogLevel)
	set(&c.Log.Format, o.LogFormat)
	set(&c.DataDir, o.DataDir)
	set(&c.MasterKeyFile, o.MasterKeyFile)
	return changed
}

// validate checks the effective configuration against the schema plus the
// constraints JSON Schema cannot express portably.
func validate(c Config) error {
	if err := schema.ValidateValue(schema.Config, c); err != nil {
		return err
	}
	if c.DataDir != "" && !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("data_dir must be an absolute path, got %q", c.DataDir)
	}
	if c.MasterKeyFile != "" {
		if !filepath.IsAbs(c.MasterKeyFile) {
			return fmt.Errorf("master_key_file must be an absolute path, got %q", c.MasterKeyFile)
		}
		// The master key must live outside the data directory (ADR-0015): the
		// data directory holds tenant files, which the key protects.
		if c.DataDir != "" {
			if rel, err := filepath.Rel(c.DataDir, c.MasterKeyFile); err == nil &&
				rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("master_key_file must be outside data_dir (ADR-0015): %q is inside %q", c.MasterKeyFile, c.DataDir)
			}
		}
	}
	return nil
}
