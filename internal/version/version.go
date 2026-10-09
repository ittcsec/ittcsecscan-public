// Package version reports build identity for ittcsecscan.
//
// Release builds inject identity at link time (see release/build.sh). Other
// builds fall back to the Go toolchain's embedded build information and are
// always reported as development builds. The build time is derived from
// SOURCE_DATE_EPOCH, never from the wall clock, so release binaries are
// reproducible.
package version

import (
	"runtime"
	"runtime/debug"
	"strconv"
	"time"
)

// Link-time values, set with -ldflags "-X". Empty means "not a release build".
var (
	version         string
	commit          string
	sourceDateEpoch string
	treeState       string
)

// DevVersion is reported when no release version was injected.
const DevVersion = "0.0.0-dev"

// Unknown marks a field whose value could not be determined. It is never
// replaced with a guess.
const Unknown = "unknown"

// Source tree states.
const (
	TreeClean    = "clean"
	TreeModified = "modified"
)

// SchemaVersion is the version of the JSON document produced by
// "ittcsecscan version --json" (schemas/cli/v1/version.schema.json).
const SchemaVersion = 1

// Info is the build identity.
type Info struct {
	SchemaVersion int    `json:"schema_version"`
	Version       string `json:"version"`
	Development   bool   `json:"development_build"`
	Commit        string `json:"commit"`
	SourceTree    string `json:"source_tree"`
	BuildTime     string `json:"build_time"`
	GoVersion     string `json:"go_version"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`

	buildTime time.Time
}

// BuildTimestamp returns the build time and whether it is known.
func (i Info) BuildTimestamp() (time.Time, bool) {
	return i.buildTime, !i.buildTime.IsZero()
}

// Get returns the identity of the running binary.
func Get() Info {
	bi, _ := debug.ReadBuildInfo()
	return resolve(linkValues{
		version:         version,
		commit:          commit,
		sourceDateEpoch: sourceDateEpoch,
		treeState:       treeState,
	}, bi)
}

type linkValues struct {
	version, commit, sourceDateEpoch, treeState string
}

func resolve(lv linkValues, bi *debug.BuildInfo) Info {
	info := Info{
		SchemaVersion: SchemaVersion,
		Version:       DevVersion,
		Development:   lv.version == "",
		Commit:        Unknown,
		SourceTree:    Unknown,
		BuildTime:     Unknown,
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
	}

	vcs := map[string]string{}
	if bi != nil {
		for _, s := range bi.Settings {
			vcs[s.Key] = s.Value
		}
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			info.Version = v
		}
	}

	if lv.version != "" {
		info.Version = lv.version
	}

	switch {
	case lv.commit != "":
		info.Commit = lv.commit
	case vcs["vcs.revision"] != "":
		info.Commit = vcs["vcs.revision"]
	}

	switch {
	case lv.treeState == TreeClean || lv.treeState == TreeModified:
		info.SourceTree = lv.treeState
	case vcs["vcs.modified"] == "true":
		info.SourceTree = TreeModified
	case vcs["vcs.modified"] == "false":
		info.SourceTree = TreeClean
	}

	if t, ok := parseEpoch(lv.sourceDateEpoch); ok {
		info.buildTime = t
	} else if t, err := time.Parse(time.RFC3339, vcs["vcs.time"]); err == nil {
		info.buildTime = t.UTC()
	}
	if !info.buildTime.IsZero() {
		info.BuildTime = info.buildTime.Format(time.RFC3339)
	}
	return info
}

func parseEpoch(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}
