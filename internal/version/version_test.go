package version

import (
	"runtime/debug"
	"testing"
)

func TestResolveDevelopmentDefaults(t *testing.T) {
	info := resolve(linkValues{}, nil)
	if !info.Development || info.Version != DevVersion {
		t.Errorf("want development build %q, got dev=%v version=%q", DevVersion, info.Development, info.Version)
	}
	if info.Commit != Unknown || info.SourceTree != Unknown || info.BuildTime != Unknown {
		t.Errorf("unknown fields must be reported as unknown: %+v", info)
	}
	if _, ok := info.BuildTimestamp(); ok {
		t.Error("BuildTimestamp must report unknown")
	}
	if info.SchemaVersion != SchemaVersion {
		t.Errorf("schema version %d", info.SchemaVersion)
	}
}

func TestResolveRelease(t *testing.T) {
	info := resolve(linkValues{
		version:         "1.2.3",
		commit:          "abc123",
		sourceDateEpoch: "1767225600",
		treeState:       TreeClean,
	}, &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}})
	if info.Development {
		t.Error("release build reported as development")
	}
	if info.Version != "1.2.3" || info.Commit != "abc123" || info.SourceTree != TreeClean {
		t.Errorf("unexpected identity: %+v", info)
	}
	if info.BuildTime != "2026-01-01T00:00:00Z" {
		t.Errorf("BuildTime = %q", info.BuildTime)
	}
}

func TestResolveFromVCS(t *testing.T) {
	info := resolve(linkValues{}, &debug.BuildInfo{
		Main: debug.Module{Version: "v0.4.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "deadbeef"},
			{Key: "vcs.time", Value: "2026-03-04T05:06:07Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	})
	if !info.Development {
		t.Error("a build without injected version is a development build")
	}
	if info.Version != "v0.4.0" || info.Commit != "deadbeef" || info.SourceTree != TreeModified {
		t.Errorf("unexpected identity: %+v", info)
	}
	if info.BuildTime != "2026-03-04T05:06:07Z" {
		t.Errorf("BuildTime = %q", info.BuildTime)
	}
}

func TestResolveRejectsBadEpoch(t *testing.T) {
	for _, e := range []string{"-1", "0", "abc", "1e9"} {
		if info := resolve(linkValues{sourceDateEpoch: e}, nil); info.BuildTime != Unknown {
			t.Errorf("epoch %q produced %q, want unknown", e, info.BuildTime)
		}
	}
}

func TestResolveIgnoresUnknownTreeState(t *testing.T) {
	if info := resolve(linkValues{treeState: "pristine"}, nil); info.SourceTree != Unknown {
		t.Errorf("SourceTree = %q", info.SourceTree)
	}
}
