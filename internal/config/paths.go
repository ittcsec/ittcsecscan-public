package config

import (
	"errors"
	"path"
	"path/filepath"
)

const appName = "ittcsecscan"

// platformDirs returns the per-user configuration and data directories for
// goos, using lookup for every environment read so that tests are hermetic.
//
//	windows: %APPDATA%\ittcsecscan            %LOCALAPPDATA%\ittcsecscan
//	darwin:  ~/Library/Application Support/ittcsecscan (both)
//	other:   $XDG_CONFIG_HOME/ittcsecscan     $XDG_DATA_HOME/ittcsecscan
//	         (defaulting to ~/.config and ~/.local/share)
func platformDirs(goos string, lookup LookupEnv) (configDir, dataDir string, err error) {
	get := func(key string) string {
		v, _ := lookup(key)
		return v
	}
	switch goos {
	case "windows":
		appData, localAppData := get("APPDATA"), get("LOCALAPPDATA")
		if appData == "" || localAppData == "" {
			return "", "", errors.New("%APPDATA% or %LOCALAPPDATA% is not set")
		}
		return filepath.Join(appData, appName), filepath.Join(localAppData, appName), nil
	case "darwin":
		home := get("HOME")
		if home == "" {
			return "", "", errors.New("$HOME is not set")
		}
		dir := path.Join(home, "Library", "Application Support", appName)
		return dir, dir, nil
	default:
		home := get("HOME")
		cfg, cfgErr := xdgDir(get("XDG_CONFIG_HOME"), home, ".config")
		data, dataErr := xdgDir(get("XDG_DATA_HOME"), home, ".local/share")
		if err := errors.Join(cfgErr, dataErr); err != nil {
			return "", "", err
		}
		return path.Join(cfg, appName), path.Join(data, appName), nil
	}
}

// xdgDir applies the XDG Base Directory rule: a relative value is invalid and
// must be ignored in favour of the default under $HOME.
func xdgDir(value, home, fallback string) (string, error) {
	if value != "" && path.IsAbs(value) {
		return value, nil
	}
	if home == "" {
		return "", errors.New("$HOME is not set")
	}
	return path.Join(home, fallback), nil
}
