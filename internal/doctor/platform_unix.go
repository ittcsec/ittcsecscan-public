//go:build unix

package doctor

import "os"

func isElevated() (bool, error) { return os.Geteuid() == 0, nil }
