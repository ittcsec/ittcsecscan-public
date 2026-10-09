//go:build !unix && !windows

package doctor

import "errors"

func isElevated() (bool, error) { return false, errors.ErrUnsupported }
