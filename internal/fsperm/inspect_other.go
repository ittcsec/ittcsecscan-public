//go:build !unix && !windows

package fsperm

import (
	"errors"
	"fmt"
)

func inspect(path string) (Report, error) {
	return Report{}, fmt.Errorf("inspecting permissions of %s: %w", path, errors.ErrUnsupported)
}
