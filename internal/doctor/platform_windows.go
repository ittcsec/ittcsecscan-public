//go:build windows

package doctor

import "golang.org/x/sys/windows"

func isElevated() (bool, error) {
	return windows.GetCurrentProcessToken().IsElevated(), nil
}
