//go:build unix && !linux && !darwin

package fsperm

func extendedACLs(string, bool) (access, deflt []byte, incomplete string, err error) {
	return nil, nil, "extended ACLs are not inspected on this platform", nil
}
