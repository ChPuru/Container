//go:build !linux

package network

import "fmt"

// newLinkOps reports that container networking is unavailable. hull's bridges,
// veth pairs and namespaces are Linux kernel objects; the Windows CLI links
// this package only for its types and its pure helpers.
func newLinkOps() (linkOps, error) {
	return nil, fmt.Errorf("%w: bridge networking requires a Linux kernel; "+
		"run hulld inside the WSL engine distro", ErrUnsupported)
}
