//go:build !windows

package proton_api_bridge

import "golang.org/x/sys/unix"

// diskAvail returns the number of bytes available to the current user on the
// filesystem containing path, or -1 if it cannot be determined.
func diskAvail(path string) int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize) //nolint:unconvert // Bavail/Bsize types differ across platforms
}
