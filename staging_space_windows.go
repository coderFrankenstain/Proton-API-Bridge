//go:build windows

package proton_api_bridge

import "golang.org/x/sys/windows"

// diskAvail returns the number of bytes available to the current user on the
// filesystem containing path, or -1 if it cannot be determined.
func diskAvail(path string) int64 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return -1
	}
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeBytesAvailable, &totalBytes, &totalFreeBytes); err != nil {
		return -1
	}
	return int64(freeBytesAvailable)
}
