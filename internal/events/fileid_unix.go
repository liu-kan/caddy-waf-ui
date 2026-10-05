//go:build unix

package events

import (
	"os"
	"syscall"
)

// fileIdentity returns the device and inode of a file, used to notice that
// the audit log was replaced (rotation) between polls.
func fileIdentity(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino //nolint:gosec,unconvert // G115: device numbers are identifiers (int32 on darwin), not quantities.
	}
	return 0, 0
}
