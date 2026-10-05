//go:build !unix

package events

import "os"

// fileIdentity is unavailable on this platform: rotation is then detected
// only by size.
func fileIdentity(os.FileInfo) (dev, ino uint64) { return 0, 0 }
