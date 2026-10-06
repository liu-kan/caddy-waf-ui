package events

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"
)

// PollArchives follows renamed logs without relying on an old file descriptor
// held by this process. Each archive has its own durable cursor.
func (in *Ingester) PollArchives() error {
	names, err := filepath.Glob(in.Path + ".rotated-*")
	if err != nil {
		return err
	}
	for _, name := range names {
		h := sha256.Sum256([]byte(name))
		state := in.StatePath + ".archive-" + hex.EncodeToString(h[:8])
		archived := &Ingester{Path: name, StatePath: state, Store: in.Store, Norm: in.Norm, ChunkSize: in.ChunkSize, CloudStore: in.CloudStore, CloudRedaction: in.CloudRedaction}
		if err := archived.Poll(); err != nil {
			return err
		}
		// Archives are kept for the retention period after their last write
		// (at least the 48-hour grace for late records of long requests) and
		// removed only once ingested. This is not an exactly-once promise.
		fi, err := os.Stat(name)
		if err != nil {
			return err
		}
		if time.Since(fi.ModTime()) > in.archiveRetention() && archived.Status().Offset == fi.Size() {
			if err := os.Remove(name); err != nil {
				return err
			}
			if err := os.Remove(state); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

// MinArchiveRetention is the shortest archive retention: late records of
// long requests are written to the renamed file for a while.
const MinArchiveRetention = 48 * time.Hour

func (in *Ingester) archiveRetention() time.Duration {
	return max(in.ArchiveRetention, MinArchiveRetention)
}
