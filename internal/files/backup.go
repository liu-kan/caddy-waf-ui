package files

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// ErrInvalidBackup signals an invalid or nonexistent snapshot name. REST
// handlers translate it to 400 Bad Request (same pattern as ErrInvalidMode).
var ErrInvalidBackup = errors.New("invalid configuration snapshot")

// backupNamePattern validates the canonical name of a snapshot:
// {ISO8601 UTC with :→-}.{type}.conf - e.g.: 2026-08-07T15-52-13Z.waf.conf.
// The strict timestamp (optional nine-digit fraction) + known type prevents path
// traversal and any name outside the backup convention.
// The type set is built from the FileType* constants (J5-7) so regexes and
// switches never diverge.
var backupNamePattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:\.[0-9]{9})?Z)\.(` +
	FileTypeWAF + `|` + FileTypeExclusions + `|` + FileTypeIPRules + `)\.conf$`)

// BackupType validates a snapshot name and returns the overlay type it
// belongs to ("waf" | "exclusions" | "ip-rules"). It rejects names with
// path separators or outside the canonical format (anti path traversal).
func BackupType(snapshotID string) (string, error) {
	m := backupNamePattern.FindStringSubmatch(snapshotID)
	if m == nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidBackup, snapshotID)
	}
	return m[2], nil
}

// ListBackups returns the configuration snapshots of a domain ordered from
// newest to oldest. Files that do not follow the naming convention are
// ignored; without a backups directory it returns an empty list (honest
// empty state, never an error).
func ListBackups(domainName string) ([]BackupInfo, error) {
	entries, err := os.ReadDir(BackupDirPath(backupDirPath(), domainName))
	if os.IsNotExist(err) {
		return []BackupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}

	backups := make([]BackupInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		m := backupNamePattern.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{Timestamp: m[1], FileType: m[2], Size: info.Size()})
	}

	// The hyphenated ISO8601 sorts lexicographically = chronologically:
	// descending leaves the newest snapshot first.
	sort.Slice(backups, func(i, j int) bool {
		keyI := timestampSortKey(backups[i].Timestamp) + backups[i].FileType
		keyJ := timestampSortKey(backups[j].Timestamp) + backups[j].FileType
		return keyI > keyJ
	})

	return backups, nil
}

// RestoreBackup restores the bytes of the given snapshot (full name
// {ISO8601}.{type}.conf) over the overlay of its type with atomic writes
// (bytes → conf path). It fails if the name is invalid or the snapshot does
// not exist.
func RestoreBackup(domainName, snapshotID string) error {
	fileType, err := BackupType(snapshotID)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(filepath.Join(BackupDirPath(backupDirPath(), domainName), snapshotID))
	if os.IsNotExist(err) {
		return fmt.Errorf("%w: snapshot %q does not exist", ErrInvalidBackup, snapshotID)
	}
	if err != nil {
		return err
	}

	confPath, err := OverlayPath(managedDirPath(), fileType, domainName)
	if err != nil {
		return err
	}
	return AtomicWrite(confPath, content)
}

// BackupInfo describes a configuration snapshot available for rollback.
// Phase 4 completes the read path (ListBackups/RestoreBackup); the UI already
// consumes the shape to render the history (rollback.html).
type BackupInfo struct {
	Timestamp string
	FileType  string
	Size      int64
}

// managedDirPath returns the managed overlays directory. Centralized in
// config (finding J5-3): it used to live triplicated in chain.go, backup.go
// and pages.go with the same environment read.
func managedDirPath() string {
	return config.ManagedDir()
}

// backupDirPath returns the root snapshots directory.
func backupDirPath() string {
	return config.BackupDir()
}

// Backup takes the current state of a domain's configuration file and
// creates a snapshot. It respects the retention limit defined by the
// environment variables[cite: 4].
func Backup(domainName string, fileType string) error {
	// 1. Define paths based on the environment variables
	managedDir := managedDirPath()
	backupDir := backupDirPath()

	keepLimit := config.BackupKeep()

	// Source file in /ui-managed/
	// E.g.: waf-api_example_com.conf
	// The slug is used both for the source and the backups directory (bug
	// #265): the raw wildcard domain ("*") cannot be part of a path.
	sourceFileName := fmt.Sprintf("%s-%s.conf", fileType, domain.DomainSlug(domainName))
	sourcePath := filepath.Join(managedDir, sourceFileName)

	// If the source file does not exist, there is nothing to back up (e.g.:
	// first time it is configured). Any other stat error (e.g. EACCES) is a
	// real failure and must be propagated, not treated as "no previous backup".
	if _, err := os.Stat(sourcePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error checking source file %q: %w", sourcePath, err)
	}

	// 2. Create the backup directory for this domain
	domainBackupDir := BackupDirPath(backupDir, domainName)
	if err := os.MkdirAll(domainBackupDir, 0750); err != nil {
		return fmt.Errorf("error creating backup directory: %w", err)
	}

	// 3. Generate the snapshot with format {ISO8601}.{fileType}.conf[cite: 1]
	// We use a filename-safe format (replacing : with -)
	timestamp := time.Now().UTC().Format("2006-01-02T15-04-05.000000000Z")
	backupFileName := fmt.Sprintf("%s.%s.conf", timestamp, fileType)
	backupPath := filepath.Join(domainBackupDir, backupFileName)

	if err := copyFile(sourcePath, backupPath); err != nil {
		return fmt.Errorf("error copying backup: %w", err)
	}

	// 4. Apply the retention policy (remove old backups)
	return enforceRetention(domainBackupDir, fileType, keepLimit)
}

// copyFile is a helper that copies the bytes of one file to another
func copyFile(src, dst string) (err error) {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()

	// Snapshot files use the same restricted owner/group policy as overlays.
	destFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640) //nolint:gosec // G302: intentional shared UID/GID 65532, no world access.
	if err != nil {
		return err
	}
	defer func() {
		_ = destFile.Close()
		if err != nil {
			_ = os.Remove(dst)
		}
	}()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}
	return destFile.Close()
}

func timestampSortKey(timestamp string) string {
	if strings.Contains(timestamp, ".") {
		return timestamp
	}
	return strings.TrimSuffix(timestamp, "Z") + ".000000000Z"
}

// enforceRetention removes the oldest snapshots when the limit is exceeded
func enforceRetention(dir, fileType string, limit int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// Filter only the canonical snapshots of this specific type (waf,
	// exclusions, ip-rules): the same strict regex as ListBackups, so
	// retention and listing agree on what counts as a backup.
	var backups []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		m := backupNamePattern.FindStringSubmatch(entry.Name())
		if m == nil || m[2] != fileType {
			continue
		}
		backups = append(backups, entry)
	}

	// If we are within the limit, do nothing
	if len(backups) <= limit {
		return nil
	}

	// Sort alphabetically (with the ISO8601 as built, alphabetical order is
	// chronological)
	sort.Slice(backups, func(i, j int) bool {
		mi := backupNamePattern.FindStringSubmatch(backups[i].Name())
		mj := backupNamePattern.FindStringSubmatch(backups[j].Name())
		return timestampSortKey(mi[1]) < timestampSortKey(mj[1])
	})

	// Remove the oldest
	toDelete := len(backups) - limit
	for i := 0; i < toDelete; i++ {
		oldPath := filepath.Join(dir, backups[i].Name())
		if err := os.Remove(oldPath); err != nil {
			return fmt.Errorf("error removing old backup %s: %w", oldPath, err)
		}
	}

	return nil
}
