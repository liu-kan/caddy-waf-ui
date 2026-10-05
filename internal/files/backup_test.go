package files_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

// TestBackupWildcardSlug verifies the fix for bug #265:
// the directory and the source file must use the normalized slug,
// never the raw domain (a literal "*" cannot be part of a safe path).
func TestBackupWildcardSlug(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	// The real source file is generated as waf-{slug}.conf (see WAFConfigPath).
	sourcePath := filepath.Join(managedDir, "waf-wildcard_example_com.conf")
	content := []byte("# domain: *.example.com | mode: On | updated: 2026-07-22T14:00:00Z\n")
	if err := os.WriteFile(sourcePath, content, 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	if err := files.Backup("*.example.com", "waf"); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// The backup must live in the slug-normalized directory.
	slugDir := filepath.Join(backupDir, "wildcard_example_com")
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("backup directory with slug %q not found: %v", slugDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 snapshot in %q, found %d", slugDir, len(entries))
	}

	// A directory with the raw domain must never exist.
	rawDir := filepath.Join(backupDir, "*.example.com")
	if _, err := os.Stat(rawDir); !os.IsNotExist(err) {
		t.Errorf("a backup directory with the raw domain %q must not exist (bug #265)", rawDir)
	}
}

// TestBackupRetention verifies that CADDY_UI_BACKUP_KEEP is honored:
// when the limit is exceeded, the oldest snapshots of the same type are
// removed.
func TestBackupRetention(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "1")

	sourcePath := filepath.Join(managedDir, "waf-api_example_com.conf")
	if err := os.WriteFile(sourcePath, []byte("# domain: api.example.com\n"), 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	// Seed two previous snapshots of the same type (alphabetical order =
	// chronological).
	slugDir := filepath.Join(backupDir, "api_example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed to create slugDir: %v", err)
	}
	old := []string{
		"2020-01-01T00-00-00Z.waf.conf",
		"2021-01-01T00-00-00Z.waf.conf",
	}
	for _, name := range old {
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte("v"), 0640); err != nil {
			t.Fatalf("failed to seed snapshot %s: %v", name, err)
		}
	}

	if err := files.Backup("api.example.com", "waf"); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("failed to read the backups directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("retention with KEEP=1: expected 1 snapshot, found %d", len(entries))
	}
	// The surviving snapshot must be the newly created one, not the seeded ones.
	if entries[0].Name() == old[0] || entries[0].Name() == old[1] {
		t.Errorf("retention left a seeded snapshot (%s) instead of the newest one", entries[0].Name())
	}
	// The snapshot created now must carry the current timestamp (ISO8601
	// format with ":" replaced).
	if fileType, err := files.BackupType(entries[0].Name()); err != nil || fileType != files.FileTypeWAF {
		t.Errorf("new snapshot is not a valid restorable WAF snapshot: %q (%v)", entries[0].Name(), err)
	}
}

// TestBackupSourceStatErrorReturnsError: a stat error other than IsNotExist
// (e.g. ENOTDIR because managedDir is a file) must be propagated, not treated
// as "nothing to back up" (finding J1).
func TestBackupSourceStatErrorReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	managedAsFile := filepath.Join(tmpDir, "managed-es-un-archivo")
	if err := os.WriteFile(managedAsFile, []byte("x"), 0640); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedAsFile)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.Backup("example.com", "waf"); err == nil {
		t.Fatal("Backup with a failed stat (ENOTDIR) must return an error")
	}
}

// TestBackupRetentionIgnoresNonCanonical: retention uses the same strict
// regex as ListBackups - a file that merely "contains" .waf.conf but does not
// follow the canonical format does not count toward the limit nor get
// removed.
func TestBackupRetentionIgnoresNonCanonical(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "1")

	sourcePath := filepath.Join(managedDir, "waf-example_com.conf")
	if err := os.WriteFile(sourcePath, []byte("# domain: example.com\n"), 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	slugDir := filepath.Join(backupDir, "example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed to create slugDir: %v", err)
	}
	// Three canonical snapshots + a non-canonical name that a strings.Contains
	// would have counted (and removed) by mistake.
	for _, name := range []string{
		"2020-01-01T00-00-00Z.waf.conf",
		"2020-01-02T00-00-00Z.waf.conf",
		"2020-01-03T00-00-00Z.waf.conf",
		"notas.waf.conf.txt",
	} {
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte("v"), 0640); err != nil {
			t.Fatalf("failed to seed %s: %v", name, err)
		}
	}

	if err := files.Backup("example.com", "waf"); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// KEEP=1: the non-canonical file must survive retention.
	if _, err := os.Stat(filepath.Join(slugDir, "notas.waf.conf.txt")); err != nil {
		t.Errorf("the non-canonical file must survive retention: %v", err)
	}
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("failed to read slugDir: %v", err)
	}
	// 1 canonical (the newly created) + 1 non-canonical.
	if len(entries) != 2 {
		t.Fatalf("KEEP=1 with a non-canonical file: expected 2 files, got %d", len(entries))
	}
}

// seedSnapshot seeds a snapshot file in the backups directory of the slug.
func seedSnapshot(t *testing.T, backupDir, domainName, name, content string) {
	t.Helper()
	slugDir := filepath.Join(backupDir, domain.DomainSlug(domainName))
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed to create slugDir %q: %v", slugDir, err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("failed to seed snapshot %s: %v", name, err)
	}
}

// TestListBackupsSortedNewestFirst: ListBackups returns the domain snapshots
// ordered from newest to oldest, with the real size, and ignores files that
// do not follow the {ISO8601}.{type}.conf pattern.
func TestListBackupsSortedNewestFirst(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	seedSnapshot(t, backupDir, "api.example.com", "2020-01-01T00-00-00Z.waf.conf", "waf-2020")
	seedSnapshot(t, backupDir, "api.example.com", "2021-01-01T00-00-00Z.waf.conf", "waf-2021")
	seedSnapshot(t, backupDir, "api.example.com", "2021-01-01T00-00-00Z.exclusions.conf", "exc-2021")
	seedSnapshot(t, backupDir, "api.example.com", "not-a-backup.txt", "ignorado")

	backups, err := files.ListBackups("api.example.com")
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups) != 3 {
		t.Fatalf("expected 3 snapshots (the .txt does not count), got %d", len(backups))
	}

	// Order: newest to oldest (the hyphenated ISO sorts lexicographically).
	if backups[0].Timestamp != "2021-01-01T00-00-00Z" || backups[0].FileType != "waf" {
		t.Errorf("the first must be the 2021 waf, got %+v", backups[0])
	}
	if backups[1].FileType != "exclusions" {
		t.Errorf("the second must be the 2021 exclusions, got %+v", backups[1])
	}
	if backups[2].Timestamp != "2020-01-01T00-00-00Z" || backups[2].FileType != "waf" {
		t.Errorf("the last must be the 2020 waf, got %+v", backups[2])
	}

	// The size must be the real one of the file.
	if backups[0].Size != int64(len("waf-2021")) {
		t.Errorf("size of snapshot waf-2021 = %d; expected %d", backups[0].Size, len("waf-2021"))
	}
}

// TestListBackupsEmptyDirReturnsEmpty: with no backups directory (or empty)
// the listing returns an empty list, not an error (honest empty state in the
// UI).
func TestListBackupsEmptyDirReturnsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups")) // does not exist yet

	backups, err := files.ListBackups("api.example.com")
	if err != nil {
		t.Fatalf("ListBackups without a directory must return an empty list without error, got: %v", err)
	}
	if len(backups) != 0 {
		t.Errorf("without backups: expected an empty list, got %d", len(backups))
	}
}

// TestRestoreBackupWritesBytesToConfPath: RestoreBackup copies the bytes of
// the chosen snapshot over the overlay of the corresponding type (waf →
// waf-{slug}.conf).
func TestRestoreBackupWritesBytesToConfPath(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	snapContent := "# domain: api.example.com | mode: Off\n(snippet restaurado)\n"
	seedSnapshot(t, backupDir, "api.example.com", "2020-01-01T00-00-00Z.waf.conf", snapContent)

	if err := files.RestoreBackup("api.example.com", "2020-01-01T00-00-00Z.waf.conf"); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay waf-api_example_com.conf was not written: %v", err)
	}
	if string(got) != snapContent {
		t.Errorf("the overlay must contain exactly the snapshot bytes:\n%s", got)
	}
}

// TestRestoreBackupRejectsUnsafeNames: names with path separators, unknown
// types or without the exact format must be rejected without writing
// anything.
func TestRestoreBackupRejectsUnsafeNames(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	for _, bad := range []string{
		"",                                  // empty
		"../evil.conf",                      // path traversal
		"/etc/passwd",                       // absolute path
		"2020-01-01T00-00-00Z",              // missing extension
		"2020-01-01T00-00-00Z.unknown.conf", // unsupported type
		"2020-01-01T00:00:00Z.waf.conf",     // ISO format with ":" (not a snapshot name)
	} {
		if err := files.RestoreBackup("api.example.com", bad); err == nil {
			t.Errorf("RestoreBackup(%q) must be rejected", bad)
		}
	}

	// No file must have been written with invalid names.
	if _, err := os.Stat(filepath.Join(managedDir, "waf-api_example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("the overlay must not be written with invalid snapshot names")
	}
}

// TestRestoreBackupMissingSnapshotFails: a valid name but no file (deleted or
// nonexistent) must fail with an error and write nothing.
func TestRestoreBackupMissingSnapshotFails(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.RestoreBackup("api.example.com", "2099-01-01T00-00-00Z.waf.conf"); err == nil {
		t.Fatal("RestoreBackup of a nonexistent snapshot must fail")
	}
	if _, err := os.Stat(filepath.Join(managedDir, "waf-api_example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("the overlay must not be written if the snapshot does not exist")
	}
}

// TestBackupTypeParsesValidNames: BackupType extracts the overlay type of a
// valid snapshot name (the three managed types).
func TestBackupTypeParsesValidNames(t *testing.T) {
	cases := []struct{ name, want string }{
		{"2026-08-07T15-52-13Z.waf.conf", "waf"},
		{"2026-08-07T15-52-13Z.exclusions.conf", "exclusions"},
		{"2026-08-07T15-52-13Z.ip-rules.conf", "ip-rules"},
	}
	for _, tc := range cases {
		got, err := files.BackupType(tc.name)
		if err != nil {
			t.Errorf("BackupType(%q) failed: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("BackupType(%q) = %q; expected %q", tc.name, got, tc.want)
		}
	}
}

// TestBackupTypeRejectsUnsafeNames: unsafe or malformed names must yield an
// error (never a valid type).
func TestBackupTypeRejectsUnsafeNames(t *testing.T) {
	for _, bad := range []string{
		"",                                  // empty
		"../evil.conf",                      // path traversal
		"etc/passwd",                        // relative subdirectory
		"2020-01-01T00-00-00Z",              // missing extension
		"2020-01-01T00-00-00Z.waf",          // missing .conf
		"2020-01-01T00-00-00Z.txt.conf",     // unknown type
		"2020-01-01T00:00:00Z.waf.conf",     // ISO with ":" (broken convention)
		"2020-01-01T00-00-00Z.waf.conf.bak", // extra suffix
	} {
		if _, err := files.BackupType(bad); err == nil {
			t.Errorf("BackupType(%q) must be rejected", bad)
		}
	}
}

func TestRestoreBackupErrors(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CADDY_UI_MANAGED_DIR", filepath.Join(tmpDir, "managed"))
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	// 1. Invalid snapshot ID
	if err := files.RestoreBackup("example.com", "not-a-valid-snapshot"); err == nil {
		t.Error("RestoreBackup with invalid snapshot name expected error, got nil")
	}

	// 2. Nonexistent snapshot
	if err := files.RestoreBackup("example.com", "2026-01-01T00-00-00Z.waf.conf"); err == nil {
		t.Error("RestoreBackup with nonexistent snapshot expected error, got nil")
	}
}

func TestListBackupsIgnoresSubdirsAndNonMatchingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	domainSlugDir := filepath.Join(backupDir, "example_com")
	if err := os.MkdirAll(domainSlugDir, 0750); err != nil {
		t.Fatalf("failed to create backup dir: %v", err)
	}

	// Create a subdirectory inside the domain backup dir
	if err := os.Mkdir(filepath.Join(domainSlugDir, "nested-dir"), 0750); err != nil {
		t.Fatalf("failed to create nested dir: %v", err)
	}

	// Create a non-matching file
	if err := os.WriteFile(filepath.Join(domainSlugDir, "random.txt"), []byte("data"), 0640); err != nil {
		t.Fatalf("failed to write non-matching file: %v", err)
	}

	// Create a valid snapshot file
	validFile := filepath.Join(domainSlugDir, "2026-09-01T12-00-00Z.waf.conf")
	if err := os.WriteFile(validFile, []byte("# domain: example.com"), 0640); err != nil {
		t.Fatalf("failed to write valid snapshot: %v", err)
	}

	backups, err := files.ListBackups("example.com")
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups) != 1 {
		t.Errorf("expected exactly 1 valid backup, got %d", len(backups))
	}
}

func TestBackupDirectoryCreationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(managedDir, "waf-test_com.conf")
	if err := os.WriteFile(sourcePath, []byte("content"), 0640); err != nil {
		t.Fatal(err)
	}

	// Create a regular file where the backup dir should be
	badBackupDir := filepath.Join(tmpDir, "file-not-dir")
	if err := os.WriteFile(badBackupDir, []byte("blocker"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", badBackupDir)

	if err := files.Backup("test.com", "waf"); err == nil {
		t.Error("Backup should fail when backup dir cannot be created, got nil")
	}
}

func TestBackupCopyFileFailure(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(managedDir, "waf-test_com.conf")
	if err := os.WriteFile(sourcePath, []byte("content"), 0640); err != nil {
		t.Fatal(err)
	}

	// Create domain backup dir then make it read-only so copyFile cannot create destination file
	domainBackupDir := filepath.Join(backupDir, "test_com")
	if err := os.MkdirAll(domainBackupDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(domainBackupDir, 0550); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(domainBackupDir, 0750) }()

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	if err := files.Backup("test.com", "waf"); err == nil {
		t.Error("Backup should fail when destination cannot be written, got nil")
	}
}

func TestRestoreBackupReadError(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	// Create domain dir with a directory named as a snapshot (EISDIR on ReadFile)
	domainSlugDir := filepath.Join(backupDir, "example_com")
	dirSnapshot := filepath.Join(domainSlugDir, "2026-01-01T00-00-00Z.waf.conf")
	if err := os.MkdirAll(dirSnapshot, 0750); err != nil {
		t.Fatal(err)
	}

	if err := files.RestoreBackup("example.com", "2026-01-01T00-00-00Z.waf.conf"); err == nil {
		t.Error("RestoreBackup should fail when snapshot is a directory, got nil")
	}
}

func TestBackupStatPermissionError(t *testing.T) {
	// Skip if running as root where 0000 perms don't prevent stat
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test as root")
	}
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "managed-unreadable")
	if err := os.MkdirAll(managedDir, 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(managedDir, 0750) }()

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.Backup("test.com", "waf"); err == nil {
		t.Error("Backup should fail when source path cannot be statted, got nil")
	}
}

func TestListBackupsReadDirError(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	// Create a regular file instead of domain dir
	domainSlugFile := filepath.Join(backupDir, "example_com")
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(domainSlugFile, []byte("file"), 0640); err != nil {
		t.Fatal(err)
	}

	if _, err := files.ListBackups("example.com"); err == nil {
		t.Error("ListBackups should fail when domain path is a file, got nil")
	}
}

func TestRestoreBackupAtomicWriteError(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_MANAGED_DIR", "/nonexistent-managed-dir-xyz")

	// Create valid snapshot
	domainSlugDir := filepath.Join(backupDir, "example_com")
	if err := os.MkdirAll(domainSlugDir, 0750); err != nil {
		t.Fatal(err)
	}
	snapshotFile := filepath.Join(domainSlugDir, "2026-09-01T12-00-00Z.waf.conf")
	if err := os.WriteFile(snapshotFile, []byte("data"), 0640); err != nil {
		t.Fatal(err)
	}

	if err := files.RestoreBackup("example.com", "2026-09-01T12-00-00Z.waf.conf"); err == nil {
		t.Error("RestoreBackup should fail when AtomicWrite fails, got nil")
	}
}

func TestEnforceRetentionErrors(t *testing.T) {
	// 1. Nonexistent directory
	if err := files.EnforceRetentionForTest("/nonexistent-dir-for-retention-test", "waf", 5); err == nil {
		t.Error("EnforceRetention on nonexistent dir expected error, got nil")
	}

	// 2. Directory where file cannot be removed
	if os.Geteuid() == 0 {
		return // skip if root
	}
	tmpDir := t.TempDir()
	retentionDir := filepath.Join(tmpDir, "retention-ro")
	if err := os.MkdirAll(retentionDir, 0750); err != nil {
		t.Fatal(err)
	}
	f1 := filepath.Join(retentionDir, "2026-01-01T00-00-00Z.waf.conf")
	f2 := filepath.Join(retentionDir, "2026-01-02T00-00-00Z.waf.conf")
	if err := os.WriteFile(f1, []byte("1"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("2"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(retentionDir, 0550); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(retentionDir, 0750) }()

	if err := files.EnforceRetentionForTest(retentionDir, "waf", 1); err == nil {
		t.Error("EnforceRetention should fail when file cannot be removed, got nil")
	}
}
