package files_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/files"
)

func TestRapidBackupsNeverOverwriteAnExistingSnapshot(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	backups := filepath.Join(root, "backups")
	if err := os.MkdirAll(managed, 0750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managed)
	t.Setenv("CADDY_UI_BACKUP_DIR", backups)
	path := files.ExclusionsConfigPath(managed, "example.com")
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, []byte{byte('a' + i)}, 0600); err != nil {
			t.Fatal(err)
		}
		if err := files.Backup("example.com", files.FileTypeExclusions); err != nil {
			t.Fatal(err)
		}
	}
	snapshots, err := files.ListBackups("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 3 {
		t.Fatalf("rapid updates overwrote snapshots: got %d", len(snapshots))
	}
	values := map[string]bool{}
	for _, snapshot := range snapshots {
		data, err := os.ReadFile(filepath.Join(backups, "example_com", snapshot.Timestamp+".exclusions.conf"))
		if err != nil {
			t.Fatal(err)
		}
		values[string(data)] = true
	}
	if !values["a"] || !values["b"] || !values["c"] {
		t.Fatal("snapshot contents were overwritten")
	}
}
