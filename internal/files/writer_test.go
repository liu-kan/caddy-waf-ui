package files_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/files"
)

func TestAtomicWrite(t *testing.T) {
	// Create a temp directory for the test
	tmpDir, err := os.MkdirTemp("", "caddy-waf-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // Cleanup when done

	targetPath := filepath.Join(tmpDir, "test-config.conf")
	content := []byte("SecRuleEngine On")

	// Run the atomic write
	err = files.AtomicWrite(targetPath, content)
	if err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	// 1. Validate the final file exists and has the correct content
	readContent, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read the written file: %v", err)
	}
	if string(readContent) != string(content) {
		t.Errorf("written content = %q; expected %q", string(readContent), string(content))
	}

	// 2. Validate the unique temp file (.tmp-*) was renamed/removed
	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("failed listing temp files: %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("%d temp files left uncleaned: %v", len(leftovers), leftovers)
	}
}

func TestAtomicWriteFileMode(t *testing.T) {
	// The file mode is part of the deployment contract (amendment A, R4-006):
	// the overlays must be readable by Caddy, which runs as UID/GID 65532.
	tmpDir, err := os.MkdirTemp("", "caddy-waf-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // Cleanup when done

	targetPath := filepath.Join(tmpDir, "overlay.conf")

	// Run the atomic write
	err = files.AtomicWrite(targetPath, []byte("SecRuleEngine On"))
	if err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	// Validate the final file is world-readable (0640)
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("failed to stat the written file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0640 {
		t.Errorf("mode of the written file = %o; expected 0640", got)
	}
}

// TestAtomicWriteCleansTempOnError: if the rename fails (target is a
// directory), the unique temp file must be removed instead of left stale.
func TestAtomicWriteCleansTempOnError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy-waf-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // Cleanup when done

	// Point the target at an existing directory: CreateTemp and the write
	// work, but the rename fails (EISDIR) and the temp file must be cleaned
	// up.
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(targetDir, 0750); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	if err := files.AtomicWrite(targetDir, []byte("x")); err == nil {
		t.Fatal("AtomicWrite against a directory must fail")
	}

	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("failed listing temp files: %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("a failed write left %d stale temp files: %v", len(leftovers), leftovers)
	}
}

func TestAtomicWriteInvalidDirectory(t *testing.T) {
	err := files.AtomicWrite("/nonexistent-dir-test-xyz/test.conf", []byte("data"))
	if err == nil {
		t.Error("AtomicWrite in nonexistent directory should fail, got nil")
	}
}
