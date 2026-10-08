package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
)

var rotationMu sync.Mutex

// RotateAudit renames the old file instead of truncating a live writer.
// Reapplying each managed overlay opens new writers. The ingester continues
// following archives, including late records written by old transactions.
func RotateAudit(maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	rotationMu.Lock()
	defer rotationMu.Unlock()
	path := config.AuditLogPath()
	marker := filepath.Join(config.DataDir(), "audit-reopen.pending")
	_, pendingErr := os.Stat(marker)
	pending := pendingErr == nil
	if !pending {
		fi, err := os.Stat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Size() < maxBytes {
			return nil
		}
		if err := os.MkdirAll(config.DataDir(), 0o750); err != nil {
			return err
		}
		// A crash after the marker or rename is recovered by retrying the reopen.
		if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o600); err != nil {
			return err
		}
		archive := path + ".rotated-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if err := os.Rename(path, archive); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640) //nolint:gosec // G304: operator-configured audit file, shared UID 65532.
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	sites, err := domain.NewScanner(config.ManagedDir()).Scan()
	if err != nil {
		return err
	}
	if len(sites) == 0 {
		return fmt.Errorf("audit rotation needs at least one UI-managed WAF overlay")
	}
	for _, site := range sites {
		state, err := ReadSiteState(site.Domain)
		if err != nil {
			return err
		}
		if !state.HasWAF {
			continue
		}
		// Republish the state stored under the change lock: a mode read here
		// could be stale by the time the lock is free.
		err = reapplySite(Actor{User: "audit-maintenance", Reason: "reopen rotated audit log"}, site.Domain, chainOpts{
			failEvent:       "audit_reopen_failed",
			reloadFailEvent: "audit_reopen_reload_failed",
			successEvent:    "audit_reopened",
			action:          "maintenance",
			summary:         "republished to reopen the rotated audit log",
		})
		if err != nil {
			return err
		}
	}
	return os.Remove(marker)
}
