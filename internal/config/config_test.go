package config_test

import (
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

func TestConfigDefaults(t *testing.T) {
	// Ensure relevant environment variables are unset for testing defaults
	keys := []string{
		"CADDY_UI_MANAGED_DIR",
		"CADDY_UI_BACKUP_DIR",
		"CADDY_UI_BACKUP_KEEP",
		"CADDY_UI_AUDIT_LOG",
		"CADDY_UI_CADDYFILE",
		"CADDY_ADMIN_URL",
		"CADDY_UI_INCLUDE_DIR",
		"CADDY_UI_BIND",
		"CADDY_UI_LOG_LEVEL",
		"CADDY_UI_TOKEN",
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"ManagedDir", config.ManagedDir(), "/ui-managed"},
		{"BackupDir", config.BackupDir(), "/backups"},
		{"AuditLogPath", config.AuditLogPath(), "/data/logs/coraza-audit.log"},
		{"CaddyfilePath", config.CaddyfilePath(), "/etc/caddy/Caddyfile"},
		{"AdminURL", config.AdminURL(), "http://caddy:2019"},
		{"IncludeDir", config.IncludeDir(), "/etc/caddy/ui-managed"},
		{"BindAddr", config.BindAddr(), "0.0.0.0:8080"},
		{"LogLevel", config.LogLevel(), "info"},
		{"Token", config.Token(), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s default = %q, expected %q", tt.name, tt.got, tt.expected)
			}
		})
	}

	if keep := config.BackupKeep(); keep != 10 {
		t.Errorf("BackupKeep default = %d, expected 10", keep)
	}
}

func TestConfigOverrides(t *testing.T) {
	t.Setenv("CADDY_UI_MANAGED_DIR", "/custom/managed")
	t.Setenv("CADDY_UI_BACKUP_DIR", "/custom/backups")
	t.Setenv("CADDY_UI_BACKUP_KEEP", "25")
	t.Setenv("CADDY_UI_AUDIT_LOG", "/custom/audit.log")
	t.Setenv("CADDY_UI_CADDYFILE", "/custom/Caddyfile")
	t.Setenv("CADDY_ADMIN_URL", "http://localhost:2019")
	t.Setenv("CADDY_UI_INCLUDE_DIR", "/custom/include")
	t.Setenv("CADDY_UI_BIND", "127.0.0.1:9090")
	t.Setenv("CADDY_UI_LOG_LEVEL", "debug")
	t.Setenv("CADDY_UI_TOKEN", "supersecret")

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"ManagedDir", config.ManagedDir(), "/custom/managed"},
		{"BackupDir", config.BackupDir(), "/custom/backups"},
		{"AuditLogPath", config.AuditLogPath(), "/custom/audit.log"},
		{"CaddyfilePath", config.CaddyfilePath(), "/custom/Caddyfile"},
		{"AdminURL", config.AdminURL(), "http://localhost:2019"},
		{"IncludeDir", config.IncludeDir(), "/custom/include"},
		{"BindAddr", config.BindAddr(), "127.0.0.1:9090"},
		{"LogLevel", config.LogLevel(), "debug"},
		{"Token", config.Token(), "supersecret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s override = %q, expected %q", tt.name, tt.got, tt.expected)
			}
		})
	}

	if keep := config.BackupKeep(); keep != 25 {
		t.Errorf("BackupKeep override = %d, expected 25", keep)
	}
}

func TestBackupKeepInvalidValues(t *testing.T) {
	invalidCases := []string{"invalid", "-5", "0"}
	for _, val := range invalidCases {
		t.Run(val, func(t *testing.T) {
			t.Setenv("CADDY_UI_BACKUP_KEEP", val)
			if keep := config.BackupKeep(); keep != 10 {
				t.Errorf("BackupKeep for %q = %d, expected default 10", val, keep)
			}
		})
	}
}

func TestArchiveRetentionAndCloudExport(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_ARCHIVE_HOURS", "")
	t.Setenv("CADDY_UI_CLOUD_EXPORT", "")
	if config.AuditArchiveHours() != 48 || !config.CloudExport() {
		t.Fatalf("defaults: %d hours, export %v", config.AuditArchiveHours(), config.CloudExport())
	}
	t.Setenv("CADDY_UI_AUDIT_ARCHIVE_HOURS", "12")
	if config.AuditArchiveHours() != 48 {
		t.Fatal("archives must be kept at least 48 hours for late records")
	}
	t.Setenv("CADDY_UI_AUDIT_ARCHIVE_HOURS", "336")
	t.Setenv("CADDY_UI_CLOUD_EXPORT", "false")
	if config.AuditArchiveHours() != 336 || config.CloudExport() {
		t.Fatalf("overrides: %d hours, export %v", config.AuditArchiveHours(), config.CloudExport())
	}
}
