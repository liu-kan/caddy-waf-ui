// Package config centralizes environment-based configuration reads
// (convention D2): the variable names and their defaults live in a single
// place instead of being repeated per package (finding J5-3). The defaults
// are identical to the historical ones: /ui-managed, /backups,
// /data/logs/coraza-audit.log.
//
// Each helper deliberately re-reads the environment on EVERY call:
// configuration is read per request (decision D2), and tests change variables
// per test with t.Setenv. A sync.Once cache would freeze the first value read
// and break both contracts.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultManagedDir = "/ui-managed"
	defaultBackupDir  = "/backups"
	defaultBackupKeep = 10
	defaultAuditLog   = "/data/logs/coraza-audit.log"
	defaultCaddyfile  = "/etc/caddy/Caddyfile"
	defaultAdminURL   = "http://caddy:2019"
	defaultBindAddr   = "0.0.0.0:8080"
	defaultLogLevel   = "info"
	defaultIncludeDir = "/etc/caddy/ui-managed"
)

// envOr returns the value of the key variable, or fallback if it is empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ManagedDir returns CADDY_UI_MANAGED_DIR (default /ui-managed): the
// directory where the UI writes the managed overlays.
func ManagedDir() string {
	return envOr("CADDY_UI_MANAGED_DIR", defaultManagedDir)
}

// BackupDir returns CADDY_UI_BACKUP_DIR (default /backups): the root of the
// configuration snapshots.
func BackupDir() string {
	return envOr("CADDY_UI_BACKUP_DIR", defaultBackupDir)
}

// BackupKeep returns CADDY_UI_BACKUP_KEEP (default 10): the snapshot
// retention limit per domain and type.
func BackupKeep() int {
	if k, err := strconv.Atoi(os.Getenv("CADDY_UI_BACKUP_KEEP")); err == nil && k > 0 {
		return k
	}
	return defaultBackupKeep
}

// AuditLogPath returns CADDY_UI_AUDIT_LOG (default
// /data/logs/coraza-audit.log): the Coraza audit log read by the explorer.
func AuditLogPath() string {
	return envOr("CADDY_UI_AUDIT_LOG", defaultAuditLog)
}

// CaddyfilePath returns CADDY_UI_CADDYFILE (default /etc/caddy/Caddyfile):
// the Caddyfile sent to the Admin API on each reload.
func CaddyfilePath() string {
	return envOr("CADDY_UI_CADDYFILE", defaultCaddyfile)
}

// AdminURL returns CADDY_ADMIN_URL (default http://caddy:2019): Caddy's
// Admin API.
func AdminURL() string {
	return envOr("CADDY_ADMIN_URL", defaultAdminURL)
}

// IncludeDir returns CADDY_UI_INCLUDE_DIR (default /etc/caddy/ui-managed):
// Caddy's view of the overlays directory, used in the Include directive of
// the generated overlays (finding J5-1). It is independent of ManagedDir: the
// UI and Caddy mount the same volume at different points of each container's
// filesystem (INTEGRATION.md §3).
func IncludeDir() string {
	return envOr("CADDY_UI_INCLUDE_DIR", defaultIncludeDir)
}

// BindAddr returns CADDY_UI_BIND (default 0.0.0.0:8080): the listen address
// of the UI's HTTP server.
func BindAddr() string {
	return envOr("CADDY_UI_BIND", defaultBindAddr)
}

// LogLevel returns CADDY_UI_LOG_LEVEL (default "info"): the logger level.
func LogLevel() string {
	return envOr("CADDY_UI_LOG_LEVEL", defaultLogLevel)
}

// Token returns CADDY_UI_TOKEN (empty when unset: the session middleware
// blocks all access without a valid token, and the server refuses to start,
// see ValidateSecrets).
func Token() string {
	return os.Getenv("CADDY_UI_TOKEN")
}

// MinSecretLength is the minimum length of CADDY_UI_TOKEN and
// CADDY_UI_METRICS_TOKEN: `openssl rand -hex 32` produces 64 characters.
const MinSecretLength = 32

// ValidateSecrets rejects an access token that is missing, shorter than
// MinSecretLength, padded with whitespace or still the "replace-with..."
// placeholder of .env.example. The metrics token, when set, follows the
// same rules and must differ from the access token (Alloy holds it).
func ValidateSecrets() error {
	token := Token()
	if token == "" {
		return errors.New("CADDY_UI_TOKEN is not set: generate one with `openssl rand -hex 32`")
	}
	if err := validateSecret("CADDY_UI_TOKEN", token); err != nil {
		return err
	}
	metrics := MetricsToken()
	if metrics == "" {
		return nil
	}
	if err := validateSecret("CADDY_UI_METRICS_TOKEN", metrics); err != nil {
		return err
	}
	if metrics == token {
		return errors.New("CADDY_UI_METRICS_TOKEN must differ from CADDY_UI_TOKEN")
	}
	return nil
}

func validateSecret(name, value string) error {
	switch {
	case strings.TrimSpace(value) != value:
		return fmt.Errorf("%s has leading or trailing whitespace", name)
	case strings.HasPrefix(strings.ToLower(value), "replace-with"):
		return fmt.Errorf("%s is still the .env.example placeholder: generate one with `openssl rand -hex 32`", name)
	case len(value) < MinSecretLength:
		return fmt.Errorf("%s is too short (%d characters, minimum %d): generate one with `openssl rand -hex 32`", name, len(value), MinSecretLength)
	}
	return nil
}

// WAF baseline settings are operator-controlled, never HTTP payload fields.
func CRSMode() string { return envOr("CADDY_UI_CRS_MODE", "embedded") }
func CorazaConfig() string {
	if CRSMode() == "files" {
		return envOr("CADDY_UI_CORAZA_CONFIG", "/etc/caddy/coraza.conf")
	}
	return envOr("CADDY_UI_CORAZA_CONFIG", "@coraza.conf-recommended")
}
func CRSSetup() string {
	if CRSMode() == "files" {
		return envOr("CADDY_UI_CRS_SETUP", "/etc/caddy/owasp-crs/crs-setup.conf")
	}
	return envOr("CADDY_UI_CRS_SETUP", "@crs-setup.conf.example")
}
func CRSRules() string {
	if CRSMode() == "files" {
		return envOr("CADDY_UI_CRS_RULES", "/etc/caddy/owasp-crs/rules/*.conf")
	}
	return envOr("CADDY_UI_CRS_RULES", "@owasp_crs/*.conf")
}
func BeforeFile() string         { return os.Getenv("CADDY_UI_WAF_BEFORE_FILE") }
func AfterFile() string          { return os.Getenv("CADDY_UI_WAF_AFTER_FILE") }
func ResponseBodyAccess() string { return envOr("CADDY_UI_RESPONSE_BODY_ACCESS", "Off") }
func AuditLogParts() string      { return envOr("CADDY_UI_AUDIT_LOG_PARTS", "AHKZ") }

// DataDir returns CADDY_UI_DATA_DIR (default /ui-data): the UI's own
// persistent volume for normalized WAF events, the change journal, ingest
// cursors and long-term rollups. Alloy reads the shipped files from here.
func DataDir() string { return envOr("CADDY_UI_DATA_DIR", "/ui-data") }

// EventsRetentionDays returns CADDY_UI_EVENTS_RETENTION_DAYS (default 14,
// matching the Grafana Cloud free tier): daily event files older than this
// are deleted. Daily rollups are kept.
func EventsRetentionDays() int { return positiveIntEnv("CADDY_UI_EVENTS_RETENTION_DAYS", 14) }

// EventsMemoryMax returns CADDY_UI_EVENTS_MEMORY_MAX (default 1000): the
// number of recent events kept in memory for queries and impact estimates.
func EventsMemoryMax() int { return positiveIntEnv("CADDY_UI_EVENTS_MEMORY_MAX", 1000) }

// IngestInterval returns CADDY_UI_INGEST_INTERVAL (default 2s).
func IngestInterval() time.Duration { return durationEnv("CADDY_UI_INGEST_INTERVAL", 2*time.Second) }

// NodeName returns CADDY_UI_NODE (default: the host name), recorded on
// events so several Caddy nodes can share one Loki tenant.
func NodeName() string {
	if v := os.Getenv("CADDY_UI_NODE"); v != "" {
		return v
	}
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

// ActorHeader returns CADDY_UI_ACTOR_HEADER (default empty): a request
// header set by a trusted authenticating proxy (e.g. caddy-security) whose
// value is recorded as the actor of configuration changes. It only affects
// attribution, never authorization.
func ActorHeader() string { return os.Getenv("CADDY_UI_ACTOR_HEADER") }

// MetricsToken returns CADDY_UI_METRICS_TOKEN (default empty = /metrics
// disabled): the bearer token Alloy uses to scrape the WAF metrics.
func MetricsToken() string { return os.Getenv("CADDY_UI_METRICS_TOKEN") }

// CRSRulesDir returns CADDY_UI_CRS_RULES_DIR (default empty): an optional
// mounted ruleset directory parsed at startup to refresh the embedded rule
// dictionary when the backend runs a different CRS version.
func CRSRulesDir() string { return os.Getenv("CADDY_UI_CRS_RULES_DIR") }

// LokiURL returns CADDY_UI_LOKI_URL (default empty = Loki history disabled),
// e.g. https://logs-prod-012.grafana.net.
func LokiURL() string { return os.Getenv("CADDY_UI_LOKI_URL") }

// LokiUser returns CADDY_UI_LOKI_USER: the Grafana Cloud Loki user (tenant) id.
func LokiUser() string { return os.Getenv("CADDY_UI_LOKI_USER") }

// LokiToken returns CADDY_UI_LOKI_TOKEN: a Grafana Cloud access policy token
// limited to logs:read.
func LokiToken() string { return os.Getenv("CADDY_UI_LOKI_TOKEN") }

// LokiSelector returns CADDY_UI_LOKI_SELECTOR (default
// {job="caddy-waf-ui",kind="event"}): the stream selector of shipped events.
func LokiSelector() string {
	return envOr("CADDY_UI_LOKI_SELECTOR", `{job="caddy-waf-ui",kind="event"}`)
}

// LokiSyncInterval returns CADDY_UI_LOKI_SYNC_INTERVAL (default 0 =
// manual backfill only): periodic import of events shipped by other nodes.
func LokiSyncInterval() time.Duration { return durationEnv("CADDY_UI_LOKI_SYNC_INTERVAL", 0) }

// GrafanaExploreURL returns CADDY_UI_GRAFANA_URL (default empty): the
// Grafana stack URL used to link events to Explore.
func GrafanaExploreURL() string { return os.Getenv("CADDY_UI_GRAFANA_URL") }

// GrafanaLokiDatasource returns CADDY_UI_GRAFANA_LOKI_DATASOURCE (default
// grafanacloud-logs): the Loki data source uid used in Explore links.
func GrafanaLokiDatasource() string {
	return envOr("CADDY_UI_GRAFANA_LOKI_DATASOURCE", "grafanacloud-logs")
}

func positiveIntEnv(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil && v >= 0 {
		return v
	}
	return fallback
}

// MatchedValues is opt-in; credentials and unrecognized data remain hidden.
func MatchedValues() bool { return os.Getenv("CADDY_UI_MATCHED_VALUES") == "true" }

// EventsDiskMaxBytes bounds event storage without deleting unsent entries.
func EventsDiskMaxBytes() int64 {
	return int64(positiveIntEnv("CADDY_UI_EVENTS_DISK_MAX_MB", 128)) << 20
}

// ProbeURLs maps managed sites to operator-selected origin URLs.
func ProbeURLs() string { return os.Getenv("CADDY_UI_PROBE_URLS") }

// AuditRotateMB bounds raw files by rename and writer reopening.
func AuditRotateMB() int {
	if os.Getenv("CADDY_UI_AUDIT_ROTATE_MB") == "0" {
		return 0
	}
	return positiveIntEnv("CADDY_UI_AUDIT_ROTATE_MB", 32)
}

// RedactionLocal prefers explicit levels, with the legacy matched-values
// switch mapped to standard. Standalone default remains strict.
func RedactionLocal() string {
	if v, ok := os.LookupEnv("CADDY_UI_REDACTION_LOCAL"); ok {
		return v
	}
	if MatchedValues() {
		return "standard"
	}
	return "strict"
}
func RedactionCloud() string  { return envOr("CADDY_UI_REDACTION_CLOUD", "strict") }
func RedactionHide() []string { return redactionNames("CADDY_UI_REDACTION_HIDE") }
func RedactionKeep() []string { return redactionNames("CADDY_UI_REDACTION_KEEP") }
func redactionNames(key string) []string {
	return strings.FieldsFunc(os.Getenv(key), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}
func CloudDiskMaxBytes() int64 { return int64(positiveIntEnv("CADDY_UI_CLOUD_DISK_MAX_MB", 128)) << 20 }

// CloudExport reports whether a separately redacted copy of every event is
// queued for Alloy (CADDY_UI_CLOUD_EXPORT, default true). Deployments that
// never ship to Grafana Cloud can turn it off to save disk and CPU.
func CloudExport() bool { return os.Getenv("CADDY_UI_CLOUD_EXPORT") != "false" }

// IPGroupDir returns CADDY_UI_IPGROUP_DIR (default /ipgroups): the
// operator-mounted directory of file-based IP group sources.
func IPGroupDir() string { return envOr("CADDY_UI_IPGROUP_DIR", "/ipgroups") }

// IPGroupMaxPrefixes returns CADDY_UI_IPGROUP_MAX_PREFIXES (default
// 100000): the largest IP group list. Coraza compares the client address
// with every prefix of a list on each request that reaches a group rule,
// unless the backend image has the coraza-ipset plugin (binary search).
func IPGroupMaxPrefixes() int { return positiveIntEnv("CADDY_UI_IPGROUP_MAX_PREFIXES", 100000) }

// IPGroupProxy returns CADDY_UI_IPGROUP_PROXY (default empty: the
// HTTPS_PROXY/NO_PROXY environment): the proxy for IP group downloads only.
func IPGroupProxy() string { return os.Getenv("CADDY_UI_IPGROUP_PROXY") }

// AuditArchiveHours returns CADDY_UI_AUDIT_ARCHIVE_HOURS (default and
// minimum 48): how long rotated raw audit archives stay available for the
// on-demand local match context after their last write.
func AuditArchiveHours() int {
	return max(positiveIntEnv("CADDY_UI_AUDIT_ARCHIVE_HOURS", 48), 48)
}
