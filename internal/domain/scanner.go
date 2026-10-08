package domain

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Scanner reads the filesystem to discover domains[cite: 1].
// The in-memory registry was removed (finding J5-6): the abstraction was
// created and discarded per request without providing shared state; Scan
// returns the sites directly and freshness is kept by reading per request
// (decision D2).
type Scanner struct {
	managedDir string
}

// NewScanner creates a new scanner instance.
func NewScanner(managedDir string) *Scanner {
	return &Scanner{managedDir: managedDir}
}

// Scan reads the ui-managed directory and returns the sites found.
// Sites are registered with the REAL domain read from the overlay header
// ("# domain: | mode: | updated:", shared contract in overlay.go), not with
// the slug derived from the file name. Files without a valid header are
// skipped with a warning and the scan continues.
func (s *Scanner) Scan() ([]*Site, error) {
	entries, err := os.ReadDir(s.managedDir)
	if err != nil {
		if os.IsNotExist(err) {
			// If the directory does not exist, there is nothing to scan
			return nil, nil
		}
		return nil, err
	}

	sites := make([]*Site, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Look for files matching the waf-{slug}.conf pattern[cite: 1]
		if !strings.HasPrefix(name, "waf-") || !strings.HasSuffix(name, ".conf") {
			continue
		}

		site, err := parseSiteHeader(filepath.Join(s.managedDir, name), name)
		if err != nil {
			slog.Warn("overlay without a valid header, skipped", "file", name, "error", err)
			continue
		}

		sites = append(sites, site)
	}

	return sites, nil
}

// parseSiteHeader reads the "# domain: <domain> | mode: <mode> |
// updated: <RFC3339>" header of the overlay file and builds the Site.
// Returns an error if the header is missing or provides no domain: the file
// is skipped (skip + warn) but the scan is not aborted.
func parseSiteHeader(path, name string) (*Site, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading overlay: %w", err)
	}

	var headerLine string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, headerPrefix) {
			headerLine = trimmed
			break
		}
	}
	if headerLine == "" {
		return nil, fmt.Errorf("header '# domain:' not found")
	}

	info, err := ParseHeader(headerLine)
	if err != nil {
		return nil, err
	}

	site := &Site{
		Domain: info.Domain,
		Mode:   ModeDetectionOnly, // Default value when the header does not define a mode
	}

	// Mode present but unknown: the non-blocking default is kept (skipping
	// would hide the domain and break forward-compat with future modes), but
	// the Degraded flag warns that the UI does NOT reflect the real state
	// loaded in Caddy (W1 verify).
	if !info.HasMode {
		site.Mode = ModeDetectionOnly
	} else {
		switch info.Mode {
		case ModeOn, ModeOff, ModeDetectionOnly:
			site.Mode = info.Mode
		default:
			site.Degraded = true
			slog.Warn("unknown mode in header, using DetectionOnly (degraded site)", "file", name, "mode", info.Mode)
		}
	}

	if info.HasUpdated {
		site.Updated = info.Updated
	} else if info.UpdatedRaw != "" {
		slog.Warn("invalid 'updated' timestamp in header", "file", name, "updated", info.UpdatedRaw)
	}

	return site, nil
}
