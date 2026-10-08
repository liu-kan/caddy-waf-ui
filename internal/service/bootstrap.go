package service

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// Initialize creates a working DetectionOnly baseline for new managed sites.
// Existing WAF rules, exclusions, and IP lists are never overwritten. Empty
// comment-only placeholders from older releases are safe to initialize.
func Initialize(sites []string) error {
	changeMu.Lock()
	defer changeMu.Unlock()
	if len(sites) == 0 {
		return fmt.Errorf("set CADDY_UI_SITES or pass site names to init")
	}
	for _, site := range sites {
		if err := ValidateDomain(site); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(config.ManagedDir(), 0750); err != nil {
		return err
	}
	for _, site := range sites {
		if err := checkSlugOwner(site); err != nil {
			return err
		}
		exclusionsPath := files.ExclusionsConfigPath(config.ManagedDir(), site)
		exclusions, err := waf.GenerateExclusions(&domain.Site{Domain: site}, nil)
		if err != nil {
			return err
		}
		if err := initializeFile(exclusionsPath, exclusions); err != nil {
			return err
		}
		ips, err := iprules.GenerateSnippet(&domain.Site{Domain: site}, iprules.IPRules{})
		if err != nil {
			return err
		}
		if err := initializeFile(files.IPRulesConfigPath(config.ManagedDir(), site), ips); err != nil {
			return err
		}
		path := files.WAFConfigPath(config.ManagedDir(), site)
		content, _, err := readPreviousState(path)
		if err != nil {
			return err
		}
		if commentOnly(content) {
			mode := domain.ModeDetectionOnly
			if _, err := writeSiteWAF(site, wafOverride{mode: &mode}); err != nil {
				return err
			}
		}
	}
	return verifyImports()
}

func initializeFile(path string, content []byte) error {
	_, exists, err := readPreviousState(path)
	if err != nil || exists {
		return err
	}
	return files.AtomicWrite(path, content)
}

func commentOnly(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return false
		}
	}
	return true
}

var managedImport = regexp.MustCompile(`(?m)^\s*import\s+(\S+/(?:waf|ip-rules)-[A-Za-z0-9_]+\.conf)\s*(?:#.*)?$`)

func verifyImports() error {
	source, err := os.ReadFile(config.CaddyfilePath())
	if err != nil {
		return fmt.Errorf("read initialization Caddyfile: %w", err)
	}
	for _, match := range managedImport.FindAllSubmatch(source, -1) {
		path := string(match[1])
		if filepath.Dir(path) != config.IncludeDir() {
			continue
		}
		localPath := filepath.Join(config.ManagedDir(), filepath.Base(path))
		if _, err := os.Stat(localPath); err != nil {
			return fmt.Errorf("missing managed import %s: add its domain to CADDY_UI_SITES: %w", path, err)
		}
	}
	return nil
}
