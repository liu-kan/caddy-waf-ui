package service

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

// ErrInvalidDomain signals a domain name that does not meet the strict
// hostname format (finding J2: Caddyfile directive injection and backup path
// traversal). REST handlers translate it to 400 Bad Request, same sentinel
// pattern as ErrInvalidMode and files.ErrInvalidBackup.
var ErrInvalidDomain = errors.New("invalid domain")

// ErrSlugConflict refuses a domain whose overlay files already belong to
// another domain (REST handlers translate it to 409 Conflict).
var ErrSlugConflict = errors.New("another managed domain uses the same configuration file names")

// maxDomainLength is the upper bound of a hostname/FQDN without the trailing
// dot (RFC 1035: 255 bytes with separators → 253 characters of labels).
const maxDomainLength = 253

// maxLabelLength is the per-label limit of a hostname (RFC 1035).
const maxLabelLength = 63

// ValidateDomain validates a domain as a strict hostname/FQDN: only
// [a-zA-Z0-9.-], no consecutive double dots, no leading/trailing dots, and
// with each label meeting [a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])? (1..63
// characters, alphanumeric or hyphens, without starting or ending with a
// hyphen). It rejects everything else (slashes, whitespace, control chars,
// %0A, quotes, braces, $, @, "..", etc.) with a descriptive error.
//
// It is the PRIMARY defense against directive injection in the "# domain:"
// header of the overlays and against backup path traversal: it is invoked at
// the public chain entries (UpdateWAFMode, UpdateExclusions, UpdateIPRules,
// Rollback) BEFORE any use of the domain in paths, templates or backups.
// DomainSlug (internal/domain/slug.go) remains as an additional sanitization
// layer (defense in depth).
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("%w: the domain is empty", ErrInvalidDomain)
	}
	if len(domain) > maxDomainLength {
		return fmt.Errorf("%w: %q exceeds the maximum of %d characters", ErrInvalidDomain, domain, maxDomainLength)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("%w: %q cannot start or end with a dot", ErrInvalidDomain, domain)
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("%w: %q contains two consecutive dots", ErrInvalidDomain, domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if err := validateLabel(label); err != nil {
			return fmt.Errorf("%w: %q: %v", ErrInvalidDomain, domain, err)
		}
	}
	return nil
}

// validateLabel verifies a single hostname label: 1..63 characters, only
// alphanumerics and hyphens, without leading or trailing hyphens. It returns
// the detail without the sentinel (ValidateDomain wraps it with context).
func validateLabel(label string) error {
	if len(label) == 0 || len(label) > maxLabelLength {
		return fmt.Errorf("label length out of range (1..%d)", maxLabelLength)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("labels cannot start or end with a hyphen")
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("character %q not allowed (only [a-zA-Z0-9.-])", c)
		}
	}
	return nil
}

// checkSlugOwner refuses a domain whose overlay files belong to another
// domain. DomainSlug maps "." and "-" to "_" (a file-name contract the
// operator's Caddyfile imports rely on), so a-b.example.com and
// a.b.example.com share file names; the header of each overlay records its
// real domain. Letter case is not a conflict (DNS names are case-insensitive).
// Unreadable files are left to the chain, which reports and audits them.
func checkSlugOwner(domainName string) error {
	dir := config.ManagedDir()
	slug := domain.DomainSlug(domainName)
	for _, path := range []string{
		files.WAFConfigPath(dir, domainName),
		files.ExclusionsConfigPath(dir, domainName),
		files.IPRulesConfigPath(dir, domainName),
	} {
		content, err := os.ReadFile(path) //nolint:gosec // G304: path built from a validated domain slug.
		if err != nil {
			continue
		}
		owner := domain.HeaderDomain(content)
		if owner != "" && !strings.EqualFold(owner, domainName) && domain.DomainSlug(owner) == slug {
			return fmt.Errorf("%w: %s and %s both map to %s", ErrSlugConflict, domainName, owner, slug)
		}
	}
	return nil
}
