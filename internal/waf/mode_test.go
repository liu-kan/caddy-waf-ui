package waf_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// auditDirectives are the audit directives that the inline overlay must keep
// (S2): they are verified present and in order inside the block.
// defaultAuditPath is the default value of CADDY_UI_AUDIT_LOG - the tests
// pass the path explicitly (pure signature GenerateSnippet(site, auditPath,
// includeDir), invariant M4: the overlay and the reader share the same path).
// defaultIncludeDir is the default value of CADDY_UI_INCLUDE_DIR (the Caddy
// view of the overlays directory, finding J5-1).
const (
	defaultAuditPath  = "/data/logs/coraza-audit.log"
	defaultIncludeDir = "/etc/caddy/ui-managed"
)

var auditDirectives = []string{
	"SecAuditEngine RelevantOnly",
	"SecAuditLog " + defaultAuditPath,
	"SecAuditLogFormat JSON",
	"SecAuditLogParts AHKZ",
}

// assertInlineOverlay verifies the R1 contract of the inline overlay (S1,
// S2): top-level coraza_waf block without a snippet wrapper, 3-segment header
// preserved (scanner contract), exclusions Include inside the block and audit
// directives preserved and in order.
func assertInlineOverlay(t *testing.T, result, headerPrefix, slug, mode string) {
	t.Helper()

	// S1: the coraza_waf block must be at root level (column 0), not nested
	// in a named snippet.
	topLevel := false
	for _, line := range strings.Split(result, "\n") {
		if line == "coraza_waf {" {
			topLevel = true
			break
		}
	}
	if !topLevel {
		t.Errorf("the overlay does not contain a top-level coraza_waf block (exact line \"coraza_waf {\"):\n%s", result)
	}

	// S1: the snippet wrapper (waf_{slug}) { is forbidden.
	if strings.Contains(result, "(waf_"+slug+") {") {
		t.Errorf("the overlay must not declare the snippet (waf_%s) {:\n%s", slug, result)
	}

	// Structural order: header, WAF, compiled exclusions, engine and audit.
	order := []string{
		headerPrefix,
		"coraza_waf {",
		"# ui-config-exclusions-begin",
		"SecRuleEngine " + mode,
	}
	order = append(order, auditDirectives...)

	prev := -1
	prevFragment := "<start>"
	for _, fragment := range order {
		idx := strings.Index(result, fragment)
		if idx < 0 {
			t.Errorf("the inline overlay does not contain the expected fragment: %q\nOverlay:\n%s", fragment, result)
			continue
		}
		if idx < prev {
			t.Errorf("fragment %q out of order (appears before %q)", fragment, prevFragment)
		}
		prev = idx
		prevFragment = fragment
	}

	// S2: the block closes after the audit directives.
	if closeIdx := strings.LastIndex(result, "}"); closeIdx < prev {
		t.Errorf("the coraza_waf block must close after the audit directives:\n%s", result)
	}
}

func TestGenerateSnippetInline(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	resultBytes, err := waf.GenerateSnippet(site, defaultAuditPath, defaultIncludeDir)
	if err != nil {
		t.Fatalf("GenerateSnippet failed unexpectedly: %v", err)
	}

	result := string(resultBytes)

	// S1 + S2: 3-segment header preserved (scanner contract).
	assertInlineOverlay(t, result,
		"# domain: api.developmi.com | mode: DetectionOnly | updated: ",
		"api_developmi_com", "DetectionOnly")
}

// TestGenerateSnippetHonorsAuditPath verifies the M4 invariant: the
// SecAuditLog path in the overlay is the one the caller passes
// (logs.AuditLogPath(), which honors CADDY_UI_AUDIT_LOG), not a hardcoded
// value.
func TestGenerateSnippetHonorsAuditPath(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	customPath := "/var/log/waf/custom-audit.log"
	resultBytes, err := waf.GenerateSnippet(site, customPath, defaultIncludeDir)
	if err != nil {
		t.Fatalf("GenerateSnippet failed unexpectedly: %v", err)
	}

	result := string(resultBytes)
	if !strings.Contains(result, "SecAuditLog "+customPath) {
		t.Errorf("the overlay must contain SecAuditLog %q (invariant M4, CADDY_UI_AUDIT_LOG):\n%s", customPath, result)
	}
	if strings.Contains(result, "SecAuditLog /data/logs/coraza-audit.log") {
		t.Errorf("the overlay must not contain the hardcoded path when the caller passes another one:\n%s", result)
	}
}

// TestGenerateSnippetHonorsIncludeDir verifies finding J5-1: the exclusions
// Include directive of the overlay must reference the include directory that
// the caller passes (config.IncludeDir(), CADDY_UI_INCLUDE_DIR) - the CADDY
// view of the volume, NOT a hardcoded value. A deployment with custom dirs
// stops breaking silently.
func TestGenerateSnippetNeedsNoExternalExclusionsFile(t *testing.T) {
	site := &domain.Site{Domain: "api.example.com", Mode: domain.ModeDetectionOnly}
	snippet, err := waf.GenerateSnippet(site, defaultAuditPath, "/custom/managed")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snippet), "Include /custom/managed") {
		t.Fatal("new overlays must not depend on a missing exclusions file")
	}
}

func TestGenerateSnippetInlineOnMode(t *testing.T) {
	site := &domain.Site{
		Domain: "app.example.org",
		Mode:   domain.ModeOn,
	}

	resultBytes, err := waf.GenerateSnippet(site, defaultAuditPath, defaultIncludeDir)
	if err != nil {
		t.Fatalf("GenerateSnippet failed unexpectedly: %v", err)
	}

	result := string(resultBytes)

	// Triangulation: another domain and On mode - the template must render
	// the real values of the site, not a fixed output.
	assertInlineOverlay(t, result,
		"# domain: app.example.org | mode: On | updated: ",
		"app_example_org", "On")
}
