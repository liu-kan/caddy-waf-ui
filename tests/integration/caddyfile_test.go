package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleUsesManagedWAFBeforeProxyAndNoUnavailablePlugin(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	ip := strings.Index(text, "import /etc/caddy/ui-managed/ip-rules-localhost.conf")
	waf := strings.Index(text, "import /etc/caddy/ui-managed/waf-localhost.conf")
	proxy := strings.Index(text, "reverse_proxy example-app:80")
	if !strings.Contains(text, "route {") || ip < 0 || waf < ip || proxy < waf {
		t.Fatal("example must retain IP -> WAF -> proxy order")
	}
	if strings.Contains(text, "rate_limit") || strings.Contains(text, "Include /etc/caddy/coraza.conf") {
		t.Fatal("example requires modules or files absent from caddy-with-auth")
	}
}
