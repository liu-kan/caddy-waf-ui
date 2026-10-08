package domain_test

import (
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// TestOverlayHeaderRoundTripWAF: Header → ParseHeader must return the same
// fields for the 3-segment format (waf: with mode).
func TestOverlayHeaderRoundTripWAF(t *testing.T) {
	ts := time.Date(2026, 8, 7, 12, 30, 0, 0, time.UTC)
	header := domain.Header("api.example.com", domain.ModeOn, ts)

	want := "# domain: api.example.com | mode: On | updated: 2026-08-07T12:30:00Z"
	if header != want {
		t.Fatalf("Header() = %q; expected %q", header, want)
	}

	info, err := domain.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if info.Domain != "api.example.com" {
		t.Errorf("Domain = %q; expected api.example.com", info.Domain)
	}
	if !info.HasMode || info.Mode != domain.ModeOn {
		t.Errorf("Mode = %q (HasMode=%v); expected On", info.Mode, info.HasMode)
	}
	if !info.HasUpdated || !info.Updated.Equal(ts) {
		t.Errorf("Updated = %v (HasUpdated=%v); expected %v", info.Updated, info.HasUpdated, ts)
	}
}

// TestOverlayHeaderRoundTripNoMode: the 2-segment format (exclusions and
// ip-rules) round-trips without a mode and without degrading.
func TestOverlayHeaderRoundTripNoMode(t *testing.T) {
	// RFC3339 does not carry sub-seconds: a truncated timestamp is used so
	// the round-trip is exact.
	ts := time.Now().UTC().Truncate(time.Second)
	header := domain.Header("api.example.com", "", ts)

	info, err := domain.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if info.Domain != "api.example.com" {
		t.Errorf("Domain = %q; expected api.example.com", info.Domain)
	}
	if info.HasMode || info.Mode != "" {
		t.Errorf("Mode = %q (HasMode=%v); a header without mode must not carry a mode", info.Mode, info.HasMode)
	}
	if !info.HasUpdated || !info.Updated.Equal(ts) {
		t.Errorf("Updated = %v (HasUpdated=%v); expected %v", info.Updated, info.HasUpdated, ts)
	}
}

// TestParseHeaderTolerant: the parser keeps the tolerance of the historical
// scanner: irregular spacing, uppercase keys and unknown segments do not
// break parsing.
func TestParseHeaderTolerant(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantDomain  string
		wantMode    domain.WAFMode
		wantHasMode bool
	}{
		{"Espaciado irregular", "  # domain:  api.example.com  |  mode: Off  |  updated: 2026-08-07T12:30:00Z  ", "api.example.com", domain.ModeOff, true},
		{"Claves en mayusculas", "# domain: api.example.com | MODE: On | UPDATED: 2026-08-07T12:30:00Z", "api.example.com", domain.ModeOn, true},
		{"Segmento desconocido", "# domain: api.example.com | foo: bar | updated: 2026-08-07T12:30:00Z", "api.example.com", "", false},
		{"Sin updated", "# domain: api.example.com | mode: DetectionOnly", "api.example.com", domain.ModeDetectionOnly, true},
		{"Sin modo ni updated", "# domain: api.example.com", "api.example.com", "", false},
		{"Valor vacio en mode", "# domain: api.example.com | mode:", "api.example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := domain.ParseHeader(tt.line)
			if err != nil {
				t.Fatalf("ParseHeader failed: %v", err)
			}
			if info.Domain != tt.wantDomain {
				t.Errorf("Domain = %q; expected %q", info.Domain, tt.wantDomain)
			}
			if info.HasMode != tt.wantHasMode || info.Mode != tt.wantMode {
				t.Errorf("Mode = %q (HasMode=%v); expected %q (HasMode=%v)", info.Mode, info.HasMode, tt.wantMode, tt.wantHasMode)
			}
		})
	}
}

// TestParseHeaderErrors: explicit errors for headers without a prefix or
// without a domain (fail-loud, not silent).
func TestParseHeaderErrors(t *testing.T) {
	if _, err := domain.ParseHeader("domain: api.example.com | mode: On"); err == nil {
		t.Error("a line without the '# domain:' prefix must fail")
	}
	if _, err := domain.ParseHeader("# domain:   | mode: On"); err == nil {
		t.Error("a header with an empty domain must fail")
	}
}

// TestParseHeaderInvalidTimestamp: an unparseable "updated" is not a header
// error: it is flagged with HasUpdated=false and the raw value is kept
// available so the consumer can surface it (same behavior as the previous
// scanner).
func TestParseHeaderInvalidTimestamp(t *testing.T) {
	info, err := domain.ParseHeader("# domain: api.example.com | updated: no-es-una-fecha")
	if err != nil {
		t.Fatalf("an invalid timestamp must not break the header: %v", err)
	}
	if info.Domain != "api.example.com" {
		t.Errorf("Domain = %q; expected api.example.com", info.Domain)
	}
	if info.HasUpdated {
		t.Error("HasUpdated must be false with an invalid timestamp")
	}
	if info.UpdatedRaw != "no-es-una-fecha" {
		t.Errorf("UpdatedRaw = %q; expected the raw value", info.UpdatedRaw)
	}
}

func TestHeaderDomain(t *testing.T) {
	content := []byte("# Caddy WAF UI managed - do not edit manually\n" + domain.Header("a-b.example.com", domain.ModeOn, time.Now()) + "\nSecRuleEngine On\n")
	if got := domain.HeaderDomain(content); got != "a-b.example.com" {
		t.Fatalf("expected a-b.example.com, got %q", got)
	}
	if got := domain.HeaderDomain([]byte("# no header\n")); got != "" {
		t.Fatalf("expected no domain, got %q", got)
	}
}
