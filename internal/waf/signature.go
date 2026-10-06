package waf

import (
	"fmt"
	"strconv"
	"strings"
)

// Signature identifies the configuration a Coraza WAF instance was built
// from. The generator writes it with SecComponentSignature; Coraza copies the
// component names into every audit record (producer.rulesets with part H and
// messages[].actionset with part K), so each event names its site, policy and
// revision without any correlation by time.
type Signature struct {
	Site          string
	Revision      string
	Mode          string
	BlockingPL    int
	DetectionPL   int
	Inbound       int
	Outbound      int
	Tuning        bool
	EarlyBlocking bool
}

const signaturePrefix = "caddy-waf-ui;v=1;"

// String renders the single-token signature (no spaces: actionset joins
// component names with spaces).
func (s Signature) String() string {
	tune := "0"
	if s.Tuning {
		tune = "1"
	}
	early := "0"
	if s.EarlyBlocking {
		early = "1"
	}
	return fmt.Sprintf("%ssite=%s;rev=%s;mode=%s;bpl=%d;dpl=%d;in=%d;out=%d;tune=%s;early=%s",
		signaturePrefix, s.Site, s.Revision, s.Mode, s.BlockingPL, s.DetectionPL, s.Inbound, s.Outbound, tune, early)
}

// ParseSignature parses one component name.
func ParseSignature(name string) (Signature, bool) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, signaturePrefix) {
		return Signature{}, false
	}
	var s Signature
	for _, field := range strings.Split(strings.TrimPrefix(name, signaturePrefix), ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		n, _ := strconv.Atoi(value)
		switch key {
		case "site":
			s.Site = value
		case "rev":
			s.Revision = value
		case "mode":
			s.Mode = value
		case "bpl":
			s.BlockingPL = n
		case "dpl":
			s.DetectionPL = n
		case "in":
			s.Inbound = n
		case "out":
			s.Outbound = n
		case "early":
			s.EarlyBlocking = value == "1"
		case "tune":
			s.Tuning = value == "1"
		}
	}
	return s, s.Site != ""
}

// FindSignature looks for the signature in the rulesets list first, then in
// space-separated actionset strings.
func FindSignature(rulesets []string, actionsets ...string) (Signature, bool) {
	for _, name := range rulesets {
		if s, ok := ParseSignature(name); ok {
			return s, true
		}
	}
	for _, set := range actionsets {
		for _, name := range strings.Fields(set) {
			if s, ok := ParseSignature(name); ok {
				return s, true
			}
		}
	}
	return Signature{}, false
}
