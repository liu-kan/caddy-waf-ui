package events

import (
	"fmt"
	"github.com/developmi/caddy-waf-ui/internal/config"
)

// RedactionSettings separates locally retained detail from cloud export.
type RedactionSettings struct {
	Local Redaction
	Cloud Redaction
}

func ReadRedactionSettings() (RedactionSettings, error) {
	var s RedactionSettings
	local, err := ParseLevel(config.RedactionLocal())
	if err != nil {
		return s, fmt.Errorf("CADDY_UI_REDACTION_LOCAL: %w", err)
	}
	cloud, err := ParseLevel(config.RedactionCloud())
	if err != nil {
		return s, fmt.Errorf("CADDY_UI_REDACTION_CLOUD: %w", err)
	}
	hide, keep := config.RedactionHide(), config.RedactionKeep()
	for _, list := range [][]string{hide, keep} {
		if len(list) > 64 {
			return s, fmt.Errorf("redaction name lists accept at most 64 entries")
		}
		for _, name := range list {
			if len(name) > 128 {
				return s, fmt.Errorf("redaction name exceeds 128 bytes")
			}
		}
	}
	s.Local = Redaction{Level: local, Hide: hide, Keep: keep}
	s.Cloud = Redaction{Level: Stricter(local, cloud), Hide: hide, Keep: keep}
	return s, nil
}
