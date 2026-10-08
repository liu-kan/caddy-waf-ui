package ui

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/service"
)

// Runtime holds the long-lived components started by cmd/server: the event
// store and its ingester, the rule dictionary and the optional Loki client.
// Handlers degrade to honest empty states when it is not set (tests, or the
// event pipeline failed to start).
type Runtime struct {
	Store         *events.Store
	Ingester      *events.Ingester
	Dict          *crs.Dictionary
	Loki          *events.LokiClient
	CloudStore    *events.Store
	Redaction     events.RedactionSettings
	PipelineError string
}

func displayEvent(e *events.Event) *events.Event {
	if e == nil {
		return nil
	}
	return localRedaction().Apply(e)
}
func displayEvents(list []*events.Event) []*events.Event {
	out := make([]*events.Event, 0, len(list))
	for _, e := range list {
		out = append(out, displayEvent(e))
	}
	return out
}
func localRedaction() events.Redaction {
	if rt := currentRuntime(); rt != nil {
		return rt.Redaction.Local
	}
	if cfg, err := events.ReadRedactionSettings(); err == nil {
		return cfg.Local
	}
	return events.Redaction{Level: events.LevelStrict}
}

var runtimeRef atomic.Pointer[Runtime]

// SetRuntime installs the shared components.
func SetRuntime(r *Runtime) { runtimeRef.Store(r) }

func currentRuntime() *Runtime { return runtimeRef.Load() }

func dictionary() *crs.Dictionary {
	if r := currentRuntime(); r != nil && r.Dict != nil {
		return r.Dict
	}
	return crs.Default()
}

func eventStore() *events.Store {
	if r := currentRuntime(); r != nil {
		return r.Store
	}
	return nil
}

// actor builds the journal attribution of a request: the remote address
// and, when configured, the identity header of a trusted authenticating
// proxy. The reason comes from the form or JSON payload.
func actor(r *http.Request, reason string) service.Actor {
	a := service.Actor{RemoteIP: clientIP(r), Reason: truncateUTF8(strings.TrimSpace(reason), 500)}
	if h := config.ActorHeader(); h != "" {
		a.User = truncateUTF8(strings.TrimSpace(r.Header.Get(h)), 128)
	}
	return a
}

// truncateUTF8 cuts s to at most max bytes without splitting a character.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Time ranges offered by the event and analysis pages.
var ranges = []struct {
	Key   string
	Label string
	D     time.Duration
}{
	{"1h", "Last hour", time.Hour},
	{"24h", "Last 24 hours", 24 * time.Hour},
	{"7d", "Last 7 days", 7 * 24 * time.Hour},
	{"14d", "Last 14 days", 14 * 24 * time.Hour},
	{"30d", "Last 30 days", 30 * 24 * time.Hour},
}

// parseRange returns the range key and duration (default def).
func parseRange(key, def string) (string, time.Duration) {
	for _, r := range ranges {
		if r.Key == key {
			return r.Key, r.D
		}
	}
	for _, r := range ranges {
		if r.Key == def {
			return r.Key, r.D
		}
	}
	return "7d", 7 * 24 * time.Hour
}

// rangeOption is a select option.
type rangeOption struct {
	Key, Label string
	Selected   bool
}

func rangeOptions(selected string) []rangeOption {
	out := make([]rangeOption, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, rangeOption{Key: r.Key, Label: r.Label, Selected: r.Key == selected})
	}
	return out
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
