// Package metrics exposes WAF counters in the Prometheus text format
// (stdlib only). Coraza Caddy publishes no WAF metrics, so the UI derives
// them while it ingests the audit log; Alloy scrapes /metrics and forwards
// them to Grafana Cloud.
package metrics

import (
	"crypto/subtle"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Sample is one labelled value of a gauge collected at scrape time.
type Sample struct {
	Labels []string
	Value  float64
}

type collector interface {
	write(w io.Writer) error
}

// CounterVec is a monotonically increasing counter with labels.
type CounterVec struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	values     map[string]*series
}

type series struct {
	labels []string
	value  float64
}

// GaugeFunc computes its samples when scraped.
type GaugeFunc struct {
	name, help string
	labels     []string
	collect    func() []Sample
}

// Registry holds the collectors in registration order.
type Registry struct {
	mu         sync.Mutex
	collectors []collector
}

// Default is the process registry.
var Default = &Registry{}

// NewCounterVec registers a counter vector.
func (r *Registry) NewCounterVec(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{name: name, help: help, labels: labels, values: map[string]*series{}}
	r.register(c)
	return c
}

// NewGaugeFunc registers a gauge computed at scrape time.
func (r *Registry) NewGaugeFunc(name, help string, labels []string, collect func() []Sample) *GaugeFunc {
	g := &GaugeFunc{name: name, help: help, labels: labels, collect: collect}
	r.register(g)
	return g
}

func (r *Registry) register(c collector) {
	r.mu.Lock()
	r.collectors = append(r.collectors, c)
	r.mu.Unlock()
}

// Add increases the series identified by labelValues by v (v >= 0).
func (c *CounterVec) Add(v float64, labelValues ...string) {
	if v < 0 || len(labelValues) != len(c.labels) {
		return
	}
	key := strings.Join(labelValues, "\xff")
	c.mu.Lock()
	s, ok := c.values[key]
	if !ok {
		s = &series{labels: append([]string(nil), labelValues...)}
		c.values[key] = s
	}
	s.value += v
	c.mu.Unlock()
}

// Inc adds 1.
func (c *CounterVec) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Value returns the current value of one series (tests).
func (c *CounterVec) Value(labelValues ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.values[strings.Join(labelValues, "\xff")]; ok {
		return s.value
	}
	return 0
}

func (c *CounterVec) write(w io.Writer) error {
	c.mu.Lock()
	list := make([]series, 0, len(c.values))
	for _, s := range c.values {
		list = append(list, *s)
	}
	c.mu.Unlock()
	sortSeries(list)
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name); err != nil {
		return err
	}
	for _, s := range list {
		if err := writeSample(w, c.name, c.labels, s.labels, s.value); err != nil {
			return err
		}
	}
	return nil
}

func (g *GaugeFunc) write(w io.Writer) error {
	samples := g.collect()
	list := make([]series, 0, len(samples))
	for _, s := range samples {
		if len(s.Labels) == len(g.labels) {
			list = append(list, series{labels: s.Labels, value: s.Value})
		}
	}
	sortSeries(list)
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name); err != nil {
		return err
	}
	for _, s := range list {
		if err := writeSample(w, g.name, g.labels, s.labels, s.value); err != nil {
			return err
		}
	}
	return nil
}

func sortSeries(list []series) {
	sort.Slice(list, func(i, j int) bool {
		return strings.Join(list[i].labels, "\xff") < strings.Join(list[j].labels, "\xff")
	})
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func writeSample(w io.Writer, name string, names, values []string, v float64) error {
	var b strings.Builder
	b.WriteString(name)
	if len(names) > 0 {
		b.WriteByte('{')
		for i, n := range names {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(n)
			b.WriteString(`="`)
			b.WriteString(labelEscaper.Replace(values[i]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatValue(v))
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Render writes every collector in the text exposition format.
func (r *Registry) Render(w io.Writer) error {
	r.mu.Lock()
	collectors := append([]collector(nil), r.collectors...)
	r.mu.Unlock()
	for _, c := range collectors {
		if err := c.write(w); err != nil {
			return err
		}
	}
	return nil
}

// Handler serves the registry to scrapers presenting token as a bearer
// token. An empty token disables the endpoint (404) so metrics are never
// public by accident.
func Handler(r *Registry, token func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		expected := token()
		if expected == "" {
			http.NotFound(w, req)
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.Render(w)
	})
}

// WAF metrics shared by the ingester and the service layer.
var (
	Events = Default.NewCounterVec("waf_events_total",
		"WAF audit events ingested, by site and action (blocked, would_block, detected).", "site", "action")
	RuleHits = Default.NewCounterVec("waf_rule_hits_total",
		"Rule matches in ingested WAF events, by site, rule id and event action.", "site", "rule_id", "action")
	Reloads = Default.NewCounterVec("waf_reload_total",
		"Configuration changes sent to Caddy, by result (success, failed).", "result")
	IngestErrors = Default.NewCounterVec("waf_ingest_errors_total",
		"Audit log ingestion problems, by kind (parse, read, store).", "kind")
)
