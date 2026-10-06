package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/crs"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/events"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/ipgroups"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/metrics"
	"github.com/developmi/caddy-waf-ui/internal/ratelimit"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		sites := os.Args[2:]
		if len(sites) == 0 {
			sites = strings.Fields(strings.ReplaceAll(os.Getenv("CADDY_UI_SITES"), ",", " "))
		}
		if err := service.Initialize(sites); err != nil {
			slog.Error("failed to initialize overlays", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(serveUntilSignal); err != nil {
		slog.Error("failed to start the server", "error", err)
		os.Exit(1)
	}
}

// serveUntilSignal serves until SIGINT/SIGTERM, then drains connections.
func serveUntilSignal(srv *http.Server) error {
	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errs:
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// run wires configuration, logging, the WAF event pipeline and handlers,
// and delegates serving to the provided runner.
func run(serve func(*http.Server) error) error {
	// 1. Initialize the foundations: structured JSON logger to stdout (NIST AU-12)
	logs.Setup()

	// Invalid privacy configuration is fatal rather than silently exporting more detail.
	if _, err := events.ReadRedactionSettings(); err != nil {
		return err
	}

	// 2. IP groups before anything regenerates overlays (audit rotation).
	stopGroups := startIPGroups()
	defer stopGroups()

	// 3. Event pipeline: storage failures keep configuration pages working.
	stop := startPipeline()
	defer stop()

	// 4. Read the environment configuration for the listening port
	bindAddr := config.BindAddr()

	slog.Info("starting Caddy WAF UI", "bind", bindAddr)
	srv := newServer(bindAddr, buildHandler())
	return serve(srv)
}

// startIPGroups opens the IP group registry and starts the periodic import.
// A registry failure is not fatal: policies that use groups then fail to
// render, which the change journal reports.
func startIPGroups() func() {
	ipgroups.MaxPrefixes = config.IPGroupMaxPrefixes()
	reg, err := ipgroups.Open(ipgroups.Options{
		StateDir:  filepath.Join(config.DataDir(), "ipgroups"),
		ListDir:   filepath.Join(config.ManagedDir(), "ipgroups"),
		CaddyDir:  strings.TrimSuffix(config.IncludeDir(), "/") + "/ipgroups",
		SourceDir: config.IPGroupDir(),
		Proxy:     config.IPGroupProxy(),
	})
	if err != nil {
		slog.Error("IP groups disabled: could not read their state", "error", err)
		return func() {}
	}
	service.SetIPGroups(reg)
	ipGroupGauges.Do(registerIPGroupGauges)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); service.RunIPGroups(ctx, time.Minute) }()
	return func() {
		cancel()
		<-done
	}
}

// startPipeline opens the event store, starts the audit log ingester and
// the maintenance loops, and installs them for the UI. It returns the
// shutdown function.
func startPipeline() func() {
	settings, err := events.ReadRedactionSettings()
	if err != nil {
		slog.Error("invalid redaction configuration", "error", err)
		return func() {}
	}
	dict := crs.Default()
	if dir := config.CRSRulesDir(); dir != "" {
		if mounted, err := crs.LoadDir(dir); err != nil {
			slog.Warn("could not parse CADDY_UI_CRS_RULES_DIR, using the embedded rule dictionary", "dir", dir, "error", err)
		} else {
			dict = dict.Merge(mounted)
			slog.Info("rule dictionary refreshed from mounted rules", "dir", dir, "crs", dict.CRSVersion, "rules", dict.Len())
		}
	}
	for _, name := range []string{config.BeforeFile(), config.AfterFile()} {
		if name == "" {
			continue
		}
		mounted, err := crs.LoadFile(name)
		if err != nil {
			slog.Warn("could not parse custom rule dictionary", "file", name, "error", err)
			continue
		}
		dict = dict.Merge(mounted)
	}
	rt := &ui.Runtime{Dict: dict, Redaction: settings, Loki: &events.LokiClient{URL: config.LokiURL(), User: config.LokiUser(),
		Token: config.LokiToken(), Selector: config.LokiSelector()}}
	defer ui.SetRuntime(rt)

	retention := time.Duration(config.EventsRetentionDays()) * 24 * time.Hour
	store, err := events.OpenStore(filepath.Join(config.DataDir(), "events"), retention, config.EventsMemoryMax())
	if err != nil {
		slog.Error("WAF event store disabled: check CADDY_UI_DATA_DIR (a writable volume)", "dir", config.DataDir(), "error", err)
		return disabledPipeline(rt, err)
	}
	store.MaxDiskBytes = config.EventsDiskMaxBytes()
	store.OnAdd = countEvent
	rt.Store = store
	cloud, err := openExportQueue(store, settings, retention)
	if err != nil {
		return disabledPipeline(rt, err)
	}
	rt.CloudStore = cloud
	ingester := &events.Ingester{
		Path: config.AuditLogPath(), StatePath: filepath.Join(config.DataDir(), "state", "ingest.json"),
		Store: store, CloudStore: cloud, CloudRedaction: settings.Cloud,
		ArchiveRetention: time.Duration(config.AuditArchiveHours()) * time.Hour,
		Norm:             &events.Normalizer{Dict: dict, Node: config.NodeName(), Redaction: &settings.Local, SiteForHost: newSiteResolver().resolve},
	}
	rt.Ingester = ingester
	registerGauges(rt)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ingester.Run(ctx, config.IngestInterval()) }()
	stores := []*events.Store{store}
	if cloud != nil {
		stores = append(stores, cloud)
	}
	go func() { defer wg.Done(); maintain(ctx, stores...) }()
	if interval := config.LokiSyncInterval(); interval > 0 && rt.Loki.Configured() {
		wg.Add(1)
		go func() { defer wg.Done(); syncLoki(ctx, rt, interval) }()
	}
	return func() {
		cancel()
		wg.Wait()
		for _, s := range stores {
			if err := s.Rollups().Flush(); err != nil {
				slog.Warn("could not flush event rollups", "error", err)
			}
		}
	}
}

// openExportQueue opens the separately redacted queue that Alloy ships to
// Grafana Cloud and, on the first start with export enabled, fills it with
// the retained local events. It returns nil when CADDY_UI_CLOUD_EXPORT=false;
// turning export back on later queues the retained history again (the queue
// deduplicates, so nothing is sent twice).
func openExportQueue(store *events.Store, settings events.RedactionSettings, retention time.Duration) (*events.Store, error) {
	marker := filepath.Join(config.DataDir(), "cloud", "bootstrap.done")
	if !config.CloudExport() {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("could not reset export migration state", "error", err)
			return nil, err
		}
		slog.Info("cloud export disabled: no event copy is queued for Alloy")
		return nil, nil
	}
	cloud, err := events.OpenStore(filepath.Join(config.DataDir(), "cloud", "events"), retention, 1)
	if err != nil {
		slog.Error("WAF export queue unavailable", "error", err)
		return nil, err
	}
	cloud.MaxDiskBytes = config.CloudDiskMaxBytes()
	if err := cloud.Prune(time.Now().UTC()); err != nil {
		slog.Error("could not prune export queue", "error", err)
		return nil, err
	}
	if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
		if err := store.ExportRetained(cloud, settings.Cloud); err != nil {
			slog.Error("pending event migration failed; ingestion disabled until corrected and restarted", "error", err)
			return nil, err
		}
		if err := files.AtomicWrite(marker, []byte(time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
			slog.Error("could not save export migration state", "error", err)
			return nil, err
		}
	} else if err != nil {
		slog.Error("could not read export migration state", "error", err)
		return nil, err
	}
	return cloud, nil
}

func disabledPipeline(rt *ui.Runtime, err error) func() {
	rt.PipelineError = err.Error()
	return func() {}
}

// countEvent feeds the WAF metrics from newly ingested events.
func countEvent(e *events.Event) {
	metrics.Events.Inc(e.Site, e.Action)
	seen := map[int]bool{}
	for _, h := range e.Hits {
		if seen[h.ID] || h.Kind == crs.KindDecision {
			continue
		}
		seen[h.ID] = true
		metrics.RuleHits.Inc(e.Site, strconv.Itoa(h.ID), e.Action)
	}
}

// maintain flushes rollups every 30 seconds and prunes expired events
// hourly.
func maintain(ctx context.Context, stores ...*events.Store) {
	flush := time.NewTicker(30 * time.Second)
	prune := time.NewTicker(time.Hour)
	defer flush.Stop()
	defer prune.Stop()
	for _, store := range stores {
		if err := store.Prune(time.Now().UTC()); err != nil {
			slog.Warn("could not prune expired events", "error", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			if err := service.RotateAudit(int64(config.AuditRotateMB()) << 20); err != nil {
				slog.Warn("audit rotation failed", "error", err)
			}
			for _, store := range stores {
				if err := store.Rollups().Flush(); err != nil {
					slog.Warn("could not flush event rollups", "error", err)
				}
			}
		case <-prune.C:
			for _, store := range stores {
				if err := store.Prune(time.Now().UTC()); err != nil {
					slog.Warn("could not prune expired events", "error", err)
				}
			}
		}
	}
}

// syncLoki periodically imports events shipped by other nodes.
func syncLoki(ctx context.Context, rt *ui.Runtime, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := time.Now().UTC().Add(-24 * time.Hour)
	for {
		end := time.Now().UTC().Add(-time.Minute)
		qctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		res, err := events.Backfill(qctx, rt.Loki, rt.Store, last, end)
		cancel()
		if err != nil {
			slog.Warn("Loki sync failed", "error", err, "imported", res.Imported)
		} else {
			if res.Imported > 0 {
				slog.Info("Loki sync imported events", "imported", res.Imported)
			}
			last = end.Add(-24 * time.Hour) // overlap: late lines are deduplicated
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// siteResolver maps a Host to a managed site domain (exact or wildcard),
// for audit records written by overlays without a UI signature.
type siteResolver struct {
	mu      sync.Mutex
	sites   []string
	scanned time.Time
}

func newSiteResolver() *siteResolver { return &siteResolver{} }

func (s *siteResolver) resolve(host string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.scanned) > 30*time.Second {
		s.sites = s.sites[:0]
		if list, err := domain.NewScanner(config.ManagedDir()).Scan(); err == nil {
			for _, site := range list {
				s.sites = append(s.sites, site.Domain)
			}
		}
		s.scanned = time.Now()
	}
	host = strings.ToLower(host)
	for _, site := range s.sites {
		if strings.EqualFold(site, host) {
			return site
		}
	}
	for _, site := range s.sites {
		if suffix, ok := strings.CutPrefix(site, "*."); ok && strings.HasSuffix(host, "."+strings.ToLower(suffix)) {
			return site
		}
	}
	return ""
}

var gaugesOnce sync.Once

// registerGauges exposes pipeline and policy state at scrape time.
var ipGroupGauges sync.Once

// registerIPGroupGauges exports the state of every IP group: list size,
// last check, failed imports and updates waiting for approval.
func registerIPGroupGauges() {
	sample := func(value func(ipgroups.Group) float64) func() []metrics.Sample {
		return func() []metrics.Sample {
			reg := service.IPGroups()
			if reg == nil {
				return nil
			}
			var out []metrics.Sample
			for _, g := range reg.Groups() {
				out = append(out, metrics.Sample{Labels: []string{g.Name}, Value: value(g)})
			}
			return out
		}
	}
	flag := func(on bool) float64 {
		if on {
			return 1
		}
		return 0
	}
	metrics.Default.NewGaugeFunc("waf_ipgroup_prefixes", "Prefixes of the active list of each IP group.", []string{"group"},
		sample(func(g ipgroups.Group) float64 {
			if g.Active == nil {
				return 0
			}
			return float64(g.Active.Prefixes)
		}))
	metrics.Default.NewGaugeFunc("waf_ipgroup_checked_timestamp_seconds", "Last import check of each IP group (Unix time).", []string{"group"},
		sample(func(g ipgroups.Group) float64 { return float64(g.Checked.Unix()) }))
	metrics.Default.NewGaugeFunc("waf_ipgroup_error", "1 when the last import of an IP group failed.", []string{"group"},
		sample(func(g ipgroups.Group) float64 { return flag(g.Error != "") }))
	metrics.Default.NewGaugeFunc("waf_ipgroup_pending", "1 when an IP group update waits for approval.", []string{"group"},
		sample(func(g ipgroups.Group) float64 { return flag(g.Pending != nil) }))
}

func registerGauges(rt *ui.Runtime) {
	gaugesOnce.Do(func() { registerGaugesOnce(rt) })
}

func registerGaugesOnce(rt *ui.Runtime) {
	metrics.Default.NewGaugeFunc("waf_ingest_lag_bytes", "Audit log bytes not ingested yet.", nil, func() []metrics.Sample {
		st := rt.Ingester.Status()
		return []metrics.Sample{{Value: float64(st.Size - st.Offset)}}
	})
	metrics.Default.NewGaugeFunc("waf_ingest_last_poll_timestamp_seconds", "Last audit log poll (Unix time).", nil, func() []metrics.Sample {
		return []metrics.Sample{{Value: float64(rt.Ingester.Status().LastPoll.Unix())}}
	})
	metrics.Default.NewGaugeFunc("waf_events_in_memory", "Events held in memory for queries.", nil, func() []metrics.Sample {
		return []metrics.Sample{{Value: float64(rt.Store.Stats().Count)}}
	})
	metrics.Default.NewGaugeFunc("waf_policy_info", "Configured WAF mode and CRS policy per managed site (value 1).",
		[]string{"site", "mode", "blocking_pl", "detection_pl", "tuning"}, func() []metrics.Sample {
			sites, err := domain.NewScanner(config.ManagedDir()).Scan()
			if err != nil {
				return nil
			}
			var out []metrics.Sample
			for _, site := range sites {
				state, err := service.ReadSiteState(site.Domain)
				if err != nil {
					continue
				}
				out = append(out, metrics.Sample{Labels: []string{site.Domain, string(state.Mode),
					strconv.Itoa(state.Policy.BlockingPL), strconv.Itoa(state.Policy.DetectionPL),
					strconv.FormatBool(state.Policy.Tuning)}, Value: 1})
			}
			return out
		})
}

// buildHandler configures and returns the application's root HTTP handler
// with all route groups, middlewares, and security headers applied.
func buildHandler() http.Handler {
	public := ui.NewLoginMux()
	pages := auth.Session(logs.RequestLogger(auth.CSRF(ui.NewPagesMux())))
	api := ratelimit.API(auth.Middleware(logs.RequestLogger(ui.NewRouter())))

	mux := http.NewServeMux()
	mux.Handle("/login", ratelimit.Login(public))
	mux.Handle("/static/", http.StripPrefix("/static/", ui.StaticHandler()))
	mux.Handle("/", pages)
	mux.Handle("/api/", api)
	mux.Handle("/health", ui.HealthHandler())
	// Scraped by Alloy with CADDY_UI_METRICS_TOKEN; 404 while unset.
	mux.Handle("/metrics", ratelimit.API(metrics.Handler(metrics.Default, config.MetricsToken)))

	return ui.SecurityHeaders(mux)
}

// newServer builds the *http.Server with the SH-1 hardening limits:
//   - ReadHeaderTimeout 5s: cap for the header read (mitigates slowloris,
//     G114; the previous value is kept).
//   - WriteTimeout 30s: covers the Caddy admin chain (2 x 10s) with margin.
//   - IdleTimeout 60s: margin over the container healthcheck (30s).
//   - MaxHeaderBytes 1 MiB: size cap of the headers per request.
//
// The helper does NOT assemble muxes: it receives the already assembled
// handler (with ui.SecurityHeaders wrapping the mux) and the listening
// address; the route assembly lives in main().
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
