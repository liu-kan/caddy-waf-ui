package ipgroups

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/files"
)

// Group sources.
const (
	SourceFile = "file" // a file in the operator-mounted source directory
	SourceURL  = "url"  // an HTTPS URL downloaded periodically
)

// Refresh limits of URL groups and the retry delay after a failure.
const (
	DefaultRefresh = 24 * time.Hour
	MinRefresh     = time.Hour
	MaxRefresh     = 30 * 24 * time.Hour
	retryAfter     = 15 * time.Minute
)

var (
	// maxSourceBytes bounds a downloaded or read source file.
	maxSourceBytes int64 = 32 << 20

	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	filePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	notePattern = regexp.MustCompile("^[^\\x00-\\x1f\\x7f`]{0,200}$")

	// ErrNotFound is returned for an unknown group.
	ErrNotFound = errors.New("IP group not found")
)

// Definition is the operator configuration of a group.
type Definition struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// File is a file name in the source directory (CADDY_UI_IPGROUP_DIR).
	File string `json:"file,omitempty"`
	// URL is an HTTPS URL; Refresh (Go duration, default 24h, 1h-720h) sets
	// how often it is downloaded. File sources are checked every minute.
	URL     string `json:"url,omitempty"`
	Refresh string `json:"refresh,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Version is one imported list, stored as a CIDR file named after its
// content hash so overlays referencing older lists keep working.
type Version struct {
	SHA256   string    `json:"sha256"`
	File     string    `json:"file"`
	Prefixes int       `json:"prefixes"`
	IPv4     int       `json:"ipv4"`
	IPv6     int       `json:"ipv6"`
	Format   string    `json:"format"`
	Skipped  int       `json:"skipped,omitempty"`
	Imported time.Time `json:"imported"`
}

// Group is a definition with its import state.
type Group struct {
	Definition
	Active *Version `json:"active,omitempty"`
	// Pending is a downloaded update held for approval (Hold says why).
	Pending  *Version  `json:"pending,omitempty"`
	Hold     string    `json:"hold,omitempty"`
	Checked  time.Time `json:"checked,omitempty"`
	Error    string    `json:"error,omitempty"`
	ETag     string    `json:"etag,omitempty"`
	Modified string    `json:"last_modified,omitempty"`
	// Stamp is the size and modification time of the last read source file.
	Stamp string `json:"stamp,omitempty"`
}

func (g Group) refreshEvery() time.Duration {
	d, err := time.ParseDuration(g.Refresh)
	if err != nil || d <= 0 {
		return DefaultRefresh
	}
	return d
}

// Options locates the registry state and lists.
type Options struct {
	StateDir  string // UI data: groups.json
	ListDir   string // lists written by the UI (managed volume)
	CaddyDir  string // the same directory as Caddy sees it
	SourceDir string // operator-mounted source files
	// Proxy is an http(s) proxy URL for downloads; empty uses the
	// HTTPS_PROXY/NO_PROXY environment.
	Proxy  string
	Client *http.Client
	Now    func() time.Time
}

// Registry holds the groups. It is safe for concurrent use; imports are
// serialized.
type Registry struct {
	opts   Options
	client *http.Client

	// imports serializes downloads and list writes; mu guards the state.
	imports sync.Mutex
	mu      sync.Mutex
	groups  map[string]*Group
	sets    map[string]*Set
}

// Open loads the registry and the active list of every group.
func Open(opts Options) (*Registry, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	client, err := httpClient(opts.Client, opts.Proxy)
	if err != nil {
		return nil, err
	}
	r := &Registry{opts: opts, client: client, groups: map[string]*Group{}, sets: map[string]*Set{}}
	data, err := os.ReadFile(r.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var state struct {
		Groups []*Group `json:"groups"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read %s: %w", r.statePath(), err)
	}
	for _, g := range state.Groups {
		r.groups[g.Name] = g
		if g.Active == nil {
			continue
		}
		set, err := r.readList(g.Active.File)
		if err != nil {
			// Keep the definition; the next import rewrites the list.
			slog.Warn("IP group list unavailable", "group", g.Name, "file", g.Active.File, "error", err)
			g.Error = "active list unavailable: " + err.Error()
			g.Stamp, g.ETag, g.Modified = "", "", ""
			continue
		}
		r.sets[g.Name] = set
	}
	return r, nil
}

// httpClient enforces HTTPS on redirects, bounds the request time and
// applies the download proxy.
func httpClient(base *http.Client, proxy string) (*http.Client, error) {
	c := &http.Client{Timeout: 60 * time.Second}
	if base != nil {
		copied := *base
		c = &copied
		if c.Timeout == 0 {
			c.Timeout = 60 * time.Second
		}
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid IP group proxy %q: use http(s)://host:port", proxy)
		}
		var tr *http.Transport
		if t, ok := c.Transport.(*http.Transport); ok {
			tr = t.Clone()
		} else {
			tr = http.DefaultTransport.(*http.Transport).Clone()
		}
		tr.Proxy = http.ProxyURL(u)
		c.Transport = tr
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirects must stay on https")
		}
		return nil
	}
	return c, nil
}

func (r *Registry) statePath() string { return filepath.Join(r.opts.StateDir, "groups.json") }

func (r *Registry) readList(name string) (*Set, error) {
	data, err := os.ReadFile(filepath.Join(r.opts.ListDir, filepath.Base(name)))
	if err != nil {
		return nil, err
	}
	var b Builder
	if err := parseText(data, &b); err != nil {
		return nil, err
	}
	return b.Set(), nil
}

// Groups returns copies of all groups, by name.
func (r *Registry) Groups() []Group {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Group, 0, len(r.groups))
	for _, g := range r.groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a copy of one group.
func (r *Registry) Get(name string) (Group, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.groups[name]
	if !ok {
		return Group{}, false
	}
	return *g, true
}

// Validate checks a definition and fills its defaults.
func Validate(d Definition) (Definition, error) {
	d.Name = strings.TrimSpace(d.Name)
	d.Note = strings.TrimSpace(d.Note)
	if !namePattern.MatchString(d.Name) {
		return d, fmt.Errorf("invalid group name %q: use 1-32 lowercase letters, digits, '-' or '_'", d.Name)
	}
	if !notePattern.MatchString(d.Note) {
		return d, errors.New("invalid note: at most 200 printable characters")
	}
	switch d.Source {
	case SourceFile:
		d.File = strings.TrimSpace(d.File)
		if !filePattern.MatchString(d.File) || strings.Contains(d.File, "..") {
			return d, fmt.Errorf("invalid file name %q: use a file name inside the IP group directory", d.File)
		}
		d.URL, d.Refresh = "", ""
	case SourceURL:
		d.URL = strings.TrimSpace(d.URL)
		u, err := url.Parse(d.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(d.URL) > 2048 {
			return d, errors.New("invalid URL: use an https:// URL")
		}
		if u.User != nil {
			return d, errors.New("invalid URL: credentials in the URL are not allowed")
		}
		u.Fragment, u.RawFragment = "", ""
		d.URL, d.File = u.String(), ""
		if d.Refresh == "" {
			d.Refresh = DefaultRefresh.String()
		}
		every, err := time.ParseDuration(d.Refresh)
		if err != nil || every < MinRefresh || every > MaxRefresh {
			return d, fmt.Errorf("invalid refresh interval %q: use %s to %s", d.Refresh, MinRefresh, MaxRefresh)
		}
		d.Refresh = every.String()
	default:
		return d, fmt.Errorf("invalid source %q: use file or url", d.Source)
	}
	return d, nil
}

// Put creates or updates a group and imports its list immediately. A
// definition is kept even when the first import fails; the error is
// reported on the group and the import is retried later. It reports whether
// the active list changed.
func (r *Registry) Put(ctx context.Context, d Definition) (Group, error) {
	d, err := Validate(d)
	if err != nil {
		return Group{}, err
	}
	r.mu.Lock()
	g, exists := r.groups[d.Name]
	if !exists {
		g = &Group{}
		r.groups[d.Name] = g
	}
	sourceChanged := g.Source != d.Source || g.File != d.File || g.URL != d.URL
	g.Definition = d
	if sourceChanged {
		g.Stamp, g.ETag, g.Modified, g.Pending, g.Hold = "", "", "", nil, ""
	}
	err = r.saveLocked()
	r.mu.Unlock()
	if err != nil {
		return Group{}, err
	}
	if sourceChanged || g.Active == nil {
		if _, err := r.Refresh(ctx, d.Name, true); err != nil {
			slog.Warn("IP group import failed", "group", d.Name, "error", err)
		}
	}
	got, _ := r.Get(d.Name)
	return got, nil
}

// Delete removes a group. Callers check that no policy uses it; its list
// files are removed by GC once no overlay references them.
func (r *Registry) Delete(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.groups[name]; !ok {
		return ErrNotFound
	}
	delete(r.groups, name)
	delete(r.sets, name)
	return r.saveLocked()
}

// Refresh imports a group's source. force ignores the change detection
// (file size/mtime, ETag/Last-Modified). It reports whether the active
// list changed. A list that lost more than half of its prefixes is held
// as Pending until approved; an empty or invalid list never replaces the
// active one.
func (r *Registry) Refresh(ctx context.Context, name string, force bool) (bool, error) {
	r.imports.Lock()
	defer r.imports.Unlock()
	r.mu.Lock()
	g, ok := r.groups[name]
	if !ok {
		r.mu.Unlock()
		return false, ErrNotFound
	}
	def, stamp, etag, modified := g.Definition, g.Stamp, g.ETag, g.Modified
	r.mu.Unlock()
	if force {
		stamp, etag, modified = "", "", ""
	}

	data, src, err := r.fetch(ctx, def, stamp, etag, modified)
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok = r.groups[name]
	if !ok || g.Definition != def {
		return false, errors.New("the group changed during the import")
	}
	g.Checked = r.opts.Now().UTC()
	if err != nil {
		g.Error = err.Error()
		return false, errors.Join(err, r.saveLocked())
	}
	if data == nil {
		// Not modified since the last import.
		g.Error = ""
		return false, r.saveLocked()
	}
	parsed, err := Parse(data)
	if err != nil {
		g.Error = err.Error()
		return false, errors.Join(err, r.saveLocked())
	}
	g.Stamp, g.ETag, g.Modified, g.Error = src.stamp, src.etag, src.modified, ""
	v, content := newVersion(name, parsed)
	v.Imported = g.Checked
	switch {
	case g.Active != nil && v.SHA256 == g.Active.SHA256 && r.sets[name] != nil:
		g.Pending, g.Hold = nil, ""
		return false, r.saveLocked()
	case g.Pending != nil && v.SHA256 == g.Pending.SHA256:
		return false, r.saveLocked()
	}
	if err := r.writeList(v, content); err != nil {
		g.Error = err.Error()
		return false, errors.Join(err, r.saveLocked())
	}
	if g.Active != nil && g.Active.Prefixes >= 20 && v.Prefixes*2 < g.Active.Prefixes {
		g.Pending = &v
		g.Hold = fmt.Sprintf("the list shrank from %d to %d prefixes; approve it to use it", g.Active.Prefixes, v.Prefixes)
		return false, r.saveLocked()
	}
	g.Active, g.Pending, g.Hold = &v, nil, ""
	r.sets[name] = parsed.Set
	return true, r.saveLocked()
}

// Approve activates a held update.
func (r *Registry) Approve(name string) (bool, error) {
	r.imports.Lock()
	defer r.imports.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.groups[name]
	if !ok {
		return false, ErrNotFound
	}
	if g.Pending == nil {
		return false, errors.New("no pending update")
	}
	set, err := r.readList(g.Pending.File)
	if err != nil {
		return false, err
	}
	g.Active, g.Pending, g.Hold = g.Pending, nil, ""
	r.sets[name] = set
	return true, r.saveLocked()
}

// Discard drops a held update; the same content is held again only when
// the source changes.
func (r *Registry) Discard(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.groups[name]
	if !ok {
		return ErrNotFound
	}
	g.Pending, g.Hold = nil, ""
	return r.saveLocked()
}

// Due returns the groups to check now: file groups every time (a cheap
// size/mtime check), URL groups after their interval or retry delay.
func (r *Registry) Due(now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for name, g := range r.groups {
		every := g.refreshEvery()
		if g.Error != "" && retryAfter < every {
			every = retryAfter
		}
		if g.Source == SourceFile || g.Checked.IsZero() || now.Sub(g.Checked) >= every {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ActiveFiles maps each group with an active list to the list path that
// Caddy reads.
func (r *Registry) ActiveFiles() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for name, g := range r.groups {
		if g.Active != nil && r.sets[name] != nil {
			out[name] = strings.TrimSuffix(r.opts.CaddyDir, "/") + "/" + g.Active.File
		}
	}
	return out
}

// Digest identifies the active lists: reviewed drafts that render group
// rules become stale when it changes.
func (r *Registry) Digest() string {
	files := r.ActiveFiles()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		_, _ = fmt.Fprintf(h, "%s=%s\n", name, files[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Contains reports whether the active list of a group holds addr.
func (r *Registry) Contains(name string, addr netip.Addr) bool {
	r.mu.Lock()
	set := r.sets[name]
	r.mu.Unlock()
	return set.Contains(addr)
}

// Lookup returns the groups whose active list holds addr.
func (r *Registry) Lookup(addr netip.Addr) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for name, set := range r.sets {
		if set.Contains(addr) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// GC removes list files that are neither active nor pending, are not in
// referenced (file names used by current overlays) and are older than
// minAge.
func (r *Registry) GC(referenced map[string]bool, minAge time.Duration) error {
	r.mu.Lock()
	keep := map[string]bool{}
	for _, g := range r.groups {
		for _, v := range []*Version{g.Active, g.Pending} {
			if v != nil {
				keep[v.File] = true
			}
		}
	}
	r.mu.Unlock()
	entries, err := os.ReadDir(r.opts.ListDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	now := r.opts.Now()
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".txt") || keep[name] || referenced[name] {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < minAge {
			continue
		}
		if err := os.Remove(filepath.Join(r.opts.ListDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *Registry) saveLocked() error {
	list := make([]*Group, 0, len(r.groups))
	for _, g := range r.groups {
		list = append(list, g)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	data, err := json.MarshalIndent(struct {
		Groups []*Group `json:"groups"`
	}{list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.opts.StateDir, 0o750); err != nil {
		return err
	}
	return files.AtomicWrite(r.statePath(), data)
}

// newVersion renders the canonical list of a parsed source.
func newVersion(name string, p Parsed) (Version, []byte) {
	var body strings.Builder
	v := Version{Format: p.Format, Skipped: p.Skipped}
	for _, prefix := range p.Set.Prefixes() {
		body.WriteString(prefix.String())
		body.WriteByte('\n')
		v.Prefixes++
		if prefix.Addr().Is4() {
			v.IPv4++
		} else {
			v.IPv6++
		}
	}
	sum := sha256.Sum256([]byte(body.String()))
	v.SHA256 = hex.EncodeToString(sum[:])
	v.File = name + "." + v.SHA256[:12] + ".txt"
	header := fmt.Sprintf("# caddy-waf-ui IP group %s: %d prefixes (%d IPv4, %d IPv6), sha256 %s\n",
		name, v.Prefixes, v.IPv4, v.IPv6, v.SHA256)
	return v, []byte(header + body.String())
}

func (r *Registry) writeList(v Version, content []byte) error {
	if err := os.MkdirAll(r.opts.ListDir, 0o750); err != nil {
		return err
	}
	return files.AtomicWrite(filepath.Join(r.opts.ListDir, v.File), content)
}

// source describes what was read, for change detection.
type source struct{ stamp, etag, modified string }

// fetch reads a group source. It returns nil data when the source did not
// change since the last import.
func (r *Registry) fetch(ctx context.Context, d Definition, stamp, etag, modified string) ([]byte, source, error) {
	if d.Source == SourceFile {
		return r.readSource(d.File, stamp)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, source{}, err
	}
	req.Header.Set("User-Agent", "caddy-waf-ui-ipgroups/1")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if modified != "" {
		req.Header.Set("If-Modified-Since", modified)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, source{}, fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, source{}, nil
	case http.StatusOK:
	default:
		return nil, source{}, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes+1))
	if err != nil {
		return nil, source{}, fmt.Errorf("download failed: %w", err)
	}
	if int64(len(data)) > maxSourceBytes {
		return nil, source{}, fmt.Errorf("the download is larger than %d bytes", maxSourceBytes)
	}
	return data, source{etag: resp.Header.Get("ETag"), modified: resp.Header.Get("Last-Modified")}, nil
}

func (r *Registry) readSource(name, stamp string) ([]byte, source, error) {
	if r.opts.SourceDir == "" {
		return nil, source{}, errors.New("no IP group directory is configured (CADDY_UI_IPGROUP_DIR)")
	}
	path := filepath.Join(r.opts.SourceDir, filepath.Base(name))
	info, err := os.Stat(path)
	if err != nil {
		return nil, source{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, source{}, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > maxSourceBytes {
		return nil, source{}, fmt.Errorf("%s is larger than %d bytes", name, maxSourceBytes)
	}
	now := strconv.FormatInt(info.Size(), 10) + "@" + info.ModTime().UTC().Format(time.RFC3339Nano)
	if now == stamp {
		return nil, source{}, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: validated file name inside the operator-mounted IP group directory.
	if err != nil {
		return nil, source{}, err
	}
	return data, source{stamp: now}, nil
}
