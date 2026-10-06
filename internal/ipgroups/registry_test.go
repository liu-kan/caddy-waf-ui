package ipgroups

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testEnv struct {
	opts   Options
	now    time.Time
	source string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	root := t.TempDir()
	env := &testEnv{now: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), source: filepath.Join(root, "sources")}
	if err := os.MkdirAll(env.source, 0o750); err != nil {
		t.Fatal(err)
	}
	env.opts = Options{StateDir: filepath.Join(root, "ui-data", "ipgroups"), ListDir: filepath.Join(root, "managed", "ipgroups"),
		CaddyDir: "/etc/caddy/ui-managed/ipgroups", SourceDir: env.source, Now: func() time.Time { return env.now }}
	return env
}

func (env *testEnv) open(t *testing.T) *Registry {
	t.Helper()
	r, err := Open(env.opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (env *testEnv) writeSource(t *testing.T, name, content string) {
	t.Helper()
	path := filepath.Join(env.source, name)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	// Make the change visible to size/mtime detection even within a second.
	env.now = env.now.Add(time.Minute)
	if err := os.Chtimes(path, env.now, env.now); err != nil {
		t.Fatal(err)
	}
}

func cidrLines(n int, second byte) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24\n", second, i*2)
	}
	return b.String()
}

func TestFileGroupImportChangeAndPersistence(t *testing.T) {
	env := newTestEnv(t)
	env.writeSource(t, "office.txt", "192.0.2.0/24\n")
	r := env.open(t)
	g, err := r.Put(context.Background(), Definition{Name: "office", Source: SourceFile, File: "office.txt", Note: "HQ"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Active == nil || g.Active.Prefixes != 1 || g.Active.Format != FormatText || g.Error != "" {
		t.Fatalf("imported group: %+v", g)
	}
	list, err := os.ReadFile(filepath.Join(env.opts.ListDir, g.Active.File))
	if err != nil || !strings.Contains(string(list), "\n192.0.2.0/24\n") {
		t.Fatalf("list file: %q %v", list, err)
	}
	if !strings.HasPrefix(g.Active.File, "office.") || r.ActiveFiles()["office"] != env.opts.CaddyDir+"/"+g.Active.File {
		t.Fatalf("active file mapping: %v", r.ActiveFiles())
	}
	if got := r.Lookup(netip.MustParseAddr("192.0.2.9")); !reflect.DeepEqual(got, []string{"office"}) {
		t.Fatalf("lookup: %v", got)
	}
	if changed, err := r.Refresh(context.Background(), "office", false); changed || err != nil {
		t.Fatalf("an unchanged source must not produce a new version: %v %v", changed, err)
	}
	first := g.Active.File
	env.writeSource(t, "office.txt", "192.0.2.0/24\n198.51.100.0/24\n")
	if changed, err := r.Refresh(context.Background(), "office", false); !changed || err != nil {
		t.Fatalf("a changed source must produce a new version: %v %v", changed, err)
	}
	g, _ = r.Get("office")
	if g.Active.Prefixes != 2 || g.Active.File == first {
		t.Fatalf("new version: %+v", g.Active)
	}
	digest := r.Digest()
	reopened := env.open(t)
	if g2, ok := reopened.Get("office"); !ok || g2.Active.File != g.Active.File || g2.Note != "HQ" {
		t.Fatalf("state must survive a restart: %+v", g2)
	}
	if !reopened.Contains("office", netip.MustParseAddr("198.51.100.1")) || reopened.Digest() != digest {
		t.Fatal("active sets and digest must be reloaded from the list files")
	}
}

func TestShrinkingListsWaitForApproval(t *testing.T) {
	env := newTestEnv(t)
	env.writeSource(t, "cn.txt", cidrLines(100, 1))
	r := env.open(t)
	if _, err := r.Put(context.Background(), Definition{Name: "cn", Source: SourceFile, File: "cn.txt"}); err != nil {
		t.Fatal(err)
	}
	env.writeSource(t, "cn.txt", cidrLines(30, 1))
	if changed, err := r.Refresh(context.Background(), "cn", false); changed || err != nil {
		t.Fatalf("a list that lost most prefixes must be held: %v %v", changed, err)
	}
	g, _ := r.Get("cn")
	if g.Active.Prefixes != 100 || g.Pending == nil || g.Pending.Prefixes != 30 || !strings.Contains(g.Hold, "100") {
		t.Fatalf("held update: %+v", g)
	}
	if changed, err := r.Approve("cn"); !changed || err != nil {
		t.Fatalf("approve: %v %v", changed, err)
	}
	if g, _ = r.Get("cn"); g.Active.Prefixes != 30 || g.Pending != nil || g.Hold != "" {
		t.Fatalf("approved: %+v", g)
	}
	env.writeSource(t, "cn.txt", cidrLines(10, 1))
	if _, err := r.Refresh(context.Background(), "cn", false); err != nil {
		t.Fatal(err)
	}
	if err := r.Discard("cn"); err != nil {
		t.Fatal(err)
	}
	if g, _ = r.Get("cn"); g.Active.Prefixes != 30 || g.Pending != nil {
		t.Fatalf("discarded: %+v", g)
	}
	env.writeSource(t, "cn.txt", "# nothing left\n")
	if _, err := r.Refresh(context.Background(), "cn", false); err == nil {
		t.Fatal("an empty list must never replace the active one")
	}
	if g, _ = r.Get("cn"); g.Active.Prefixes != 30 || g.Error == "" {
		t.Fatalf("failed refresh keeps the active list and reports the error: %+v", g)
	}
}

func TestURLGroupsUseHTTPSAndConditionalRequests(t *testing.T) {
	srs, err := os.ReadFile(filepath.Join("testdata", "ip.srs"))
	if err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	body.Store(srs)
	var conditional atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		etag := fmt.Sprintf(`"%d"`, len(body.Load().([]byte)))
		if req.Header.Get("If-None-Match") == etag {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer srv.Close()
	env := newTestEnv(t)
	env.opts.Client = srv.Client()
	r := env.open(t)
	g, err := r.Put(context.Background(), Definition{Name: "edge", Source: SourceURL, URL: srv.URL + "/ip.srs", Refresh: "6h"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Active == nil || g.Active.Format != FormatSRS || g.Active.Prefixes != 4 {
		t.Fatalf("imported: %+v", g)
	}
	if changed, err := r.Refresh(context.Background(), "edge", false); changed || err != nil || conditional.Load() != 1 {
		t.Fatalf("revalidation must use the ETag: %v %v %d", changed, err, conditional.Load())
	}
	random, err := os.ReadFile(filepath.Join("testdata", "random.srs"))
	if err != nil {
		t.Fatal(err)
	}
	body.Store(random)
	if changed, err := r.Refresh(context.Background(), "edge", false); !changed || err != nil {
		t.Fatalf("new content: %v %v", changed, err)
	}
}

func TestURLFetchLimits(t *testing.T) {
	defer func(old int64) { maxSourceBytes = old }(maxSourceBytes)
	maxSourceBytes = 1024
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("10.0.0.0/8\n", 200)))
		case "/plain-redirect":
			http.Redirect(w, req, "http://example.invalid/list.txt", http.StatusFound)
		default:
			http.Error(w, "gone", http.StatusGone)
		}
	}))
	defer srv.Close()
	env := newTestEnv(t)
	env.opts.Client = srv.Client()
	r := env.open(t)
	for path, want := range map[string]string{"/big": "larger than", "/plain-redirect": "https", "/missing": "410"} {
		g, err := r.Put(context.Background(), Definition{Name: "t" + strings.Trim(strings.ReplaceAll(path, "-", ""), "/"), Source: SourceURL, URL: srv.URL + path})
		if err != nil {
			t.Fatalf("%s: a definition is kept even when its first import fails: %v", path, err)
		}
		if g.Active != nil || !strings.Contains(g.Error, want) {
			t.Fatalf("%s: %+v", path, g)
		}
	}
}

func TestDefinitionValidation(t *testing.T) {
	env := newTestEnv(t)
	r := env.open(t)
	for _, d := range []Definition{
		{Name: "Bad Name", Source: SourceFile, File: "a.txt"},
		{Name: "a", Source: "ftp", URL: "ftp://example.com/a"},
		{Name: "a", Source: SourceURL, URL: "http://example.com/a.srs"},
		{Name: "a", Source: SourceURL, URL: "https://user:pass@example.com/a.srs"},
		{Name: "a", Source: SourceURL, URL: "https://example.com/a.srs", Refresh: "10m"},
		{Name: "a", Source: SourceFile, File: "../etc/passwd"},
		{Name: "a", Source: SourceFile, File: "sub/a.txt"},
		{Name: "a", Source: SourceFile, File: "a.txt", Note: "bad\nnote"},
	} {
		if _, err := r.Put(context.Background(), d); err == nil {
			t.Errorf("accepted %+v", d)
		}
	}
	if len(r.Groups()) != 0 {
		t.Fatal("rejected definitions must not be stored")
	}
}

func TestDueSchedule(t *testing.T) {
	env := newTestEnv(t)
	env.writeSource(t, "a.txt", "192.0.2.0/24\n")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer srv.Close()
	env.opts.Client = srv.Client()
	r := env.open(t)
	if _, err := r.Put(context.Background(), Definition{Name: "a", Source: SourceFile, File: "a.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Put(context.Background(), Definition{Name: "b", Source: SourceURL, URL: srv.URL, Refresh: "1h"}); err != nil {
		t.Fatal(err)
	}
	if got := r.Due(env.now); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("file groups are always checked, url groups after their interval: %v", got)
	}
	if got := r.Due(env.now.Add(61 * time.Minute)); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("after the interval: %v", got)
	}
}

func TestGCKeepsListsInUse(t *testing.T) {
	env := newTestEnv(t)
	env.writeSource(t, "a.txt", "192.0.2.0/24\n")
	r := env.open(t)
	g, err := r.Put(context.Background(), Definition{Name: "a", Source: SourceFile, File: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(env.opts.ListDir, "a.000000000000.txt")
	referenced := filepath.Join(env.opts.ListDir, "a.111111111111.txt")
	fresh := filepath.Join(env.opts.ListDir, "a.222222222222.txt")
	for _, p := range []string{old, referenced, fresh} {
		if err := os.WriteFile(p, []byte("10.0.0.0/8\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	past := env.now.Add(-48 * time.Hour)
	for _, p := range []string{old, referenced, filepath.Join(env.opts.ListDir, g.Active.File)} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.GC(map[string]bool{filepath.Base(referenced): true}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	for p, keep := range map[string]bool{old: false, referenced: true, fresh: true, filepath.Join(env.opts.ListDir, g.Active.File): true} {
		if _, err := os.Stat(p); (err == nil) != keep {
			t.Errorf("%s: keep=%v, stat err %v", filepath.Base(p), keep, err)
		}
	}
}

func TestTickReportsChangedGroups(t *testing.T) {
	env := newTestEnv(t)
	env.writeSource(t, "a.txt", "192.0.2.0/24\n")
	env.writeSource(t, "b.txt", "198.51.100.0/24\n")
	r := env.open(t)
	for _, n := range []string{"a", "b"} {
		if _, err := r.Put(context.Background(), Definition{Name: n, Source: SourceFile, File: n + ".txt"}); err != nil {
			t.Fatal(err)
		}
	}
	env.writeSource(t, "b.txt", "198.51.100.0/24\n203.0.113.0/24\n")
	var changed []string
	r.Tick(context.Background(), func(name string) { changed = append(changed, name) })
	if !reflect.DeepEqual(changed, []string{"b"}) {
		t.Fatalf("changed groups: %v", changed)
	}
}

func TestDownloadsUseTheConfiguredProxy(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// An HTTPS download through a proxy starts with CONNECT.
		if req.Method == http.MethodConnect {
			proxied.Add(1)
		}
		http.Error(w, "no tunnel in this test", http.StatusForbidden)
	}))
	defer proxy.Close()
	env := newTestEnv(t)
	env.opts.Proxy = proxy.URL
	r := env.open(t)
	g, err := r.Put(context.Background(), Definition{Name: "p", Source: SourceURL, URL: "https://example.invalid/list.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 1 || g.Error == "" {
		t.Fatalf("the download must go through the proxy: %d %q", proxied.Load(), g.Error)
	}
	env.opts.Proxy = "ftp://proxy.example"
	if _, err := Open(env.opts); err == nil {
		t.Fatal("an unsupported proxy URL must be rejected")
	}
}
