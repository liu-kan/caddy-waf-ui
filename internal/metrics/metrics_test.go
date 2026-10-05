package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryRendersCountersAndGauges(t *testing.T) {
	r := &Registry{}
	c := r.NewCounterVec("waf_test_total", "Test counter.", "site", "action")
	c.Inc("a.com", "blocked")
	c.Add(2, "a.com", "blocked")
	c.Inc(`b"x`, "detected")
	c.Add(-1, "a.com", "blocked") // negative adds are ignored
	c.Inc("missing-label")        // wrong arity is ignored
	r.NewGaugeFunc("waf_test_info", "Test gauge.", []string{"site"}, func() []Sample {
		return []Sample{{Labels: []string{"a.com"}, Value: 1}, {Labels: []string{"bad", "arity"}, Value: 9}}
	})
	if c.Value("a.com", "blocked") != 3 {
		t.Fatalf("value: %v", c.Value("a.com", "blocked"))
	}
	var b strings.Builder
	if err := r.Render(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE waf_test_total counter",
		`waf_test_total{site="a.com",action="blocked"} 3`,
		`waf_test_total{site="b\"x",action="detected"} 1`,
		"# TYPE waf_test_info gauge",
		`waf_test_info{site="a.com"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "arity") {
		t.Fatal("samples with the wrong label count must be dropped")
	}
}

func TestHandlerRequiresToken(t *testing.T) {
	r := &Registry{}
	r.NewCounterVec("waf_x_total", "x").Inc()
	token := ""
	h := Handler(r, func() string { return token })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled endpoint: %d", rec.Code)
	}
	token = "s3cret"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "waf_x_total 1") ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("scrape: %d %q", rec.Code, rec.Body.String())
	}
}
