package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/events"
)

// hangingLoki installs a Loki endpoint that answers only when its request is
// cancelled, and returns the number of queries it received.
func hangingLoki(t *testing.T) *atomic.Int32 {
	t.Helper()
	calls := new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	rt := currentRuntime()
	copied := *rt
	copied.Loki = &events.LokiClient{URL: srv.URL, Token: "t", HTTP: srv.Client()}
	SetRuntime(&copied)
	return calls
}

// TestPageLokiQueriesShareOneBudget: the event detail page may query Loki
// several times (the event, then its 14-day history). Together they must
// finish within the page budget, below the server WriteTimeout (30s), or the
// browser receives a truncated response.
func TestPageLokiQueriesShareOneBudget(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	calls := hangingLoki(t)
	prev := pageLokiBudget
	pageLokiBudget = 300 * time.Millisecond
	t.Cleanup(func() { pageLokiBudget = prev })

	start := time.Now()
	rec := httptest.NewRecorder()
	HandleIndex(rec, httptest.NewRequest(http.MethodGet, "/?tab=event&tx=missing&source=loki", nil))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the page waited %v for Loki; the budget is %v", elapsed, pageLokiBudget)
	}
	if calls.Load() == 0 {
		t.Fatal("the page did not query Loki")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the page with a history error, got %d", rec.Code)
	}
}

// TestPageLokiQueriesFollowTheRequestContext: a client that disconnects
// cancels the Loki queries of its page instead of leaving them running.
func TestPageLokiQueriesFollowTheRequestContext(t *testing.T) {
	setupUIEnv(t)
	setupWAFRuntime(t)
	hangingLoki(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	rec := httptest.NewRecorder()
	HandleIndex(rec, httptest.NewRequest(http.MethodGet, "/?tab=analysis&range=7d", nil).WithContext(ctx))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("a cancelled request kept waiting for Loki for %v", elapsed)
	}
}
