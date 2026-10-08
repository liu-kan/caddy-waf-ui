package auth

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/ratelimit"
)

// failCredentials sends n rejected credentials from ip, each on a new port.
func failCredentials(t *testing.T, h http.Handler, ip string, n int, set func(*http.Request)) {
	t.Helper()
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":" + strconv.Itoa(30000+i)
		set(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK || rec.Code == http.StatusTooManyRequests {
			t.Fatalf("failure %d: expected a rejection inside the budget, got %d", i+1, rec.Code)
		}
	}
}

// TestSessionGuessesShareTheFailureBudget: the SSR pages accept the session
// cookie and Bearer, so they are an alternative to POST /login for guessing
// the token. After the per-client budget, the client receives 429 BEFORE its
// credential is evaluated (even a correct one), so blocked guesses reveal
// nothing; other clients are unaffected.
func TestSessionGuessesShareTheFailureBudget(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	ratelimit.ResetCredentialFailures()
	t.Cleanup(ratelimit.ResetCredentialFailures)

	h := Session(okHandler)
	failCredentials(t, h, "192.0.2.80", ratelimit.LoginPerClientBurst, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "guess"})
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.80:39999"
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a blocked client must get 429 + Retry-After before evaluation, got %d", rec.Code)
	}

	other := httptest.NewRequest(http.MethodGet, "/", nil)
	other.RemoteAddr = "192.0.2.81:1"
	other.Header.Set("Authorization", "Bearer super-secret-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, other)
	if rec.Code != http.StatusOK {
		t.Fatalf("another client with a valid credential must pass, got %d", rec.Code)
	}

	anonymous := httptest.NewRequest(http.MethodGet, "/", nil)
	anonymous.RemoteAddr = "192.0.2.80:40000"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, anonymous)
	if rec.Code != http.StatusFound {
		t.Fatalf("a request without credentials is redirected to /login, never limited; got %d", rec.Code)
	}
}

// TestBearerGuessesShareTheFailureBudget: the same budget protects /api.
func TestBearerGuessesShareTheFailureBudget(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	ratelimit.ResetCredentialFailures()
	t.Cleanup(ratelimit.ResetCredentialFailures)

	h := Middleware(okHandler)
	failCredentials(t, h, "192.0.2.82", ratelimit.LoginPerClientBurst, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer guess")
	})
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.RemoteAddr = "192.0.2.82:1"
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after the failure budget, got %d", rec.Code)
	}
}

// TestLoginPageDoesNotEvaluateCookiesOfBlockedClients: GET /login checks
// the session to redirect logged-in users; it must not become an oracle.
func TestLoginPageDoesNotEvaluateCookiesOfBlockedClients(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	ratelimit.ResetCredentialFailures()
	t.Cleanup(ratelimit.ResetCredentialFailures)

	for i := 0; i < ratelimit.LoginPerClientBurst; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.RemoteAddr = "192.0.2.83:" + strconv.Itoa(i+1)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "guess"})
		if HasValidSession(req) {
			t.Fatal("a wrong cookie must not be valid")
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "192.0.2.83:99"
	req.Header.Set("Authorization", "Bearer super-secret-token")
	if HasValidSession(req) {
		t.Fatal("a blocked client must not get its credential evaluated")
	}
}
