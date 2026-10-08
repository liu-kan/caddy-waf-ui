package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// okHandler is the "next" handler used in the middleware tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// cookieSesion retrieves the CADDY_UI_TOKEN cookie from the recorder.
func cookieSesion(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("cookie %s not found in the response", sessionCookieName)
	return nil
}

func TestLoginSetsSessionCookieFlags(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	if !Login(rec, "super-secret-token") {
		t.Fatal("login with a valid token must return true")
	}

	c := cookieSesion(t, rec)
	if strings.Contains(c.Value, "super-secret-token") {
		t.Errorf("the cookie must never carry the access token, got %q", c.Value)
	}
	if !validSession(c.Value, time.Now()) {
		t.Errorf("the cookie must be a valid signed session, got %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("the session cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Error("the session cookie must be Secure (loopback is a secure context, D3)")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("the session cookie must be SameSite=Strict, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("the cookie must have Path=/, got %q", c.Path)
	}
	if c.MaxAge != 43200 {
		t.Errorf("the session cookie must expire after 12h (Max-Age=43200, SC-1), got %d", c.MaxAge)
	}
}

func TestLoginRejectsWrongToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	if Login(rec, "token-incorrecto") {
		t.Fatal("login with an invalid token must return false")
	}
	if rec.Result().Cookies() != nil && len(rec.Result().Cookies()) > 0 {
		t.Error("no cookie must be set with an invalid credential")
	}
}

func TestLoginRejectsWhenTokenUnset(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "")

	rec := httptest.NewRecorder()
	if Login(rec, "") {
		t.Error("with no token configured there can be no login")
	}
	if Login(rec, "super-secret-token") {
		t.Error("with no token configured, no value must validate")
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	Logout(rec)

	c := cookieSesion(t, rec)
	if c.MaxAge >= 0 && c.Expires.After(time.Now()) {
		t.Errorf("logout must expire the cookie, MaxAge=%d Expires=%v", c.MaxAge, c.Expires)
	}
}

func TestSessionAcceptsValidCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	value, err := NewSessionValue(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("with a valid cookie it must pass to the next handler, got %d", rec.Code)
	}
}

func TestSessionAcceptsValidBearer(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("with a valid Bearer it must pass to the next handler, got %d", rec.Code)
	}
}

func TestSessionRedirectsWithoutCredentials(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("without a session: expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected Location /login, got %q", loc)
	}
}

func TestSessionRejectsWrongCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token-roto", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("with an invalid cookie: expected 302, got %d", rec.Code)
	}
}

func TestCSRFValidTokenPasses(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	token, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue failed: %v", err)
	}
	form := url.Values{"csrf": {token}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("with a valid CSRF token it must pass, got %d", rec.Code)
	}
}

func TestCSRFMissingTokenRejected(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("mode=On"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token: expected 403, got %d", rec.Code)
	}
}

func TestCSRFWrongTokenRejected(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	form := url.Values{"csrf": {"token-incorrecto"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST with invalid CSRF token: expected 403, got %d", rec.Code)
	}
}

func TestCSRFAllowsSafeMethods(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/", nil)
		rec := httptest.NewRecorder()
		CSRF(okHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s without CSRF token must pass (safe method), got %d", method, rec.Code)
		}
	}
}

func TestCSRFBearerExempt(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("mode=On"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST authenticated by Bearer must be exempt from CSRF, got %d", rec.Code)
	}
}

func TestCSRFValueDeterministicAndSecretBound(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "secreto-uno")
	first, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue failed: %v", err)
	}
	second, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue failed: %v", err)
	}
	if first != second {
		t.Error("the CSRF token must be deterministic for the same secret")
	}

	t.Setenv("CADDY_UI_TOKEN", "secreto-dos")
	other, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue failed: %v", err)
	}
	if other == first {
		t.Error("the CSRF token must change when the secret changes")
	}
}

func TestCSRFValueRequiresToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "")

	if _, err := CSRFValue(); err == nil {
		t.Error("with no token configured, CSRFValue must return an error")
	}
}

// TestSignedSessionCookie: the session cookie is "v1.<issued>.<HMAC>": it
// never exposes the access token, it expires server-side after 12h even if
// the browser keeps it, it cannot be forged from the CSRF value, and rotating
// the token invalidates every session.
func TestSignedSessionCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	now := time.Now()
	value, err := NewSessionValue(now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(value, "super-secret-token") || !strings.HasPrefix(value, "v1.") {
		t.Fatalf("unexpected session value %q", value)
	}
	if !validSession(value, now.Add(11*time.Hour)) {
		t.Fatal("a session must be valid within 12h")
	}
	if validSession(value, now.Add(12*time.Hour+time.Second)) {
		t.Fatal("a session must expire server-side after 12h")
	}
	if validSession(value, now.Add(-5*time.Minute)) {
		t.Fatal("a session issued in the future must be rejected")
	}
	if validSession("super-secret-token", now) {
		t.Fatal("the raw access token is no longer a session cookie")
	}
	csrf, _ := CSRFValue()
	issued := strings.Split(value, ".")[1]
	for _, forged := range []string{"v1." + issued + "." + csrf, "v2." + issued + "." + strings.Split(value, ".")[2], value + "0", "v1..", ""} {
		if validSession(forged, now) {
			t.Fatalf("forged session %q accepted", forged)
		}
	}
	t.Setenv("CADDY_UI_TOKEN", "rotated-secret-token")
	if validSession(value, now) {
		t.Fatal("rotating the token must invalidate existing sessions")
	}
}
