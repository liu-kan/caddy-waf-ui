package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/ratelimit"
)

// sessionCookieName is the name of the session cookie (decision D3). The
// cookie is a signed, expiring session derived from the access token, with no
// server-side state: it never carries the token itself, so a stolen cookie
// is not an API credential and stops working after sessionMaxAgeSeconds.
const sessionCookieName = "CADDY_UI_TOKEN"

// sessionVersion prefixes the session cookie format
// "v1.<issued unix seconds>.<hex HMAC-SHA256(token, "session|v1|<issued>")>".
const sessionVersion = "v1"

// sessionClockSkew tolerates sessions issued slightly in the future.
const sessionClockSkew = time.Minute

// csrfContext is the fixed HMAC context used to derive the CSRF token from
// the secret: the raw secret never travels in the DOM (decision D1).
const csrfContext = "csrf"

// sessionMaxAgeSeconds is the session lifetime: 12h (SC-1), enforced both
// by the cookie Max-Age and by the server from the signed issue time.
// Rotating CADDY_UI_TOKEN invalidates every session at once.
const sessionMaxAgeSeconds = 43200

// NewSessionValue returns a session cookie value issued at now.
func NewSessionValue(now time.Time) (string, error) {
	secret := tokenFromEnv()
	if secret == "" {
		return "", errors.New("CADDY_UI_TOKEN not configured: cannot sign a session")
	}
	issued := strconv.FormatInt(now.Unix(), 10)
	return sessionVersion + "." + issued + "." + sessionMAC(secret, issued), nil
}

// sessionMAC signs an issue time. Its context differs from the CSRF value,
// so the CSRF token in the DOM can never be replayed as a session.
func sessionMAC(secret, issued string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("session|" + sessionVersion + "|" + issued))
	return hex.EncodeToString(mac.Sum(nil))
}

// validSession verifies the signature (constant time) and the age of a
// session cookie value at now.
func validSession(value string, now time.Time) bool {
	secret := tokenFromEnv()
	if secret == "" {
		return false
	}
	version, rest, ok := strings.Cut(value, ".")
	if !ok || version != sessionVersion {
		return false
	}
	issued, signature, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	unix, err := strconv.ParseInt(issued, 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(unix, 0))
	if age < -sessionClockSkew || age > sessionMaxAgeSeconds*time.Second {
		return false
	}
	return hmac.Equal([]byte(signature), []byte(sessionMAC(secret, issued)))
}

// tokenFromEnv returns the configured token (empty if unset).
// Centralized in config (finding J5-3).
func tokenFromEnv() string {
	return config.Token()
}

// tokenMatches compares the provided token against the configured one in
// constant time (same anti-timing pattern as bearer.go). An unconfigured
// token never validates.
func tokenMatches(provided string) bool {
	expected := tokenFromEnv()
	if expected == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// bearerToken extracts the token from an Authorization Bearer header, or "".
func bearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// credentialResult classifies the credentials presented by a request.
type credentialResult int

const (
	credentialMissing credentialResult = iota
	credentialValid
	credentialInvalid
	// credentialLimited: the client spent its failed-credential budget; the
	// credential was not evaluated.
	credentialLimited
)

// checkCredentials evaluates the session cookie (when allowCookie) and the
// Bearer token under the per-client failed-credential budget shared by the
// pages, the API and the login page: without it, a cookie or Bearer guess on
// any route would bypass the POST /login limiter. A blocked client gets no
// evaluation at all, so a correct guess cannot be told from a wrong one.
func checkCredentials(r *http.Request, allowCookie bool) (credentialResult, time.Duration) {
	var cookieValue string
	if allowCookie {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			cookieValue = cookie.Value
		}
	}
	bearer := bearerToken(r)
	if cookieValue == "" && bearer == "" {
		return credentialMissing, 0
	}
	if blocked, retry := ratelimit.CredentialBlocked(r); blocked {
		return credentialLimited, retry
	}
	if (cookieValue != "" && validSession(cookieValue, time.Now())) || tokenMatches(bearer) {
		return credentialValid, 0
	}
	ratelimit.CredentialFailed(r)
	return credentialInvalid, 0
}

// HasValidSession reports whether the request carries a valid session:
// a CADDY_UI_TOKEN cookie or a valid Bearer (spec web-ui: "cookie or valid
// Bearer"). A client over its failed-credential budget has no session.
func HasValidSession(r *http.Request) bool {
	result, _ := checkCredentials(r, true)
	return result == credentialValid
}

// SetSessionCookie sets the session cookie (a NewSessionValue) with
// HttpOnly; Secure; SameSite=Strict; Path=/ and Max-Age 12h (decision D3:
// loopback is a secure context, which is why Secure works over plain HTTP;
// SC-1).
func SetSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   sessionMaxAgeSeconds,
	})
}

// Login validates the credential (constant-time comparison) and, if valid,
// sets a signed session cookie. Returns true only if the session was
// established.
func Login(w http.ResponseWriter, provided string) bool {
	if !tokenMatches(provided) {
		return false
	}
	value, err := NewSessionValue(time.Now())
	if err != nil {
		return false
	}
	SetSessionCookie(w, value)
	return true
}

// Logout deletes the client's session cookie (immediate expiration). The
// design is stateless: a copied cookie stays valid until its 12h expiry or
// until CADDY_UI_TOKEN is rotated.
func Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0), // already expired
	})
}

// Session protects the SSR pages: it accepts a valid session cookie or
// Bearer; without a session it redirects to /login (302, spec web-ui)
// instead of responding 401, because the expected client is a browser.
// A client over its failed-credential budget receives 429.
func Session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch result, retry := checkCredentials(r, true); result {
		case credentialValid:
			next.ServeHTTP(w, r)
		case credentialLimited:
			ratelimit.TooManyRequests(w, retry)
		default:
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})
}

// CSRFValue derives the double-submit token: HMAC-SHA256(secret, "csrf") in
// hex (decision D1). The raw secret never appears in the DOM, so an XSS
// cannot exfiltrate it for use against /api.
func CSRFValue() (string, error) {
	secret := tokenFromEnv()
	if secret == "" {
		return "", errors.New("CADDY_UI_TOKEN not configured: cannot derive CSRF token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(csrfContext))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CSRF validates the hidden "csrf" field (double-submit) on mutation
// requests with constant-time comparison (crypto/subtle). Bearer-authenticated
// requests are exempt: a browser cannot attach Authorization cross-site
// (decision D1). Safe methods (GET/HEAD/OPTIONS) pass without a token.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if tokenMatches(bearerToken(r)) {
			next.ServeHTTP(w, r)
			return
		}
		expected, err := CSRFValue()
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		provided := r.FormValue("csrf")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
