package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var staticFS embed.FS

// securityPolicy is the Content-Security-Policy applied to all the
// responses by the SecurityHeaders middleware. The assets are self-hosted
// (go:embed under /static, no CDN) and the handlers live in app.js: there
// are no inline scripts or styles, so script-src/style-src stay at 'self'.
const securityPolicy = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// StaticHandler serves the static assets of the UI (pico.min.css v2.1.1,
// app.css, app.js) from the embedded binary. It is a PUBLIC resource
// (without session): only static files, no sensitive data. Routes ending in
// "/" (directory listings) respond 404.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("embedded assets unavailable: %v", err))
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// SecurityHeaders wraps the full mux and sets the security headers on ALL
// the responses (SSR pages, API, login and assets):
//   - Content-Security-Policy: self-hosted policy (see securityPolicy).
//   - X-Content-Type-Options: nosniff - prevents the browser from guessing
//     the MIME type of a response and executing injected content as HTML/JS.
//   - Referrer-Policy: no-referrer - the UI URLs carry ?search= and ?domain=
//     (domain names, search terms) and must not leak to third parties
//     through the Referer header. The UI is an administration console
//     without any referrer use case, so the most restrictive policy is
//     chosen.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", securityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		// Strict-Transport-Security (SH-2): the UI does not terminate TLS, so
		// the header only applies when the request arrived over HTTPS through
		// a trusted TLS proxy. Caddy adds X-Forwarded-Proto: https in
		// reverse_proxy; EqualFold makes the comparison case-insensitive.
		// Fixed value max-age=31536000 (1 year, OWASP): without
		// includeSubDomains nor preload (no-goals). Over plain HTTP the
		// header is inert (RFC 6797).
		if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
