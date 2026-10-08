// Package ratelimit implements the UI rate limiting with a zero-dep token
// bucket (stdlib only, no golang.org/x/time/rate): single-process, no
// sharding (D3). It covers RL-1 (login: per client + global ceiling), RL-2
// (/api/* per client) and the failed-credential budget of the session and
// Bearer checks. The key is ALWAYS the IP of r.RemoteAddr without the port
// (every new connection has a new source port): X-Forwarded-For is not
// trusted (no-goal of the security-parity-mitigation change).
//
// The design avoids goroutines and lifecycles: the prune of idle clients is
// lazy and amortized inside Allow(), and the limiters are process globals
// (created on the first use of the package).
package ratelimit

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Named design constants (D1/D2): the numeric rate values live here, never
// inline in the call sites.
const (
	// LoginPerClientPerMinute is the rate of POST /login per client (5/min:
	// 1 token every 12s) and LoginPerClientBurst its burst (== rate: strict
	// 5-then-refill, RL-1/D1).
	LoginPerClientPerMinute = 5
	LoginPerClientBurst     = 5

	// LoginGlobalPerMinute is the global login ceiling shared by ALL clients
	// (60/min, 1 token/s) and LoginGlobalBurst its burst: it bounds
	// distributed guessing without self-DoS of NATs/multi-device setups
	// (RL-1/D1).
	LoginGlobalPerMinute = 60
	LoginGlobalBurst     = 60

	// APIPerMinute is the sustained /api/* rate per RemoteAddr (120/min,
	// never below the 60/min floor of the spec) and APIBurst its burst rate
	// (RL-2/D2).
	APIPerMinute = 120
	APIBurst     = 30

	// ClientIdleTimeout is the inactivity time after which the lazy prune
	// removes the entry of a client from the ClientLimiter (D3).
	ClientIdleTimeout = 30 * time.Minute
)

// Bucket is a token bucket with continuous refill (perMinute tokens per
// minute) and capacity == burst. Access is concurrency-safe (mutex). The
// grant and the refill share the injectable clock b.now to be able to fix
// the time in tests (white-box); in production b.now is time.Now.
type Bucket struct {
	mu        sync.Mutex
	perMinute float64
	capacity  float64
	tokens    float64
	last      time.Time
	now       func() time.Time
}

// NewBucket builds a bucket with the real clock. burst is the maximum
// capacity and the amount of immediate grants available.
func NewBucket(perMinute float64, burst int) *Bucket {
	return newBucket(perMinute, burst, time.Now)
}

// newBucket is the constructor with an injectable clock (white-box tests and
// ClientLimiter, which shares its clock with the buckets of each client).
func newBucket(perMinute float64, burst int, now func() time.Time) *Bucket {
	return &Bucket{
		perMinute: perMinute,
		capacity:  float64(burst),
		tokens:    float64(burst),
		last:      now(),
		now:       now,
	}
}

// Allow grants a token if ≥1 is available (refill applied up to the current
// instant); otherwise it returns the time left to accumulate ≥1 token,
// rounded up to the next second (Retry-After).
func (b *Bucket) Allow() (ok bool, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allowAt(b.now())
}

// allowAt evaluates the grant at instant now: it applies the continuous
// refill proportional to the time elapsed since the last evaluation and, if
// there is ≥1 token, consumes it. The retry is measured in minutes
// (perMinute is a per-minute rate) to avoid accumulating drift at exact
// multiples (e.g. 12s → 1 token in a 5/min bucket).
func (b *Bucket) allowAt(now time.Time) (ok bool, retryAfter time.Duration) {
	b.refillAt(now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, b.retryAfter()
}

// refillAt applies the continuous refill up to now.
func (b *Bucket) refillAt(now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Minutes() * b.perMinute
		b.last = now
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
	}
}

// blockedAt reports, without consuming, whether no token is available at now.
func (b *Bucket) blockedAt(now time.Time) (bool, time.Duration) {
	b.refillAt(now)
	if b.tokens >= 1 {
		return false, 0
	}
	return true, b.retryAfter()
}

// retryAfter returns the whole seconds until one token accumulates.
func (b *Bucket) retryAfter() time.Duration {
	if b.perMinute <= 0 {
		// No refill (defensive: the call sites use constants > 0): a retry
		// of one hour is the pragmatic cap to avoid returning infinity.
		return time.Hour
	}
	// Whole seconds until the missing token accumulates, with a minimum
	// tolerance that neutralizes the floating-point rounding at exact edges
	// (ceil(11.999999999999998) must be 12, not 11).
	need := 1 - b.tokens
	seconds := need / (b.perMinute / 60)
	retry := int(math.Ceil(seconds - 1e-9))
	if retry < 1 {
		retry = 1
	}
	return time.Duration(retry) * time.Second
}

// clientEntry groups the bucket of a client with its last activity
// (lastSeen), which the lazy prune uses to decide whether the entry is idle.
type clientEntry struct {
	bucket   *Bucket
	lastSeen time.Time
}

// ClientLimiter keeps one Bucket per key (RemoteAddr of the client). The map
// grows with the seen clients and is pruned lazily and amortized inside
// Allow: the full sweep runs at most once per ClientIdleTimeout (not per
// request) and without goroutines or lifecycle.
type ClientLimiter struct {
	mu        sync.Mutex
	perMinute float64
	burst     int
	clients   map[string]*clientEntry
	now       func() time.Time
	lastPrune time.Time
}

// NewClient builds a ClientLimiter with the real clock.
func NewClient(perMinute float64, burst int) *ClientLimiter {
	return newClient(perMinute, burst, time.Now)
}

// newClient is the constructor with an injectable clock (white-box tests).
// The client buckets created in Allow share this same clock.
func newClient(perMinute float64, burst int, now func() time.Time) *ClientLimiter {
	return &ClientLimiter{
		perMinute: perMinute,
		burst:     burst,
		clients:   make(map[string]*clientEntry),
		now:       now,
	}
}

// Allow grants (or not) a token to the bucket of the key, creating it on the
// first time. Before evaluating, the amortized lazy prune runs: it removes
// the idle clients > ClientIdleTimeout. Every call counts as activity of the
// key (lastSeen is updated also on denials).
func (c *ClientLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.Sub(c.lastPrune) > ClientIdleTimeout {
		for k, entry := range c.clients {
			if now.Sub(entry.lastSeen) > ClientIdleTimeout {
				delete(c.clients, k)
			}
		}
		c.lastPrune = now
	}

	entry, exists := c.clients[key]
	if !exists {
		entry = &clientEntry{bucket: newBucket(c.perMinute, c.burst, c.now)}
		c.clients[key] = entry
	}
	entry.lastSeen = now
	return entry.bucket.Allow()
}

// Blocked reports whether the bucket of the key has no token left, without
// consuming one. An unknown key has its full burst available.
func (c *ClientLimiter) Blocked(key string) (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.clients[key]
	if !ok {
		return false, 0
	}
	entry.bucket.mu.Lock()
	defer entry.bucket.mu.Unlock()
	return entry.bucket.blockedAt(c.now())
}

// reset drops every client bucket.
func (c *ClientLimiter) reset() {
	c.mu.Lock()
	c.clients = make(map[string]*clientEntry)
	c.mu.Unlock()
}

// process-wide shared limiters (single-process, D3). The global login
// ceiling is a single Bucket; the rest are per RemoteAddr.
var (
	loginClient = NewClient(LoginPerClientPerMinute, LoginPerClientBurst)
	loginGlobal = NewBucket(LoginGlobalPerMinute, LoginGlobalBurst)
	apiClient   = NewClient(APIPerMinute, APIBurst)
	// credentialClient counts failed session cookies and Bearer tokens per
	// client, with the per-client login budget. It has no global ceiling: a
	// distributed attack must never lock valid sessions out.
	credentialClient = NewClient(LoginPerClientPerMinute, LoginPerClientBurst)
)

// clientKey returns the IP of the request without the source port.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// CredentialBlocked reports whether the client spent its failed-credential
// budget. Callers check it BEFORE evaluating a presented credential, so a
// blocked client learns nothing about its guesses; it consumes nothing.
func CredentialBlocked(r *http.Request) (bool, time.Duration) {
	return credentialClient.Blocked(clientKey(r))
}

// CredentialFailed charges one rejected session cookie or Bearer token to
// the client.
func CredentialFailed(r *http.Request) {
	credentialClient.Allow(clientKey(r))
}

// ResetCredentialFailures clears the failed-credential budget of every
// client (tests that share the process limiter).
func ResetCredentialFailures() { credentialClient.reset() }

// TooManyRequests writes the 429 response used by every limiter.
func TooManyRequests(w http.ResponseWriter, retryAfter time.Duration) {
	tooManyRequests(w, retryAfter)
}

// tooManyRequests responds 429 with Retry-After and a plain body, without
// Set-Cookie: the short-circuit happens BEFORE auth/CSRF/RequestLogger, so a
// 429 never sets a cookie nor floods the ui_request log (D4).
func tooManyRequests(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	http.Error(w, "too many requests, retry later", http.StatusTooManyRequests)
}

// Login wraps the public login mux limiting ONLY the POST (RL-1): safe
// methods (GET /login) pass without consuming tokens, so the login page is
// never blocked by the attempt limit (RL-3/D4). The order is per-client and
// then the global ceiling.
func Login(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if ok, retryAfter := loginClient.Allow(clientKey(r)); !ok {
			tooManyRequests(w, retryAfter)
			return
		}
		if ok, retryAfter := loginGlobal.Allow(); !ok {
			tooManyRequests(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// API limits /api/* per client IP (RL-2/D2). It is mounted OUTSIDE
// auth.Middleware (D4): token-less probes consume budget and the 429 cuts
// before auth/CSRF/RequestLogger. It applies to all methods.
func API(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, retryAfter := apiClient.Allow(clientKey(r)); !ok {
			tooManyRequests(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}
