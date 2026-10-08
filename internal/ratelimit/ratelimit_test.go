package ratelimit

// Unit tests of the zero-dep token bucket (S4, RL-1/RL-2/D1-D3).
// White-box (package ratelimit): the internal constructors newBucket/newClient
// accept an injectable clock to fix the time in the assertions; Allow() and
// Allow(key) are the same production path that runs under -race.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestRateLimitConstantsMatchDesign: the numeric values are NAMED constants
// with the exact design values (D1/D2): login per client 5/min burst 5,
// global ceiling 60/min burst 60, API 120/min burst 30 and a client idle
// timeout of 30 minutes.
func TestRateLimitConstantsMatchDesign(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"LoginPerClientPerMinute", LoginPerClientPerMinute, 5},
		{"LoginPerClientBurst", LoginPerClientBurst, 5},
		{"LoginGlobalPerMinute", LoginGlobalPerMinute, 60},
		{"LoginGlobalBurst", LoginGlobalBurst, 60},
		{"APIPerMinute", APIPerMinute, 120},
		{"APIBurst", APIBurst, 30},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: expected %d, got %d", tt.name, tt.want, tt.got)
		}
	}
	if ClientIdleTimeout != 30*time.Minute {
		t.Errorf("ClientIdleTimeout: expected 30m, got %v", ClientIdleTimeout)
	}
}

// TestBucketAllowsBurstThenDeniesWithRetryAfter: a 5/min bucket (1 token
// every 12s) grants exactly its burst and then denies; the immediate
// Retry-After is the time to accumulate ≥1 token: ceil(12s)=12s.
func TestBucketAllowsBurstThenDeniesWithRetryAfter(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newBucket(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return t0 })

	for i := 0; i < LoginPerClientBurst; i++ {
		if ok, retry := b.Allow(); !ok || retry != 0 {
			t.Fatalf("request %d inside the burst: expected ok=true retry=0, got ok=%v retry=%v", i+1, ok, retry)
		}
	}
	ok, retry := b.Allow()
	if ok {
		t.Fatal("the sixth request must be denied (burst 5 exhausted)")
	}
	if retry != 12*time.Second {
		t.Errorf("immediate Retry-After: expected 12s (ceil until ≥1 token), got %v", retry)
	}
}

// TestBucketRefillsOverTimeAndRecovers: the refill is continuous (12s per
// token in a 5/min bucket). At +6s there is half a token (denies with a 6s
// retry); at +12s there is ≥1 token and the request passes; the next
// immediate one denies again.
func TestBucketRefillsOverTimeAndRecovers(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	b := newBucket(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	for i := 0; i < LoginPerClientBurst; i++ {
		b.Allow()
	}

	now = t0.Add(6 * time.Second)
	if ok, retry := b.Allow(); ok {
		t.Fatal("at +6s (half a token) the request must be denied")
	} else if retry != 6*time.Second {
		t.Errorf("at +6s the retry must be 6s (half a token left), got %v", retry)
	}

	now = t0.Add(12 * time.Second)
	if ok, retry := b.Allow(); !ok || retry != 0 {
		t.Errorf("at +12s ≥1 token must have accumulated and be granted, got ok=%v retry=%v", ok, retry)
	}

	// Just granted: the bucket is left at 0 tokens; the next one denies.
	if ok, _ := b.Allow(); ok {
		t.Error("after granting the accumulated token, the next request must be denied")
	}
}

// TestBucketCapacityClampsAtBurst: an idle client of 10 minutes accumulates
// 50 theoretical tokens (5/min) but the capacity clamps it to the burst: it
// grants exactly 5 quick requests and then denies (no accumulated debt).
func TestBucketCapacityClampsAtBurst(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	b := newBucket(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	for i := 0; i < LoginPerClientBurst; i++ {
		b.Allow()
	}
	now = t0.Add(10 * time.Minute) // 50 theoretical tokens → clamp to 5

	for i := 0; i < LoginPerClientBurst; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("request %d after the clamp must be granted (full burst), it was denied", i+1)
		}
	}
	if ok, _ := b.Allow(); ok {
		t.Error("the sixth request after the clamp must be denied: the capacity does not accumulate debt")
	}
}

// TestBucketGlobalCeilingRetryAfterOneSecond: the exhausted global login
// ceiling (60/min = 1 token/s) denies with a Retry-After of 1s.
func TestBucketGlobalCeilingRetryAfterOneSecond(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newBucket(LoginGlobalPerMinute, LoginGlobalBurst, func() time.Time { return t0 })

	for i := 0; i < LoginGlobalBurst; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("request %d of the global ceiling must be granted, it was denied", i+1)
		}
	}
	ok, retry := b.Allow()
	if ok {
		t.Fatal("request 61 of the global ceiling must be denied")
	}
	if retry != 1*time.Second {
		t.Errorf("Retry-After of the global ceiling: expected 1s (1 token/s), got %v", retry)
	}
}

// TestBucketAPIBurstRetryAfterOneSecond: the exhausted API bucket (120/min =
// 2 tokens/s, burst 30) denies with a Retry-After of 1s (ceil(0.5s)).
func TestBucketAPIBurstRetryAfterOneSecond(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newBucket(APIPerMinute, APIBurst, func() time.Time { return t0 })

	for i := 0; i < APIBurst; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("request %d of the API burst must be granted, it was denied", i+1)
		}
	}
	ok, retry := b.Allow()
	if ok {
		t.Fatal("request 31 of the API burst must be denied")
	}
	if retry != 1*time.Second {
		t.Errorf("API Retry-After: expected 1s (ceil of 0.5s at 2 tokens/s), got %v", retry)
	}
}

// TestClientLimiterSeparatesClients: the buckets are PER KEY (RemoteAddr):
// exhausting client A does not affect client B.
func TestClientLimiterSeparatesClients(t *testing.T) {
	c := NewClient(LoginPerClientPerMinute, LoginPerClientBurst)

	for i := 0; i < LoginPerClientBurst; i++ {
		if ok, _ := c.Allow("203.0.113.10:1234"); !ok {
			t.Fatalf("request %d of client A must be granted, it was denied", i+1)
		}
	}
	if ok, _ := c.Allow("203.0.113.10:1234"); ok {
		t.Error("the sixth request of client A must be denied (burst exhausted)")
	}
	if ok, retry := c.Allow("198.51.100.77:4321"); !ok {
		t.Errorf("client B (distinct key) must have its own full bucket: denied with retry=%v", retry)
	}
}

// TestClientLimiterRetryAfterTwelveSeconds: ClientLimiter propagates the
// Retry-After of the exhausted client bucket (12s for 5/min).
func TestClientLimiterRetryAfterTwelveSeconds(t *testing.T) {
	c := NewClient(LoginPerClientPerMinute, LoginPerClientBurst)

	for i := 0; i < LoginPerClientBurst; i++ {
		c.Allow("203.0.113.10:1234")
	}
	ok, retry := c.Allow("203.0.113.10:1234")
	if ok {
		t.Fatal("the sixth request must be denied")
	}
	if retry != 12*time.Second {
		t.Errorf("per-client Retry-After: expected 12s, got %v", retry)
	}
}

// TestClientLimiterPrunesIdleClients: the lazy prune in Allow removes the
// clients idle >30 min (ClientIdleTimeout) without goroutines: after
// advancing the clock, an inactive client disappears from the map and an
// active one is kept; the pruned client is recreated fresh on its next
// request.
func TestClientLimiterPrunesIdleClients(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	c := newClient(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	if ok, _ := c.Allow("idle-cliente"); !ok {
		t.Fatal("the first request of the idle client must be granted")
	}
	if ok, _ := c.Allow("cliente-activo"); !ok {
		t.Fatal("the first request of the active client must be granted")
	}

	// The active client keeps operating at 10 minutes (inside the idle window).
	now = t0.Add(10 * time.Minute)
	if ok, _ := c.Allow("cliente-activo"); !ok {
		t.Fatal("the active client must keep operating at 10 min")
	}

	// At 36 minutes (26 min since its last activity) the lazy sweep runs:
	// idle-cliente (36 min idle) is pruned; cliente-activo (26 min idle) is kept.
	now = t0.Add(36 * time.Minute)
	active := c.clients["cliente-activo"]
	if ok, _ := c.Allow("cliente-activo"); !ok {
		t.Fatal("the active client must keep its bucket after the sweep")
	}
	if len(c.clients) != 1 {
		t.Fatalf("the sweep must prune the idle client: expected 1 client, got %d", len(c.clients))
	}
	if _, pruned := c.clients["idle-cliente"]; pruned {
		t.Fatal("idle-cliente (36 min idle > 30 min) must have been pruned from the map")
	}
	if c.clients["cliente-activo"] != active {
		t.Error("cliente-activo (26 min idle < 30 min) must keep its original entry")
	}

	// The pruned client is recreated with a fresh bucket on its next request.
	if ok, _ := c.Allow("idle-cliente"); !ok {
		t.Fatal("the pruned client must be recreated with a full bucket and be granted")
	}
	if len(c.clients) != 2 {
		t.Errorf("the pruned client must reappear: expected 2 clients, got %d", len(c.clients))
	}
}

// TestBucketConcurrentAllowRace: N goroutines disputing the SAME bucket only
// get the burst (5); the rest denies. It runs under -race and verifies that
// the grant is atomic (no double grants).
func TestBucketConcurrentAllowRace(t *testing.T) {
	b := NewBucket(LoginPerClientPerMinute, LoginPerClientBurst)

	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed, denied := 0, 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _ := b.Allow()
			mu.Lock()
			if ok {
				allowed++
			} else {
				denied++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if allowed != LoginPerClientBurst {
		t.Errorf("concurrent grants: expected exactly %d ok, got %d (denied=%d)", LoginPerClientBurst, allowed, denied)
	}
	if denied != workers-LoginPerClientBurst {
		t.Errorf("concurrent denials: expected %d, got %d", workers-LoginPerClientBurst, denied)
	}
}

// TestClientLimiterConcurrentDistinctKeysRace: concurrent keys over the
// ClientLimiter neither overwrite each other nor corrupt the map (race
// covered by -race); all fresh keys are granted.
func TestClientLimiterConcurrentDistinctKeysRace(t *testing.T) {
	c := NewClient(LoginPerClientPerMinute, LoginPerClientBurst)

	const clients = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount := 0

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// The even goroutines use their own keys (exercise of the
			// concurrent map); the odd ones dispute the same shared key
			// (exercise of the shared bucket). Both paths under -race.
			key := "203.0.113.10:1234"
			if n%2 == 0 {
				key = "198.51.100." + strconv.Itoa(n) + ":1234"
			}
			ok, _ := c.Allow(key)
			mu.Lock()
			if ok {
				okCount++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// 10 own keys (1 ok each) + the shared key disputed by 10 goroutines
	// (burst 5 → 5 ok). If the map or the buckets get corrupted, the count
	// does not close at 15.
	if okCount != 15 {
		t.Errorf("concurrent per-client grants: expected 15 ok, got %d", okCount)
	}
}

func TestTooManyRequests(t *testing.T) {
	rec := httptest.NewRecorder()
	tooManyRequests(rec, 15*time.Second)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", rec.Code)
	}
	if retry := rec.Header().Get("Retry-After"); retry != "15" {
		t.Errorf("expected Retry-After 15, got %q", retry)
	}
}

func TestLoginMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	middleware := Login(handler)

	// GET requests must always pass without limiting
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.RemoteAddr = "192.0.2.1:12345"
		rec := httptest.NewRecorder()
		middleware.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /login request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// POST requests should be limited per client IP
	clientIP := "192.0.2.2:12345"
	for i := 0; i < LoginPerClientBurst; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		middleware.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /login request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 6th POST must return 429
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = clientIP
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("6th POST /login: expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}
}

func TestAPIMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	middleware := API(handler)

	clientIP := "192.0.2.3:12345"
	for i := 0; i < APIBurst; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		middleware.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/sites request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// Next request must be limited to 429
	req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
	req.RemoteAddr = clientIP
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("API request after burst: expected 429, got %d", rec.Code)
	}
}

// TestLimitersKeyByIPNotPort: every new TCP connection has a new source
// port, so keying by the full RemoteAddr would give each connection a fresh
// bucket. The login and API limiters must key by the client IP only.
func TestLimitersKeyByIPNotPort(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	cases := []struct {
		name    string
		handler http.Handler
		method  string
		ip      string
		burst   int
	}{
		{"login", Login(ok), http.MethodPost, "192.0.2.50", LoginPerClientBurst},
		{"api", API(ok), http.MethodGet, "192.0.2.51", APIBurst},
		{"api-ipv6", API(ok), http.MethodGet, "2001:db8::51", APIBurst},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i <= tc.burst; i++ {
				req := httptest.NewRequest(tc.method, "/x", nil)
				req.RemoteAddr = net.JoinHostPort(tc.ip, strconv.Itoa(40000+i))
				rec := httptest.NewRecorder()
				tc.handler.ServeHTTP(rec, req)
				if i < tc.burst && rec.Code != http.StatusOK {
					t.Fatalf("request %d inside the burst: expected 200, got %d", i+1, rec.Code)
				}
				if i == tc.burst && rec.Code != http.StatusTooManyRequests {
					t.Fatalf("request %d from the same IP on a new port: expected 429, got %d", i+1, rec.Code)
				}
			}
		})
	}
}

// TestCredentialFailuresBlockOnlyAfterBudget: failed credentials are charged
// per client IP; the check before evaluating a credential consumes nothing,
// so a client with a valid session is never slowed down by its own requests.
func TestCredentialFailuresBlockOnlyAfterBudget(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	c := newClient(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	for i := 0; i < 100; i++ {
		if blocked, _ := c.Blocked("192.0.2.60"); blocked {
			t.Fatal("checking the budget must not consume it")
		}
	}
	for i := 0; i < LoginPerClientBurst; i++ {
		c.Allow("192.0.2.60")
	}
	blocked, retry := c.Blocked("192.0.2.60")
	if !blocked || retry != 12*time.Second {
		t.Fatalf("after %d failures: expected blocked with Retry-After 12s, got %v %v", LoginPerClientBurst, blocked, retry)
	}
	if blocked, _ := c.Blocked("192.0.2.61"); blocked {
		t.Fatal("another client must keep its own budget")
	}
	now = t0.Add(12 * time.Second)
	if blocked, _ := c.Blocked("192.0.2.60"); blocked {
		t.Fatal("one refilled token must unblock the client")
	}
}

// TestCredentialGuardHelpers: CredentialBlocked/CredentialFailed share one
// per-IP budget, independent of the POST /login limiter.
func TestCredentialGuardHelpers(t *testing.T) {
	ResetCredentialFailures()
	t.Cleanup(ResetCredentialFailures)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.70:1111"
	for i := 0; i < LoginPerClientBurst; i++ {
		if blocked, _ := CredentialBlocked(req); blocked {
			t.Fatalf("failure %d: blocked too early", i+1)
		}
		other := req.Clone(req.Context())
		other.RemoteAddr = "192.0.2.70:" + strconv.Itoa(2000+i)
		CredentialFailed(other)
	}
	if blocked, retry := CredentialBlocked(req); !blocked || retry < time.Second {
		t.Fatalf("expected the IP to be blocked after %d failures on different ports, got %v %v", LoginPerClientBurst, blocked, retry)
	}
}
