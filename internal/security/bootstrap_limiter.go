package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BootstrapLimiter throttles session creation.
//
// Two dimensions, and the split matters. The **per-user** limit is the real
// control: a legitimate client bootstraps once per note, so anything beyond a
// handful a minute is a bug or an attack, and the identity comes from a signed
// token that cannot be spoofed.
//
// The **per-IP** limit is only an abuse ceiling, and is deliberately generous.
// A university, an office or a mobile carrier puts hundreds of genuine users
// behind one NAT address, so a tight per-IP rule — the tempting "10 a minute" —
// would lock out an entire campus while barely inconveniencing an attacker who
// can rotate addresses.
type BootstrapLimiter struct {
	mu sync.Mutex

	perUser map[string]*TokenBucket
	perIP   map[string]*TokenBucket

	userRate, userBurst float64
	ipRate, ipBurst     float64

	lastSweep time.Time
}

// BootstrapLimitSettings are per-minute rates with a burst allowance.
type BootstrapLimitSettings struct {
	PerUserPerMinute float64
	PerUserBurst     float64
	PerIPPerMinute   float64
	PerIPBurst       float64
}

func NewBootstrapLimiter(settings BootstrapLimitSettings, now time.Time) *BootstrapLimiter {
	return &BootstrapLimiter{
		perUser:   make(map[string]*TokenBucket),
		perIP:     make(map[string]*TokenBucket),
		userRate:  settings.PerUserPerMinute / 60,
		userBurst: settings.PerUserBurst,
		ipRate:    settings.PerIPPerMinute / 60,
		ipBurst:   settings.PerIPBurst,
		lastSweep: now,
	}
}

// AllowIP is checked before a token is even parsed, so an unauthenticated
// flood cannot make the server do signature verification work.
func (l *BootstrapLimiter) AllowIP(ip string, now time.Time) bool {
	// An unconfigured limit means "no ceiling", never "block everything". These
	// are abuse ceilings, not security controls, so a missing value must fail
	// open — the alternative is a config slip locking out every user.
	if ip == "" || l.ipRate <= 0 || l.ipBurst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)
	bucket, ok := l.perIP[ip]
	if !ok {
		bucket = NewTokenBucket(l.ipRate, l.ipBurst, now)
		l.perIP[ip] = bucket
	}
	return bucket.Allow(now)
}

// AllowUser is checked after the token verifies, when identity is trustworthy.
func (l *BootstrapLimiter) AllowUser(userID string, now time.Time) bool {
	if userID == "" || l.userRate <= 0 || l.userBurst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.perUser[userID]
	if !ok {
		bucket = NewTokenBucket(l.userRate, l.userBurst, now)
		l.perUser[userID] = bucket
	}
	return bucket.Allow(now)
}

// sweepLocked discards buckets that have refilled completely: a full bucket is
// indistinguishable from a fresh one, so keeping it only costs memory. Without
// this the maps would grow with every address ever seen.
func (l *BootstrapLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now

	for key, bucket := range l.perIP {
		if bucket.TokensAt(now) >= l.ipBurst {
			delete(l.perIP, key)
		}
	}
	for key, bucket := range l.perUser {
		if bucket.TokensAt(now) >= l.userBurst {
			delete(l.perUser, key)
		}
	}
}

// TrackedIPs and TrackedUsers expose sizes for metrics and tests.
func (l *BootstrapLimiter) TrackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.perIP)
}

func (l *BootstrapLimiter) TrackedUsers() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.perUser)
}

// ClientIP extracts the caller's address.
//
// X-Forwarded-For is honoured only because this sits behind a proxy in
// production; the *left-most* entry is the original client. Note this header is
// caller-controlled when the service is exposed directly, which is another
// reason the per-IP limit must never be the only control.
func ClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first, _, found := strings.Cut(forwarded, ","); found {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(forwarded)
	}
	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return strings.TrimSpace(real)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
