package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func settings() BootstrapLimitSettings {
	return BootstrapLimitSettings{
		PerUserPerMinute: 30,
		PerUserBurst:     10,
		PerIPPerMinute:   600,
		PerIPBurst:       100,
	}
}

func TestPerUserBudgetAllowsABurstThenThrottles(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	for i := 0; i < 10; i++ {
		if !limiter.AllowUser("user-1", now) {
			t.Fatalf("burst request %d should be allowed", i)
		}
	}
	if limiter.AllowUser("user-1", now) {
		t.Fatal("expected the user's burst to be exhausted")
	}
}

func TestPerUserBudgetsAreIndependent(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	for i := 0; i < 10; i++ {
		limiter.AllowUser("noisy", now)
	}

	if !limiter.AllowUser("quiet", now) {
		t.Fatal("one user's throttling must not affect another")
	}
}

// The whole reason the per-IP ceiling is generous: a campus or office NAT
// carries hundreds of legitimate users behind one address. A tight limit — the
// tempting 10/minute — would lock all of them out.
func TestPerIPCeilingToleratesManyUsersBehindOneNAT(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	allowed := 0
	for i := 0; i < 100; i++ {
		if limiter.AllowIP("203.0.113.7", now) {
			allowed++
		}
	}

	if allowed != 100 {
		t.Fatalf("allowed %d of 100 requests from a shared address", allowed)
	}
}

func TestPerIPCeilingStillStopsAFlood(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	for i := 0; i < 100; i++ {
		limiter.AllowIP("203.0.113.7", now)
	}

	if limiter.AllowIP("203.0.113.7", now) {
		t.Fatal("the ceiling should eventually bite")
	}
}

func TestBudgetsRefillOverTime(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	for i := 0; i < 10; i++ {
		limiter.AllowUser("user-1", now)
	}

	// 30/minute is one every two seconds.
	if !limiter.AllowUser("user-1", now.Add(3*time.Second)) {
		t.Fatal("the budget should refill")
	}
}

func TestEmptyIdentifiersAreNotThrottled(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	// Nothing to attribute the request to; the other dimension still applies.
	if !limiter.AllowUser("", now) || !limiter.AllowIP("", now) {
		t.Fatal("an unattributable request must not be blocked here")
	}
}

// Without a sweep the maps would grow with every address ever seen.
func TestFullBucketsAreReclaimed(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(settings(), now)

	limiter.AllowIP("203.0.113.1", now)
	limiter.AllowIP("203.0.113.2", now)
	if limiter.TrackedIPs() != 2 {
		t.Fatalf("tracked = %d, want 2", limiter.TrackedIPs())
	}

	// Long enough for both to refill completely, so they carry no state worth
	// keeping.
	limiter.AllowIP("203.0.113.3", now.Add(10*time.Minute))

	if limiter.TrackedIPs() > 1 {
		t.Errorf("expected refilled buckets to be reclaimed, tracked = %d", limiter.TrackedIPs())
	}
}

func TestClientIPPrefersTheOriginalCaller(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
	request.RemoteAddr = "10.0.0.5:44321"

	if got := ClientIP(request); got != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want the remote host", got)
	}

	// Left-most entry is the original client; the rest are proxies.
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 70.41.3.18")
	if got := ClientIP(request); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the left-most forwarded address", got)
	}

	request.Header.Del("X-Forwarded-For")
	request.Header.Set("X-Real-Ip", "198.51.100.4")
	if got := ClientIP(request); got != "198.51.100.4" {
		t.Errorf("ClientIP = %q, want the real-ip header", got)
	}
}

// A missing configuration value must fail open. These are abuse ceilings, not
// security controls — a config slip locking out every user is far worse than a
// temporarily absent ceiling.
func TestUnconfiguredLimitsAllowEverything(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := NewBootstrapLimiter(BootstrapLimitSettings{}, now)

	for i := 0; i < 1000; i++ {
		if !limiter.AllowIP("203.0.113.7", now) || !limiter.AllowUser("user-1", now) {
			t.Fatal("an unconfigured limiter must not block anything")
		}
	}
}
