package security

import (
	"sync"
	"time"

	"mypol/go-realtime/internal/domain"
)

// TokenBucket is a per-connection rate limiter.
//
// A bucket rather than a fixed per-second counter because canvas traffic is
// bursty by nature: a pen stroke emits a rapid batch and then nothing. A rigid
// counter would reject the legitimate burst while a bucket absorbs it, and
// still holds the sustained rate down over time.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	refill   float64 // tokens per second
	last     time.Time
}

func NewTokenBucket(ratePerSecond, burst float64, now time.Time) *TokenBucket {
	return &TokenBucket{
		tokens:   burst,
		capacity: burst,
		refill:   ratePerSecond,
		last:     now,
	}
}

// Allow consumes one token, reporting whether the caller may proceed.
func (b *TokenBucket) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.capacity, b.tokens+elapsed*b.refill)
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Tokens exposes the current allowance for tests and metrics.
func (b *TokenBucket) Tokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}

// RateLimits holds the per-class buckets for one connection.
//
// Separate buckets on purpose: a flood of cursor frames must not be able to
// starve a signalling message or an ink commit, which is exactly what a single
// shared bucket would allow.
type RateLimits struct {
	ephemeral *TokenBucket
	reliable  *TokenBucket
	signaling *TokenBucket
}

// RateLimitSettings is the tuning surface, sourced from configuration.
type RateLimitSettings struct {
	EphemeralPerSecond float64
	EphemeralBurst     float64
	ReliablePerSecond  float64
	ReliableBurst      float64
	SignalingPerSecond float64
	SignalingBurst     float64
}

func NewRateLimits(settings RateLimitSettings, now time.Time) *RateLimits {
	return &RateLimits{
		ephemeral: NewTokenBucket(settings.EphemeralPerSecond, settings.EphemeralBurst, now),
		reliable:  NewTokenBucket(settings.ReliablePerSecond, settings.ReliableBurst, now),
		signaling: NewTokenBucket(settings.SignalingPerSecond, settings.SignalingBurst, now),
	}
}

// Allow applies the bucket matching the event's class.
func (r *RateLimits) Allow(class domain.EventClass, now time.Time) bool {
	switch class {
	case domain.ClassEphemeral:
		return r.ephemeral.Allow(now)
	case domain.ClassSignaling:
		return r.signaling.Allow(now)
	default:
		return r.reliable.Allow(now)
	}
}
