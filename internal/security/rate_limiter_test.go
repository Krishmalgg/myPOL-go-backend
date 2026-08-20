package security

import (
	"testing"
	"time"

	"mypol/go-realtime/internal/domain"
)

func TestBucketAllowsBurstThenThrottles(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := NewTokenBucket(10, 5, now)

	// A burst is allowed up to capacity — canvas traffic arrives in bursts and a
	// rigid per-second counter would reject legitimate drawing.
	for i := 0; i < 5; i++ {
		if !bucket.Allow(now) {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if bucket.Allow(now) {
		t.Fatal("the bucket should be empty after its burst")
	}
}

func TestBucketRefillsOverTime(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := NewTokenBucket(10, 5, now)

	for i := 0; i < 5; i++ {
		bucket.Allow(now)
	}

	// Half a second at 10/s refills five tokens.
	later := now.Add(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if !bucket.Allow(later) {
			t.Fatalf("token %d should have refilled", i)
		}
	}
}

func TestBucketNeverExceedsCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	bucket := NewTokenBucket(10, 5, now)

	// A long idle period must not bank unlimited allowance.
	bucket.Allow(now.Add(time.Hour))

	if tokens := bucket.Tokens(); tokens > 5 {
		t.Fatalf("tokens = %f, must not exceed capacity", tokens)
	}
}

// A flood of cursor frames must not be able to starve an ink commit.
func TestClassesHaveIndependentBuckets(t *testing.T) {
	now := time.Unix(1000, 0)
	limits := NewRateLimits(RateLimitSettings{
		EphemeralPerSecond: 1, EphemeralBurst: 2,
		ReliablePerSecond: 1, ReliableBurst: 2,
		SignalingPerSecond: 1, SignalingBurst: 2,
	}, now)

	// Exhaust the ephemeral bucket.
	for i := 0; i < 2; i++ {
		limits.Allow(domain.ClassEphemeral, now)
	}
	if limits.Allow(domain.ClassEphemeral, now) {
		t.Fatal("ephemeral should be exhausted")
	}

	if !limits.Allow(domain.ClassReliable, now) {
		t.Error("reliable traffic must be unaffected by an ephemeral flood")
	}
	if !limits.Allow(domain.ClassSignaling, now) {
		t.Error("signaling must be unaffected by an ephemeral flood")
	}
}

func TestDefaultEphemeralRateAllowsUltraProfileBatching(t *testing.T) {
	now := time.Unix(1000, 0)
	// 8ms batching approaches 125 batches/second; the default sustained rate is
	// 160/s specifically so that legitimate drawing is not throttled.
	bucket := NewTokenBucket(160, 240, now)

	allowed := 0
	for i := 0; i < 125; i++ {
		if bucket.Allow(now.Add(time.Duration(i*8) * time.Millisecond)) {
			allowed++
		}
	}

	if allowed != 125 {
		t.Fatalf("allowed %d of 125 batches in one second", allowed)
	}
}
