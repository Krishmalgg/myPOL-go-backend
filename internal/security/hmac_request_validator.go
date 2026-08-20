package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Headers carrying the internal-control signature. These mirror
// HmacRequestSigner on the .NET side exactly.
const (
	HeaderServiceID = "X-Service-Id"
	HeaderKeyID     = "X-Key-Id"
	HeaderTimestamp = "X-Timestamp"
	HeaderNonce     = "X-Nonce"
	HeaderSignature = "X-Signature"
)

var (
	ErrMissingSignatureHeaders = errors.New("internal control request is missing signature headers")
	ErrUnknownKeyID            = errors.New("unknown internal control key id")
	ErrClockSkew               = errors.New("internal control timestamp outside allowed skew")
	ErrReplayedNonce           = errors.New("internal control nonce has already been used")
	ErrBadSignature            = errors.New("internal control signature does not match")
)

// HMACKey is one accepted signing key. Two are held at once so a rotation can
// overlap: callers signed with the outgoing secret stay valid until it is
// retired.
type HMACKey struct {
	KeyID  string
	Secret string
}

// CanonicalRequest builds the exact string that gets signed:
//
//	METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256(BODY)
//
// This is a cross-language contract — .NET builds the identical string — so the
// format must not drift on either side. Signing a canonical form rather than
// raw bytes means header ordering and transport framing cannot change the
// signature, while every element that matters is still covered.
func CanonicalRequest(method, path string, timestamp int64, nonce string, body []byte) string {
	return strings.Join([]string{
		strings.ToUpper(method),
		path,
		strconv.FormatInt(timestamp, 10),
		nonce,
		HashBody(body),
	}, "\n")
}

// HashBody returns lowercase hex SHA-256 of the body.
func HashBody(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// Sign returns lowercase hex HMAC-SHA256 of the canonical request.
func Sign(secret, canonical string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACValidator authenticates trusted .NET -> Go control calls.
//
// Three defences, each covering what the others cannot: the signature proves
// the caller holds the secret, the timestamp bounds how long a captured request
// stays usable, and the nonce cache rejects an exact replay inside that window.
// A signature alone would be replayable forever.
type HMACValidator struct {
	current  HMACKey
	previous HMACKey
	maxSkew  time.Duration

	mu     sync.Mutex
	nonces map[string]time.Time
}

func NewHMACValidator(current, previous HMACKey, maxSkew time.Duration) *HMACValidator {
	return &HMACValidator{
		current:  current,
		previous: previous,
		maxSkew:  maxSkew,
		nonces:   make(map[string]time.Time),
	}
}

// Configured reports whether at least one usable key is present. When false the
// internal endpoints refuse everything rather than accepting unsigned calls.
func (v *HMACValidator) Configured() bool {
	return v.current.KeyID != "" && v.current.Secret != ""
}

// Validate authenticates a request against its already-read body.
//
// The body is passed in rather than read here because it must also reach the
// handler, and an http.Request body can only be consumed once.
func (v *HMACValidator) Validate(r *http.Request, body []byte, now time.Time) error {
	keyID := r.Header.Get(HeaderKeyID)
	nonce := r.Header.Get(HeaderNonce)
	signature := r.Header.Get(HeaderSignature)
	timestampRaw := r.Header.Get(HeaderTimestamp)

	if keyID == "" || nonce == "" || signature == "" || timestampRaw == "" {
		return ErrMissingSignatureHeaders
	}

	secret, err := v.secretFor(keyID)
	if err != nil {
		return err
	}

	timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: unparseable timestamp", ErrClockSkew)
	}

	// Absolute difference: a request from the future is as suspicious as a
	// stale one, and usually means the clocks disagree.
	drift := now.Sub(time.Unix(timestamp, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > v.maxSkew {
		return fmt.Errorf("%w: %s", ErrClockSkew, drift)
	}

	canonical := CanonicalRequest(r.Method, r.URL.Path, timestamp, nonce, body)
	expected := Sign(secret, canonical)

	// Constant time: a byte-by-byte comparison leaks how much of the signature
	// was right through timing, which is enough to forge one byte at a time.
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrBadSignature
	}

	// Only after the signature verifies, so an unauthenticated caller cannot
	// fill the nonce cache.
	if !v.rememberNonce(nonce, now) {
		return ErrReplayedNonce
	}

	return nil
}

func (v *HMACValidator) secretFor(keyID string) (string, error) {
	switch {
	case v.current.KeyID != "" && keyID == v.current.KeyID:
		return v.current.Secret, nil
	case v.previous.KeyID != "" && keyID == v.previous.KeyID:
		return v.previous.Secret, nil
	default:
		return "", ErrUnknownKeyID
	}
}

// rememberNonce records a nonce, returning false if it was already used. Entries
// are dropped once they fall outside the skew window, because a request that old
// is rejected on its timestamp anyway — so the cache stays bounded by request
// rate rather than by uptime.
func (v *HMACValidator) rememberNonce(nonce string, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, seen := v.nonces[nonce]; seen {
		return false
	}

	cutoff := now.Add(-2 * v.maxSkew)
	for value, at := range v.nonces {
		if at.Before(cutoff) {
			delete(v.nonces, value)
		}
	}

	v.nonces[nonce] = now
	return true
}

// NonceCount exposes cache size for tests and metrics.
func (v *HMACValidator) NonceCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.nonces)
}
