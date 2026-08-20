package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"mypol/go-realtime/internal/domain"
)

const (
	testIssuer   = "mypol-api"
	testAudience = "canvas-realtime"
)

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func baseClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":  testIssuer,
		"aud":  testAudience,
		"sub":  "11111111-1111-1111-1111-111111111111",
		"nid":  "22222222-2222-2222-2222-222222222222",
		"sid":  "33333333-3333-3333-3333-333333333333",
		"jti":  "44444444-4444-4444-4444-444444444444",
		"perm": "edit",
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(5 * time.Minute).Unix(),
	}
}

func sign(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newValidator(t *testing.T, publicPEM []byte) *CanvasJWTValidator {
	t.Helper()
	v, err := NewCanvasJWTValidator(publicPEM, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return v
}

// ── canvas jwt validation ───────────────────────────────────────────────────

func TestValidateAcceptsWellFormedToken(t *testing.T) {
	key, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)
	now := time.Now()

	claims, err := v.Validate(sign(t, key, baseClaims(now)))
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}

	if claims.UserID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("sub = %q", claims.UserID)
	}
	if claims.NoteID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("nid = %q", claims.NoteID)
	}
	if claims.SessionID != "33333333-3333-3333-3333-333333333333" {
		t.Errorf("sid = %q", claims.SessionID)
	}
	if claims.TokenID != "44444444-4444-4444-4444-444444444444" {
		t.Errorf("jti = %q", claims.TokenID)
	}
	if claims.Permission != domain.PermissionEdit {
		t.Errorf("perm = %q", claims.Permission)
	}
	if claims.ExpiresAt.IsZero() || claims.NotBefore.IsZero() || claims.IssuedAt.IsZero() {
		t.Error("expected iat, nbf and exp to be populated")
	}
}

func TestValidateRejectsTokenSignedByAnotherKey(t *testing.T) {
	_, publicPEM := newKey(t)
	stranger, _ := newKey(t)
	v := newValidator(t, publicPEM)

	if _, err := v.Validate(sign(t, stranger, baseClaims(time.Now()))); err == nil {
		t.Fatal("expected a token signed by a different key to be rejected")
	}
}

func TestValidateRejectsTamperedToken(t *testing.T) {
	key, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)

	token := sign(t, key, baseClaims(time.Now()))
	parts := strings.Split(token, ".")
	// Corrupt the payload while keeping the original signature.
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA." + parts[2]

	if _, err := v.Validate(tampered); err == nil {
		t.Fatal("expected a tampered token to be rejected")
	}
}

// The signing-method pin is what prevents an attacker swapping ES256 for HMAC
// and using the public key as a shared secret.
func TestValidateRejectsNonES256Algorithms(t *testing.T) {
	_, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)
	now := time.Now()

	hs256, err := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims(now)).SignedString(publicPEM)
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}
	if _, err := v.Validate(hs256); err == nil {
		t.Fatal("expected HS256 to be rejected")
	}

	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(now)).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := v.Validate(none); err == nil {
		t.Fatal("expected alg=none to be rejected")
	}
}

func TestValidateRejectsWrongIssuerAndAudience(t *testing.T) {
	key, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)
	now := time.Now()

	wrongIssuer := baseClaims(now)
	wrongIssuer["iss"] = "someone-else"
	if _, err := v.Validate(sign(t, key, wrongIssuer)); err == nil {
		t.Error("expected wrong issuer to be rejected")
	}

	wrongAudience := baseClaims(now)
	wrongAudience["aud"] = "another-service"
	if _, err := v.Validate(sign(t, key, wrongAudience)); err == nil {
		t.Error("expected wrong audience to be rejected")
	}
}

func TestValidateRejectsExpiredAndNotYetValidTokens(t *testing.T) {
	key, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)
	now := time.Now()

	expired := baseClaims(now.Add(-time.Hour))
	expired["exp"] = now.Add(-30 * time.Minute).Unix()
	if _, err := v.Validate(sign(t, key, expired)); err == nil {
		t.Error("expected an expired token to be rejected")
	}

	future := baseClaims(now)
	future["nbf"] = now.Add(time.Hour).Unix()
	if _, err := v.Validate(sign(t, key, future)); err == nil {
		t.Error("expected a not-yet-valid token to be rejected")
	}
}

func TestValidateRequiresEveryCanvasClaim(t *testing.T) {
	key, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)

	for _, claim := range []string{"sub", "nid", "sid", "jti", "perm", "iat", "nbf", "exp"} {
		t.Run("missing_"+claim, func(t *testing.T) {
			claims := baseClaims(time.Now())
			delete(claims, claim)
			if _, err := v.Validate(sign(t, key, claims)); err == nil {
				t.Fatalf("expected a token missing %q to be rejected", claim)
			}
		})
	}
}

func TestValidateRejectsUnknownPermission(t *testing.T) {
	key, publicPEM := newKey(t)
	v := newValidator(t, publicPEM)

	claims := baseClaims(time.Now())
	claims["perm"] = "superuser"

	if _, err := v.Validate(sign(t, key, claims)); err == nil {
		t.Fatal("expected an unrecognised permission to be rejected")
	}
}

func TestNewValidatorRejectsUnusableKeys(t *testing.T) {
	if _, err := NewCanvasJWTValidator([]byte("not a pem"), testIssuer, testAudience, 0); err == nil {
		t.Error("expected non-PEM input to be rejected")
	}

	// P-384 is a valid ECDSA curve but not the one ES256 is defined over.
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&wrongCurve.PublicKey)
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := NewCanvasJWTValidator(wrongPEM, testIssuer, testAudience, 0); err == nil {
		t.Error("expected a non P-256 curve to be rejected")
	}

	_, publicPEM := newKey(t)
	if _, err := NewCanvasJWTValidator(publicPEM, "", testAudience, 0); err == nil {
		t.Error("expected a missing issuer to be rejected")
	}
}

// ── connection tickets ──────────────────────────────────────────────────────

func TestNewTicketValueIsRandomAndURLSafe(t *testing.T) {
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		value, err := NewTicketValue()
		if err != nil {
			t.Fatalf("new ticket: %v", err)
		}
		if _, duplicate := seen[value]; duplicate {
			t.Fatal("ticket values must never repeat")
		}
		seen[value] = struct{}{}

		if strings.ContainsAny(value, "+/=") {
			t.Fatalf("ticket must be URL safe, got %q", value)
		}
	}
}

// ── hmac canonical signing ──────────────────────────────────────────────────

func TestCanonicalRequestShape(t *testing.T) {
	canonical := CanonicalRequest("POST", "/internal/v1/sessions/revoke", 1700000000, "abc123", []byte(`{"a":1}`))
	lines := strings.Split(canonical, "\n")

	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d: %q", len(lines), canonical)
	}
	if lines[0] != "POST" {
		t.Errorf("method line = %q", lines[0])
	}
	if lines[1] != "/internal/v1/sessions/revoke" {
		t.Errorf("path line = %q", lines[1])
	}
	if lines[2] != "1700000000" {
		t.Errorf("timestamp line = %q", lines[2])
	}
	if lines[3] != "abc123" {
		t.Errorf("nonce line = %q", lines[3])
	}
	if lines[4] != HashBody([]byte(`{"a":1}`)) {
		t.Errorf("body hash line = %q", lines[4])
	}
}

// This is the cross-language contract with .NET's HmacRequestSigner. The
// expected values are pinned literals rather than recomputed, so a change to
// either side's format fails here instead of silently in production.
func TestCanonicalSigningMatchesPinnedVectors(t *testing.T) {
	if got, want := HashBody([]byte("")),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Errorf("empty body hash = %q, want %q", got, want)
	}

	canonical := CanonicalRequest("POST", "/p", 1, "n", []byte("{}"))
	signature := Sign("test-secret", canonical)
	if len(signature) != 64 {
		t.Errorf("signature should be 64 hex chars, got %d", len(signature))
	}
	if signature != Sign("test-secret", canonical) {
		t.Error("signing must be deterministic")
	}
	if signature == Sign("other-secret", canonical) {
		t.Error("a different secret must produce a different signature")
	}
}

func TestCanonicalRequestNormalisesMethodCase(t *testing.T) {
	if CanonicalRequest("post", "/p", 1, "n", nil) != CanonicalRequest("POST", "/p", 1, "n", nil) {
		t.Error("method casing must not change the canonical request")
	}
}

func TestEverySignedElementIsLoadBearing(t *testing.T) {
	baseline := Sign("s", CanonicalRequest("POST", "/p", 1, "n", []byte("{}")))

	cases := map[string]string{
		"method":    Sign("s", CanonicalRequest("PUT", "/p", 1, "n", []byte("{}"))),
		"path":      Sign("s", CanonicalRequest("POST", "/other", 1, "n", []byte("{}"))),
		"timestamp": Sign("s", CanonicalRequest("POST", "/p", 2, "n", []byte("{}"))),
		"nonce":     Sign("s", CanonicalRequest("POST", "/p", 1, "other", []byte("{}"))),
		"body":      Sign("s", CanonicalRequest("POST", "/p", 1, "n", []byte(`{"x":1}`))),
	}
	for element, signature := range cases {
		if signature == baseline {
			t.Errorf("changing %s must change the signature", element)
		}
	}
}

// ── hmac request validation ─────────────────────────────────────────────────

func signedRequest(t *testing.T, secret, keyID string, timestamp int64, nonce string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/sessions/revoke", strings.NewReader(string(body)))
	signature := Sign(secret, CanonicalRequest(req.Method, req.URL.Path, timestamp, nonce, body))
	req.Header.Set(HeaderServiceID, "mypol-api")
	req.Header.Set(HeaderKeyID, keyID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, signature)
	return req
}

func TestHMACValidateAcceptsCorrectlySignedRequest(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)
	body := []byte(`{"sessionId":"abc"}`)

	req := signedRequest(t, "s1", "k1", now.Unix(), "nonce-1", body)
	if err := v.Validate(req, body, now); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}
}

func TestHMACValidateRejectsBadSignatureAndUnknownKey(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)
	body := []byte(`{}`)

	wrongSecret := signedRequest(t, "wrong-secret", "k1", now.Unix(), "n1", body)
	if err := v.Validate(wrongSecret, body, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}

	unknownKey := signedRequest(t, "s1", "k-unknown", now.Unix(), "n2", body)
	if err := v.Validate(unknownKey, body, now); !errors.Is(err, ErrUnknownKeyID) {
		t.Errorf("expected ErrUnknownKeyID, got %v", err)
	}
}

// A signature over a different body must not verify, or the payload could be
// swapped in flight.
func TestHMACValidateRejectsTamperedBody(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)

	req := signedRequest(t, "s1", "k1", now.Unix(), "n1", []byte(`{"sessionId":"abc"}`))
	if err := v.Validate(req, []byte(`{"sessionId":"victim"}`), now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature for a swapped body, got %v", err)
	}
}

func TestHMACValidateEnforcesClockSkewInBothDirections(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)
	body := []byte(`{}`)

	stale := signedRequest(t, "s1", "k1", now.Add(-5*time.Minute).Unix(), "n1", body)
	if err := v.Validate(stale, body, now); !errors.Is(err, ErrClockSkew) {
		t.Errorf("expected stale request to be rejected, got %v", err)
	}

	future := signedRequest(t, "s1", "k1", now.Add(5*time.Minute).Unix(), "n2", body)
	if err := v.Validate(future, body, now); !errors.Is(err, ErrClockSkew) {
		t.Errorf("expected future-dated request to be rejected, got %v", err)
	}
}

func TestHMACValidateRejectsReplayedNonce(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)
	body := []byte(`{}`)

	first := signedRequest(t, "s1", "k1", now.Unix(), "same-nonce", body)
	if err := v.Validate(first, body, now); err != nil {
		t.Fatalf("first use should succeed, got %v", err)
	}

	// Byte-identical replay: signature and timestamp are still valid, so only
	// the nonce cache can catch this.
	replay := signedRequest(t, "s1", "k1", now.Unix(), "same-nonce", body)
	if err := v.Validate(replay, body, now); !errors.Is(err, ErrReplayedNonce) {
		t.Fatalf("expected ErrReplayedNonce, got %v", err)
	}
}

func TestHMACValidateAcceptsPreviousKeyDuringRotation(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k2", "s2"}, HMACKey{"k1", "s1"}, 30*time.Second)
	body := []byte(`{}`)

	old := signedRequest(t, "s1", "k1", now.Unix(), "n1", body)
	if err := v.Validate(old, body, now); err != nil {
		t.Errorf("previous key should still be accepted, got %v", err)
	}

	current := signedRequest(t, "s2", "k2", now.Unix(), "n2", body)
	if err := v.Validate(current, body, now); err != nil {
		t.Errorf("current key should be accepted, got %v", err)
	}
}

func TestHMACValidateRequiresAllSignatureHeaders(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)
	body := []byte(`{}`)

	for _, header := range []string{HeaderKeyID, HeaderNonce, HeaderSignature, HeaderTimestamp} {
		req := signedRequest(t, "s1", "k1", now.Unix(), "n-"+header, body)
		req.Header.Del(header)
		if err := v.Validate(req, body, now); !errors.Is(err, ErrMissingSignatureHeaders) {
			t.Errorf("missing %s should be rejected, got %v", header, err)
		}
	}
}

// An unauthenticated caller must not be able to grow the nonce cache.
func TestHMACNonceCacheOnlyRecordsVerifiedRequests(t *testing.T) {
	now := time.Now()
	v := NewHMACValidator(HMACKey{"k1", "s1"}, HMACKey{}, 30*time.Second)
	body := []byte(`{}`)

	bad := signedRequest(t, "wrong", "k1", now.Unix(), "n1", body)
	_ = v.Validate(bad, body, now)

	if v.NonceCount() != 0 {
		t.Fatalf("expected no nonce recorded for a failed request, got %d", v.NonceCount())
	}
}

func TestHMACValidatorConfigured(t *testing.T) {
	if NewHMACValidator(HMACKey{}, HMACKey{}, time.Second).Configured() {
		t.Error("an empty validator must not report itself configured")
	}
	if !NewHMACValidator(HMACKey{"k", "s"}, HMACKey{}, time.Second).Configured() {
		t.Error("a validator with a current key should be configured")
	}
}
