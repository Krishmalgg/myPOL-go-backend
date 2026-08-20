package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"mypol/go-realtime/internal/domain"
)

// AlgES256 is the only signature algorithm this service will accept.
const AlgES256 = "ES256"

var (
	ErrInvalidToken   = errors.New("invalid canvas token")
	ErrMissingClaim   = errors.New("canvas token is missing a required claim")
	ErrUnsupportedKey = errors.New("unsupported canvas public key")
)

// CanvasClaims is the validated content of a canvas access token — the answer
// to "who is this, on what, and may they draw", already checked.
type CanvasClaims struct {
	UserID     string
	NoteID     string
	SessionID  string
	TokenID    string
	Permission domain.Permission
	IssuedAt   time.Time
	NotBefore  time.Time
	ExpiresAt  time.Time
}

// tokenClaims mirrors the wire shape. RegisteredClaims supplies iss, sub, aud,
// exp, nbf, iat and jti; the three canvas-specific ones are declared alongside.
type tokenClaims struct {
	NoteID     string `json:"nid"`
	SessionID  string `json:"sid"`
	Permission string `json:"perm"`
	jwt.RegisteredClaims
}

// CanvasJWTValidator verifies tokens minted by the .NET API.
//
// It holds only the ECDSA *public* key. That asymmetry is the point: this
// service can prove a token is genuine but cannot create one, so compromising
// the realtime tier does not yield the ability to forge canvas access.
type CanvasJWTValidator struct {
	publicKey *ecdsa.PublicKey
	issuer    string
	audience  string
	leeway    time.Duration
}

// NewCanvasJWTValidator parses a PEM-encoded SubjectPublicKeyInfo P-256 key.
func NewCanvasJWTValidator(publicKeyPEM []byte, issuer, audience string, leeway time.Duration) (*CanvasJWTValidator, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("canvas jwt issuer and audience are required")
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: not PEM encoded", ErrUnsupportedKey)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected an ECDSA key", ErrUnsupportedKey)
	}
	// ES256 is defined over P-256 specifically; another curve would be a
	// configuration mistake that must not silently half-work.
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: expected curve P-256, got %s", ErrUnsupportedKey, key.Curve.Params().Name)
	}

	return &CanvasJWTValidator{publicKey: key, issuer: issuer, audience: audience, leeway: leeway}, nil
}

// Validate checks signature, algorithm, issuer, audience, lifetime and the
// presence of every claim this service depends on.
func (v *CanvasJWTValidator) Validate(tokenString string) (*CanvasClaims, error) {
	claims := &tokenClaims{}

	_, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(*jwt.Token) (any, error) { return v.publicKey, nil },
		// Pinning the method is what stops an `alg: none` or HMAC-substitution
		// attack, where a forged header tricks the parser into verifying with
		// the public key as if it were a shared secret.
		jwt.WithValidMethods([]string{AlgES256}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	return v.toCanvasClaims(claims)
}

func (v *CanvasJWTValidator) toCanvasClaims(claims *tokenClaims) (*CanvasClaims, error) {
	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if claims.NoteID == "" {
		return nil, fmt.Errorf("%w: nid", ErrMissingClaim)
	}
	if claims.SessionID == "" {
		return nil, fmt.Errorf("%w: sid", ErrMissingClaim)
	}
	if claims.ID == "" {
		return nil, fmt.Errorf("%w: jti", ErrMissingClaim)
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("%w: iat", ErrMissingClaim)
	}
	if claims.NotBefore == nil {
		return nil, fmt.Errorf("%w: nbf", ErrMissingClaim)
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("%w: exp", ErrMissingClaim)
	}

	permission, err := domain.ParsePermission(claims.Permission)
	if err != nil {
		return nil, fmt.Errorf("%w: perm", ErrMissingClaim)
	}

	return &CanvasClaims{
		UserID:     subject,
		NoteID:     claims.NoteID,
		SessionID:  claims.SessionID,
		TokenID:    claims.ID,
		Permission: permission,
		IssuedAt:   claims.IssuedAt.Time,
		NotBefore:  claims.NotBefore.Time,
		ExpiresAt:  claims.ExpiresAt.Time,
	}, nil
}
