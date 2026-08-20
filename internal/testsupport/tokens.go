// Package testsupport provides helpers for minting canvas access tokens in
// tests. It lives outside _test.go files so that suites in several packages can
// share it; nothing in the production binary imports it.
package testsupport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Issuer   = "mypol-api"
	Audience = "canvas-realtime"
)

// KeyPair stands in for the .NET signing key and the public half Go is given.
type KeyPair struct {
	Private   *ecdsa.PrivateKey
	PublicPEM []byte
}

func NewKeyPair() (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Private:   key,
		PublicPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}, nil
}

// Sign produces a compact ES256 token, mirroring what the .NET issuer emits.
func (k *KeyPair) Sign(claims jwt.MapClaims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(k.Private)
}

// ClaimsInput describes a token to mint. Zero values fall back to sensible
// defaults so a test only states what it actually cares about.
type ClaimsInput struct {
	UserID     string
	NoteID     string
	SessionID  string
	TokenID    string
	Permission string
	IssuedAt   time.Time
	TTL        time.Duration
}

// Claims builds a complete, valid claim set.
func Claims(in ClaimsInput) jwt.MapClaims {
	if in.UserID == "" {
		in.UserID = "11111111-1111-1111-1111-111111111111"
	}
	if in.NoteID == "" {
		in.NoteID = "22222222-2222-2222-2222-222222222222"
	}
	if in.SessionID == "" {
		in.SessionID = "33333333-3333-3333-3333-333333333333"
	}
	if in.TokenID == "" {
		in.TokenID = "44444444-4444-4444-4444-444444444444"
	}
	if in.Permission == "" {
		in.Permission = "edit"
	}
	if in.IssuedAt.IsZero() {
		in.IssuedAt = time.Now()
	}
	if in.TTL == 0 {
		in.TTL = 5 * time.Minute
	}

	return jwt.MapClaims{
		"iss":  Issuer,
		"aud":  Audience,
		"sub":  in.UserID,
		"nid":  in.NoteID,
		"sid":  in.SessionID,
		"jti":  in.TokenID,
		"perm": in.Permission,
		"iat":  in.IssuedAt.Unix(),
		"nbf":  in.IssuedAt.Unix(),
		"exp":  in.IssuedAt.Add(in.TTL).Unix(),
	}
}
