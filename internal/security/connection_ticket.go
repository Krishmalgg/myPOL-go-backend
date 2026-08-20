package security

import (
	"crypto/rand"
	"encoding/base64"
)

// TicketBytes is the entropy behind a connection ticket. 32 bytes is far beyond
// guessing range for a credential that lives 30 seconds and works once.
const TicketBytes = 32

// NewTicketValue returns a cryptographically random, URL-safe ticket.
//
// crypto/rand, never math/rand: this is a bearer credential, so a predictable
// generator would let anyone mint their own. Base64url because the value is
// carried in a query string at connect time.
func NewTicketValue() (string, error) {
	buffer := make([]byte, TicketBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
