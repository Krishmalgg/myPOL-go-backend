package domain

import "encoding/json"

// SignalingEnvelope is the part of a WebRTC signalling payload the server needs
// to read. Everything else — SDP, ICE candidate lines — stays opaque: Go is a
// router here, not a participant in the negotiation.
type SignalingEnvelope struct {
	// Target is the recipient's *connection* id, not their user id. One user may
	// hold several connections, and an offer is for exactly one of them.
	Target string `json:"target"`
}

// SignalingTarget extracts the intended recipient from a payload.
//
// Returns empty when absent, which the caller must treat as undeliverable:
// broadcasting an offer to a whole room would have every peer try to answer a
// negotiation that was never meant for them.
func SignalingTarget(payload json.RawMessage) string {
	var parsed SignalingEnvelope
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return ""
	}
	return parsed.Target
}

// IsSignalingEvent reports whether an event participates in peer negotiation.
func IsSignalingEvent(event string) bool {
	return ClassifyEvent(event) == ClassSignaling
}
