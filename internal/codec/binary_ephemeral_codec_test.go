package codec

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"mypol/go-realtime/internal/domain"
)

func TestDecodeClientFrameRestoresQuantizedInk(t *testing.T) {
	writer := newWriter(64)
	writer.header(codeInk, 9, flagHasPressure)
	writer.string("stroke-1")
	writer.varint(2)
	writer.svarint(2009) // 502.25 / 0.25
	writer.svarint(1206) // 301.50 / 0.25
	writer.u8(128)
	writer.svarint(8) // +2 canvas units
	writer.svarint(4) // +1 canvas unit
	writer.u8(153)

	envelope, err := DecodeClientFrame(writer.bytes())
	if err != nil {
		t.Fatalf("DecodeClientFrame: %v", err)
	}
	if envelope.Event != "ink.points" || envelope.Seq == nil || *envelope.Seq != 9 {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}

	var payload inkPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.StrokeID != "stroke-1" || len(payload.Points) != 2 {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if payload.Points[0].X != 502.25 || payload.Points[0].Y != 301.5 {
		t.Fatalf("first point = %#v", payload.Points[0])
	}
	if payload.Points[1].X != 504.25 || payload.Points[1].Y != 302.5 {
		t.Fatalf("second point = %#v", payload.Points[1])
	}
	if payload.Points[0].Pressure == nil || *payload.Points[0].Pressure < 0.49 {
		t.Fatalf("pressure was not restored: %#v", payload.Points[0])
	}
}

func TestDecodeClientFrameRejectsRelayMetadataAndTrailingBytes(t *testing.T) {
	writer := newWriter(32)
	writer.header(codeCursor, 1, flagRelayMetadata)
	writer.string("page-1")
	writer.svarint(4)
	writer.svarint(8)
	if _, err := DecodeClientFrame(writer.bytes()); err == nil {
		t.Fatal("relay metadata flag must not be accepted from a client")
	}

	writer = newWriter(32)
	writer.header(codeCursor, 1, 0)
	writer.string("page-1")
	writer.svarint(4)
	writer.svarint(8)
	writer.u8(99)
	if _, err := DecodeClientFrame(writer.bytes()); err == nil {
		t.Fatal("trailing client data must be rejected")
	}
}

func TestEncodeRelayFrameCarriesTrustedMetadata(t *testing.T) {
	seq := uint64(12)
	actor := "user-1"
	origin := "connection-1"
	payload, _ := json.Marshal(pointerPayload{PageID: "page-1", X: 10.25, Y: 20.5})
	envelope := &domain.Envelope{
		V:         domain.EnvelopeVersion,
		MessageID: "server-message",
		SessionID: "sender-session",
		Channel:   "note:note-1",
		Event:     "cursor.moved",
		ActorID:   &actor,
		Origin:    &origin,
		Seq:       &seq,
		SentAt:    1_700_000_000_123,
		Payload:   payload,
	}

	frame, ok := EncodeRelayFrame(envelope)
	if !ok {
		t.Fatal("cursor preview should have a binary relay frame")
	}
	header, err := readHeader(frame)
	if err != nil || header.code != codeCursor || header.seq != 12 || header.flags&flagRelayMetadata == 0 {
		t.Fatalf("unexpected header: %#v, %v", header, err)
	}

	metadataLength := int(binary.LittleEndian.Uint16(frame[len(frame)-2:]))
	metadataStart := len(frame) - 2 - metadataLength
	metadata := newReader(frame[metadataStart : len(frame)-2])
	messageID, _ := metadata.string()
	sessionID, _ := metadata.string()
	channel, _ := metadata.string()
	actorPresent, _ := metadata.u8()
	actorID, _ := metadata.string()
	originPresent, _ := metadata.u8()
	originID, _ := metadata.string()
	if metadata.remaining() != 8 {
		t.Fatalf("metadata tail length = %d, want sentAt", metadata.remaining())
	}
	sentAt := binary.LittleEndian.Uint64(frame[len(frame)-2-8:])

	if messageID != "server-message" || sessionID != "sender-session" || channel != "note:note-1" ||
		actorPresent != 1 || actorID != actor || originPresent != 1 || originID != origin ||
		sentAt != uint64(envelope.SentAt) {
		t.Fatalf("unexpected relay metadata: %q %q %q %d %q %d %q %d", messageID, sessionID, channel, actorPresent, actorID, originPresent, originID, sentAt)
	}
}

func TestLoadToolCodecHelpersRoundTripClientAndRelayMetadata(t *testing.T) {
	seq := uint64(7)
	payload, _ := json.Marshal(pointerPayload{PageID: "page-1", X: 10, Y: 20})
	client, ok := EncodeClientFrame(&domain.Envelope{
		Event: "cursor.moved", Seq: &seq, Payload: payload,
	})
	if !ok {
		t.Fatal("cursor should encode for a benchmark client")
	}
	decoded, err := DecodeClientFrame(client)
	if err != nil || decoded.Seq == nil || *decoded.Seq != seq {
		t.Fatalf("client frame did not round trip: %#v %v", decoded, err)
	}

	origin := "connection-1"
	relay, ok := EncodeRelayFrame(&domain.Envelope{
		Event: "cursor.moved", Seq: &seq, Origin: &origin, SentAt: 123, Payload: payload,
	})
	if !ok {
		t.Fatal("relay should encode")
	}
	metadata, err := DecodeRelayMetadata(relay)
	if err != nil || len(metadata) != 1 || metadata[0].Origin != origin || metadata[0].Sequence != seq {
		t.Fatalf("relay metadata = %#v, %v", metadata, err)
	}
}

func TestEncodeRelayFrameKeepsReliableEventsJSON(t *testing.T) {
	envelope := &domain.Envelope{Event: "ink.commit", Payload: []byte(`{}`)}
	if _, ok := EncodeRelayFrame(envelope); ok {
		t.Fatal("reliable commit must not be binary")
	}
}

func TestEncodeRelayAggregateKeepsCompleteV1Children(t *testing.T) {
	payload, _ := json.Marshal(pointerPayload{PageID: "page-1", X: 10, Y: 20})
	first := &domain.Envelope{V: domain.EnvelopeVersion, MessageID: "m1", SessionID: "s", Channel: "note:n", Event: "cursor.moved", Payload: payload}
	second := &domain.Envelope{V: domain.EnvelopeVersion, MessageID: "m2", SessionID: "s", Channel: "note:n", Event: "cursor.moved", Payload: payload}

	aggregate, ok := EncodeRelayAggregate([]*domain.Envelope{first, second})
	if !ok || len(aggregate) <= headerSize+2 {
		t.Fatal("two compatible previews should form an aggregate")
	}
	if aggregate[0] != magic || aggregate[1] != version || aggregate[2] != codeAggregate {
		t.Fatalf("unexpected aggregate header: %v", aggregate[:headerSize])
	}
	if count := binary.LittleEndian.Uint16(aggregate[headerSize : headerSize+2]); count != 2 {
		t.Fatalf("aggregate count = %d, want 2", count)
	}

	offset := headerSize + 2
	for index := 0; index < 2; index++ {
		size := int(binary.LittleEndian.Uint16(aggregate[offset : offset+2]))
		offset += 2
		if _, err := readHeader(aggregate[offset : offset+size]); err != nil {
			t.Fatalf("child %d is not a valid v1 frame: %v", index, err)
		}
		offset += size
	}
	if offset != len(aggregate) {
		t.Fatalf("aggregate ended at %d of %d", offset, len(aggregate))
	}
}

func TestQuantizationMatchesJavaScriptForNegativeHalf(t *testing.T) {
	if got := roundLikeJavaScript(-0.5); got != 0 {
		t.Fatalf("roundLikeJavaScript(-0.5) = %v, want 0", got)
	}
}
