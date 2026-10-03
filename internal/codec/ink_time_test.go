package codec

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"mypol/go-realtime/internal/domain"
)

// Plan P3.1: ink points may carry ms-since-stroke-start times, as a section
// after the points so decoders that predate it read the points unchanged.

func timedInkFrame(flags byte) []byte {
	writer := newWriter(64)
	writer.header(codeInk, 3, flags)
	writer.string("stroke-1")
	writer.varint(3)
	for _, delta := range [][2]int32{{40, 40}, {4, 0}, {4, 4}} {
		writer.svarint(delta[0])
		writer.svarint(delta[1])
		if flags&flagHasPressure != 0 {
			writer.u8(153)
		}
	}
	if flags&flagHasTime != 0 {
		writer.varint(0)  // t = 0
		writer.varint(16) // t = 16
		writer.varint(17) // t = 33
	}
	return writer.bytes()
}

func decodedInk(t *testing.T, envelope *domain.Envelope) inkPayload {
	t.Helper()
	var payload inkPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}

func TestInkPointTimesSurviveClientDecodeAndRelayEncode(t *testing.T) {
	envelope, err := DecodeClientFrame(timedInkFrame(flagHasPressure | flagHasTime))
	if err != nil {
		t.Fatalf("DecodeClientFrame: %v", err)
	}
	payload := decodedInk(t, envelope)
	want := []uint32{0, 16, 33}
	for index, point := range payload.Points {
		if point.T == nil || *point.T != want[index] {
			t.Fatalf("point %d time = %v, want %d", index, point.T, want[index])
		}
	}

	envelope.MessageID, envelope.SessionID, envelope.Channel = "m-1", "s-1", "note:1"
	relay, ok := EncodeRelayFrame(envelope)
	if !ok {
		t.Fatal("EncodeRelayFrame refused a timed ink frame")
	}
	h, err := readHeader(relay)
	if err != nil || h.flags&flagHasTime == 0 || h.flags&flagHasPressure == 0 {
		t.Fatalf("relay flags = %#x, want pressure and time", h.flags)
	}
	again, err := decodeInk(newReader(relay[headerSize:]), h.flags)
	if err != nil {
		t.Fatalf("decode relayed ink: %v", err)
	}
	for index, point := range again.(inkPayload).Points {
		if point.T == nil || *point.T != want[index] {
			t.Fatalf("relayed point %d time = %v, want %d", index, point.T, want[index])
		}
	}
	if _, err := DecodeRelayMetadata(relay); err != nil {
		t.Fatalf("relay trailer no longer found after the time section: %v", err)
	}
}

func TestInkFramesWithoutTimesAreUnchanged(t *testing.T) {
	envelope, err := DecodeClientFrame(timedInkFrame(flagHasPressure))
	if err != nil {
		t.Fatalf("DecodeClientFrame: %v", err)
	}
	for _, point := range decodedInk(t, envelope).Points {
		if point.T != nil {
			t.Fatalf("a frame without times decoded a time: %v", *point.T)
		}
	}
	if string(envelope.Payload) != `{"strokeId":"stroke-1","points":[{"x":10,"y":10,"pressure":0.6},{"x":11,"y":10,"pressure":0.6},{"x":12,"y":11,"pressure":0.6}]}` {
		t.Fatalf("JSON for an untimed frame changed: %s", envelope.Payload)
	}
	envelope.MessageID, envelope.SessionID, envelope.Channel = "m-1", "s-1", "note:1"
	relay, ok := EncodeRelayFrame(envelope)
	if h, err := readHeader(relay); !ok || err != nil || h.flags&flagHasTime != 0 {
		t.Fatalf("an untimed frame must relay without the time flag")
	}
}

func TestUnknownInkFlagsAreStillRejected(t *testing.T) {
	if _, err := DecodeClientFrame(timedInkFrame(0x04)); err == nil {
		t.Fatal("an unknown ink flag must be rejected")
	}
}

func TestTruncatedTimeSectionIsRejected(t *testing.T) {
	frame := timedInkFrame(flagHasTime)
	if _, err := DecodeClientFrame(frame[:len(frame)-1]); err == nil {
		t.Fatal("a frame missing a time must be rejected")
	}
}

// The same bytes are produced by the browser encoder (codec.test.ts), so the
// two implementations agree on the timed layout byte for byte.
const sharedTimedInkFixture = "cb010303030000000873747" + "26f6b652d31035050990800990808990010" + "11"

func TestDecodesTheBrowserTimedInkFixture(t *testing.T) {
	frame, err := hex.DecodeString(sharedTimedInkFixture)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	envelope, err := DecodeClientFrame(frame)
	if err != nil {
		t.Fatalf("DecodeClientFrame: %v", err)
	}
	got, _ := json.Marshal(decodedInk(t, envelope).Points)
	want := `[{"x":10,"y":10,"pressure":0.6,"t":0},{"x":11,"y":10,"pressure":0.6,"t":16},{"x":12,"y":11,"pressure":0.6,"t":33}]`
	if string(got) != want {
		t.Fatalf("points = %s, want %s", got, want)
	}
}
