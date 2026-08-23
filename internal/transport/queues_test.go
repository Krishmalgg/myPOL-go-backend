package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"mypol/go-realtime/internal/domain"
)

func frame(event string) *domain.Envelope {
	return &domain.Envelope{V: domain.EnvelopeVersion, Event: event}
}

func TestEphemeralFramesCoalesceNewestWins(t *testing.T) {
	q := newOutboundQueues(8, 8)

	q.pushEphemeral(frame("first"), "cursor:a")
	q.pushEphemeral(frame("second"), "cursor:a")
	q.pushEphemeral(frame("other"), "cursor:b")

	// One frame per stream, and it is the newest.
	if got := q.takeEphemeral(); got.Event != "second" {
		t.Errorf("first take = %q, want second", got.Event)
	}
	if got := q.takeEphemeral(); got.Event != "other" {
		t.Errorf("second take = %q, want other", got.Event)
	}
	if q.takeEphemeral() != nil {
		t.Error("queue should be empty")
	}
	if q.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", q.Dropped())
	}
}

// Under sustained pressure the oldest stream is shed: an ancient cursor is
// worth less than a current one.
func TestEphemeralQueueShedsOldestWhenSaturated(t *testing.T) {
	q := newOutboundQueues(2, 8)

	q.pushEphemeral(frame("a"), "a")
	q.pushEphemeral(frame("b"), "b")
	q.pushEphemeral(frame("c"), "c")

	if got := q.takeEphemeral(); got.Event != "b" {
		t.Errorf("oldest stream should have been shed, got %q", got.Event)
	}
}

func TestEphemeralBatchPreservesOneNewestFramePerStream(t *testing.T) {
	q := newOutboundQueues(8, 8)
	q.pushEphemeral(frame("old"), "cursor:a")
	q.pushEphemeral(frame("new"), "cursor:a")
	q.pushEphemeral(frame("ink"), "ink:s")

	batch := q.takeEphemeralBatch(8)
	if len(batch) != 2 || batch[0].Event != "new" || batch[1].Event != "ink" {
		t.Fatalf("batch = %#v, want newest cursor then ink", batch)
	}
}

// Reliable traffic must never be silently discarded — the caller has to be told.
func TestReliableQueueRefusesWhenFull(t *testing.T) {
	q := newOutboundQueues(8, 2)

	if err := q.pushReliable(frame("one")); err != nil {
		t.Fatalf("first push: %v", err)
	}
	if err := q.pushReliable(frame("two")); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if err := q.pushReliable(frame("three")); !errors.Is(err, errReliableQueueFull) {
		t.Fatalf("expected errReliableQueueFull, got %v", err)
	}
}

func TestPendingReliableIncludesAnInFlightWrite(t *testing.T) {
	q := newOutboundQueues(8, 2)
	if err := q.pushReliable(frame("one")); err != nil {
		t.Fatalf("push: %v", err)
	}
	if q.takeReliable() == nil {
		t.Fatal("expected queued reliable frame")
	}
	q.beginReliableWrite()
	if got := q.PendingReliable(); got != 1 {
		t.Fatalf("pending while writing = %d, want 1", got)
	}
	q.endReliableWrite()
	if got := q.PendingReliable(); got != 0 {
		t.Fatalf("pending after write = %d, want 0", got)
	}
}

func TestQueuesGoQuietOnceClosed(t *testing.T) {
	q := newOutboundQueues(8, 8)
	q.markClosed()

	if err := q.pushReliable(frame("x")); err != nil {
		t.Errorf("push after close should be a no-op, got %v", err)
	}
	q.pushEphemeral(frame("y"), "k")

	if q.takeReliable() != nil || q.takeEphemeral() != nil {
		t.Error("nothing should be queued after close")
	}
}

func TestMarkClosedIsIdempotent(t *testing.T) {
	q := newOutboundQueues(1, 1)

	q.markClosed()
	q.markClosed() // must not panic on a double close of the channel

	if !q.isClosed() {
		t.Error("queue should report closed")
	}
}

// ── stream framing ──────────────────────────────────────────────────────────

func encodeFrame(payload string) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

// A QUIC stream has no message boundaries, so length prefixes are the only way
// the receiver knows where one envelope ends.
func TestReadStreamFramesSplitsOnLengthPrefix(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write(encodeFrame(`{"a":1}`))
	buffer.Write(encodeFrame(`{"b":2}`))

	var received []string
	err := readStreamFrames(&buffer, func(payload []byte) {
		received = append(received, string(payload))
	})

	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF at end of stream, got %v", err)
	}
	if len(received) != 2 || received[0] != `{"a":1}` || received[1] != `{"b":2}` {
		t.Fatalf("frames = %v", received)
	}
}

func TestReadStreamFramesRejectsAbsurdPrefix(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, MaxFramePrefix+1)

	err := readStreamFrames(bytes.NewReader(header), func([]byte) {
		t.Fatal("no frame should be produced")
	})

	// Refusing beats allocating whatever a hostile prefix asks for.
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestReadStreamFramesSkipsEmptyFrames(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write(encodeFrame(""))
	buffer.Write(encodeFrame(`{"a":1}`))

	var received []string
	_ = readStreamFrames(&buffer, func(payload []byte) {
		received = append(received, string(payload))
	})

	if len(received) != 1 || received[0] != `{"a":1}` {
		t.Fatalf("frames = %v", received)
	}
}

func TestReadStreamFramesStopsOnTruncatedPayload(t *testing.T) {
	var buffer bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 16)
	buffer.Write(header)
	buffer.WriteString("short")

	err := readStreamFrames(&buffer, func([]byte) {
		t.Fatal("a truncated frame must not be delivered")
	})

	if err == nil {
		t.Fatal("expected an error on a truncated payload")
	}
}
