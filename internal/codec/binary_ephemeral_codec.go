// Package codec implements the compact, versioned wire form for the four
// high-frequency ephemeral events. Everything else remains a JSON Envelope.
package codec

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"mypol/go-realtime/internal/domain"
)

const (
	magic      byte = 0xCB
	version    byte = 1
	headerSize      = 8

	codeCursor    byte = 1
	codeLaser     byte = 2
	codeInk       byte = 3
	codeTransform byte = 4
	// A Go-to-browser wrapper containing complete v1 relayed frames. The
	// children retain their own metadata and version, so a rolling deployment
	// never changes the meaning of an individual cursor/ink/transform frame.
	codeAggregate byte = 0xff

	flagHasPressure byte = 0x01
	// Set only on Go -> browser frames. Its variable-length trailer carries
	// server-stamped identity required by the recipient's dedupe and sequence
	// tracking. Browser -> Go frames never carry it.
	flagRelayMetadata byte = 0x80

	quantization = 0.25
	maxInkPoints = 4096
)

var errMalformedBinaryFrame = errors.New("malformed binary ephemeral frame")

type header struct {
	code  byte
	flags byte
	seq   uint32
}

type inkPoint struct {
	X        float64  `json:"x"`
	Y        float64  `json:"y"`
	Pressure *float64 `json:"pressure,omitempty"`
}

type inkPayload struct {
	StrokeID string     `json:"strokeId"`
	Points   []inkPoint `json:"points"`
}

type pointerPayload struct {
	PageID string  `json:"pageId"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
}

type transformPayload struct {
	BlockID  string  `json:"blockId"`
	PageID   string  `json:"pageId"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Width    float64 `json:"width"`
	Height   float64 `json:"height"`
	Rotation float64 `json:"rotation"`
}

// IsBinaryFrame distinguishes binary frames from JSON before an allocation or
// JSON parse. JSON starts with `{` (0x7B), never this magic byte.
func IsBinaryFrame(data []byte) bool {
	return len(data) >= headerSize && data[0] == magic
}

// EncodeClientFrame produces the compact browser-to-Go form for the four
// preview events. It exists for load tooling as well as browser parity tests;
// callers still use JSON for control, auth, locks and reliable commits.
func EncodeClientFrame(envelope *domain.Envelope) ([]byte, bool) {
	if envelope == nil {
		return nil, false
	}
	code, ok := eventCode(envelope.Event)
	if !ok {
		return nil, false
	}
	seq, ok := envelopeSeq(envelope.Seq)
	if !ok {
		return nil, false
	}

	writer := newWriter(96)
	writer.header(code, seq, 0)
	var err error
	switch code {
	case codeInk:
		var payload inkPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return nil, false
		}
		err = encodeInk(writer, payload)
	case codeCursor, codeLaser:
		var payload pointerPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return nil, false
		}
		err = encodePointer(writer, payload)
	case codeTransform:
		var payload transformPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return nil, false
		}
		err = encodeTransform(writer, payload)
	}
	if err != nil {
		return nil, false
	}
	return writer.bytes(), true
}

// DecodeClientFrame restores a normal Envelope from a browser-originated
// binary preview. Identity/channel are intentionally absent: transport stamps
// them from the authenticated connection after this function returns.
func DecodeClientFrame(data []byte) (*domain.Envelope, error) {
	h, err := readHeader(data)
	if err != nil || h.flags&flagRelayMetadata != 0 {
		return nil, errMalformedBinaryFrame
	}

	reader := newReader(data[headerSize:])
	var event string
	var payload any

	switch h.code {
	case codeInk:
		if h.flags&^flagHasPressure != 0 {
			return nil, errMalformedBinaryFrame
		}
		event = "ink.points"
		payload, err = decodeInk(reader, h.flags)
	case codeCursor:
		if h.flags != 0 {
			return nil, errMalformedBinaryFrame
		}
		event = "cursor.moved"
		payload, err = decodePointer(reader)
	case codeLaser:
		if h.flags != 0 {
			return nil, errMalformedBinaryFrame
		}
		event = "laser.moved"
		payload, err = decodePointer(reader)
	case codeTransform:
		if h.flags != 0 {
			return nil, errMalformedBinaryFrame
		}
		event = "block.transform.preview"
		payload, err = decodeTransform(reader)
	default:
		return nil, errMalformedBinaryFrame
	}
	if err != nil || reader.remaining() != 0 {
		return nil, errMalformedBinaryFrame
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	envelope := &domain.Envelope{V: domain.EnvelopeVersion, Event: event, Payload: raw}
	if h.seq != 0 {
		seq := uint64(h.seq)
		envelope.Seq = &seq
	}
	return envelope, nil
}

// EncodeRelayFrame encodes a server-stamped preview for a browser that proved
// it understands binary by first sending a binary frame. JSON is returned for
// every other event, preserving readable control/reliable protocol traffic.
func EncodeRelayFrame(envelope *domain.Envelope) ([]byte, bool) {
	if envelope == nil {
		return nil, false
	}
	code, ok := eventCode(envelope.Event)
	if !ok {
		return nil, false
	}
	seq, ok := envelopeSeq(envelope.Seq)
	if !ok {
		return nil, false
	}

	writer := newWriter(96)
	writer.header(code, seq, 0)
	var err error
	switch code {
	case codeInk:
		var payload inkPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return nil, false
		}
		err = encodeInk(writer, payload)
	case codeCursor, codeLaser:
		var payload pointerPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return nil, false
		}
		err = encodePointer(writer, payload)
	case codeTransform:
		var payload transformPayload
		if json.Unmarshal(envelope.Payload, &payload) != nil {
			return nil, false
		}
		err = encodeTransform(writer, payload)
	}
	if err != nil {
		return nil, false
	}

	metadata := newWriter(96)
	metadata.string(envelope.MessageID)
	metadata.string(envelope.SessionID)
	metadata.string(envelope.Channel)
	metadata.optionalString(envelope.ActorID)
	metadata.optionalString(envelope.Origin)
	metadata.u64(uint64(max(envelope.SentAt, 0)))
	if len(metadata.bytes()) > math.MaxUint16 {
		return nil, false
	}

	writer.buf[3] |= flagRelayMetadata
	writer.buf = append(writer.buf, metadata.bytes()...)
	footer := make([]byte, 2)
	binary.LittleEndian.PutUint16(footer, uint16(len(metadata.bytes())))
	writer.buf = append(writer.buf, footer...)
	return writer.bytes(), true
}

// EncodeRelayAggregate packs several compatible relay frames into one WebSocket
// message. It is only selected after the browser explicitly advertises support;
// older clients continue to receive EncodeRelayFrame output unchanged.
func EncodeRelayAggregate(envelopes []*domain.Envelope) ([]byte, bool) {
	if len(envelopes) < 2 || len(envelopes) > math.MaxUint16 {
		return nil, false
	}

	children := make([][]byte, 0, len(envelopes))
	size := headerSize + 2
	for _, envelope := range envelopes {
		child, ok := EncodeRelayFrame(envelope)
		if !ok || len(child) > math.MaxUint16 {
			return nil, false
		}
		children = append(children, child)
		size += 2 + len(child)
	}

	writer := newWriter(size)
	writer.header(codeAggregate, 0, 0)
	count := make([]byte, 2)
	binary.LittleEndian.PutUint16(count, uint16(len(children)))
	writer.buf = append(writer.buf, count...)
	for _, child := range children {
		binary.LittleEndian.PutUint16(count, uint16(len(child)))
		writer.buf = append(writer.buf, count...)
		writer.buf = append(writer.buf, child...)
	}
	return writer.bytes(), true
}

// RelayMetadata is the server-stamped portion of a compact relay frame. The
// load runner uses it to pair a received preview with its sender and sequence
// without needing to duplicate the editor's payload decoder.
type RelayMetadata struct {
	Sequence uint64
	ActorID  string
	Origin   string
	SentAt   int64
}

// DecodeRelayMetadata reads one binary frame or one aggregate. It deliberately
// exposes only delivery metadata: benchmark code does not need to interpret a
// cursor, ink or transform payload in order to measure relay latency.
func DecodeRelayMetadata(data []byte) ([]RelayMetadata, error) {
	h, err := readHeader(data)
	if err != nil {
		return nil, err
	}
	if h.code == codeAggregate {
		if h.flags != 0 || len(data) < headerSize+2 {
			return nil, errMalformedBinaryFrame
		}
		count := int(binary.LittleEndian.Uint16(data[headerSize : headerSize+2]))
		offset := headerSize + 2
		metadata := make([]RelayMetadata, 0, count)
		for index := 0; index < count; index++ {
			if offset+2 > len(data) {
				return nil, errMalformedBinaryFrame
			}
			size := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2
			if size == 0 || offset+size > len(data) {
				return nil, errMalformedBinaryFrame
			}
			child, err := DecodeRelayMetadata(data[offset : offset+size])
			if err != nil || len(child) != 1 {
				return nil, errMalformedBinaryFrame
			}
			metadata = append(metadata, child[0])
			offset += size
		}
		if offset != len(data) {
			return nil, errMalformedBinaryFrame
		}
		return metadata, nil
	}

	if h.flags&flagRelayMetadata == 0 || len(data) < headerSize+2 {
		return nil, errMalformedBinaryFrame
	}
	metadataLength := int(binary.LittleEndian.Uint16(data[len(data)-2:]))
	metadataStart := len(data) - 2 - metadataLength
	if metadataStart < headerSize {
		return nil, errMalformedBinaryFrame
	}
	reader := newReader(data[metadataStart : len(data)-2])
	if _, err := reader.string(); err != nil { // message id
		return nil, errMalformedBinaryFrame
	}
	if _, err := reader.string(); err != nil { // session id
		return nil, errMalformedBinaryFrame
	}
	if _, err := reader.string(); err != nil { // channel
		return nil, errMalformedBinaryFrame
	}
	actorPresent, err := reader.u8()
	if err != nil || actorPresent > 1 {
		return nil, errMalformedBinaryFrame
	}
	actorID := ""
	if actorPresent == 1 {
		actorID, err = reader.string()
		if err != nil {
			return nil, errMalformedBinaryFrame
		}
	}
	originPresent, err := reader.u8()
	if err != nil || originPresent > 1 {
		return nil, errMalformedBinaryFrame
	}
	origin := ""
	if originPresent == 1 {
		origin, err = reader.string()
		if err != nil {
			return nil, errMalformedBinaryFrame
		}
	}
	sentAt, err := reader.u64()
	if err != nil || reader.remaining() != 0 {
		return nil, errMalformedBinaryFrame
	}
	return []RelayMetadata{{
		Sequence: uint64(h.seq),
		ActorID:  actorID,
		Origin:   origin,
		SentAt:   int64(sentAt),
	}}, nil
}

func eventCode(event string) (byte, bool) {
	switch event {
	case "cursor.moved":
		return codeCursor, true
	case "laser.moved":
		return codeLaser, true
	case "ink.points":
		return codeInk, true
	case "block.transform.preview":
		return codeTransform, true
	default:
		return 0, false
	}
}

func envelopeSeq(seq *uint64) (uint32, bool) {
	if seq == nil {
		return 0, true
	}
	if *seq > math.MaxUint32 {
		return 0, false
	}
	return uint32(*seq), true
}

func readHeader(data []byte) (header, error) {
	if !IsBinaryFrame(data) || data[1] != version {
		return header{}, errMalformedBinaryFrame
	}
	return header{code: data[2], flags: data[3], seq: binary.LittleEndian.Uint32(data[4:8])}, nil
}

func encodeInk(writer *writer, payload inkPayload) error {
	if payload.StrokeID == "" || len(payload.Points) > maxInkPoints {
		return errMalformedBinaryFrame
	}
	hasPressure := len(payload.Points) > 0
	for _, point := range payload.Points {
		if point.Pressure == nil {
			hasPressure = false
			break
		}
	}
	if hasPressure {
		writer.buf[3] |= flagHasPressure
	}

	writer.string(payload.StrokeID)
	writer.varint(uint32(len(payload.Points)))
	var previousX, previousY int32
	for _, point := range payload.Points {
		x, err := quantizedSigned(point.X)
		if err != nil {
			return err
		}
		y, err := quantizedSigned(point.Y)
		if err != nil {
			return err
		}
		writer.svarint(x - previousX)
		writer.svarint(y - previousY)
		previousX, previousY = x, y
		if hasPressure {
			writer.u8(pressureByte(*point.Pressure))
		}
	}
	return nil
}

func decodeInk(reader *reader, flags byte) (any, error) {
	strokeID, err := reader.string()
	if err != nil || strokeID == "" {
		return nil, errMalformedBinaryFrame
	}
	count, err := reader.varint()
	if err != nil || count > maxInkPoints {
		return nil, errMalformedBinaryFrame
	}

	hasPressure := flags&flagHasPressure != 0
	points := make([]inkPoint, count)
	var x, y int32
	for index := range points {
		dx, err := reader.svarint()
		if err != nil {
			return nil, err
		}
		dy, err := reader.svarint()
		if err != nil {
			return nil, err
		}
		x += dx
		y += dy
		points[index] = inkPoint{X: dequantize(x), Y: dequantize(y)}
		if hasPressure {
			value, err := reader.u8()
			if err != nil {
				return nil, err
			}
			pressure := float64(value) / 255
			// Preserve PointerEvent's neutral fallback: 128/255 otherwise turns
			// simulated touch/mouse pressure into physical pen pressure on peers.
			if value == 128 {
				pressure = 0.5
			}
			points[index].Pressure = &pressure
		}
	}
	return inkPayload{StrokeID: strokeID, Points: points}, nil
}

func encodePointer(writer *writer, payload pointerPayload) error {
	if payload.PageID == "" {
		return errMalformedBinaryFrame
	}
	x, err := quantizedSigned(payload.X)
	if err != nil {
		return err
	}
	y, err := quantizedSigned(payload.Y)
	if err != nil {
		return err
	}
	writer.string(payload.PageID)
	writer.svarint(x)
	writer.svarint(y)
	return nil
}

func decodePointer(reader *reader) (any, error) {
	pageID, err := reader.string()
	if err != nil || pageID == "" {
		return nil, errMalformedBinaryFrame
	}
	x, err := reader.svarint()
	if err != nil {
		return nil, err
	}
	y, err := reader.svarint()
	if err != nil {
		return nil, err
	}
	return pointerPayload{PageID: pageID, X: dequantize(x), Y: dequantize(y)}, nil
}

func encodeTransform(writer *writer, payload transformPayload) error {
	if payload.BlockID == "" || payload.PageID == "" {
		return errMalformedBinaryFrame
	}
	x, err := quantizedSigned(payload.X)
	if err != nil {
		return err
	}
	y, err := quantizedSigned(payload.Y)
	if err != nil {
		return err
	}
	width, err := quantizedUnsigned(payload.Width)
	if err != nil {
		return err
	}
	height, err := quantizedUnsigned(payload.Height)
	if err != nil {
		return err
	}
	rotation, err := quantizedRotation(payload.Rotation)
	if err != nil {
		return err
	}
	writer.string(payload.BlockID)
	writer.string(payload.PageID)
	writer.svarint(x)
	writer.svarint(y)
	writer.varint(width)
	writer.varint(height)
	writer.svarint(rotation)
	return nil
}

func decodeTransform(reader *reader) (any, error) {
	blockID, err := reader.string()
	if err != nil || blockID == "" {
		return nil, errMalformedBinaryFrame
	}
	pageID, err := reader.string()
	if err != nil || pageID == "" {
		return nil, errMalformedBinaryFrame
	}
	x, err := reader.svarint()
	if err != nil {
		return nil, err
	}
	y, err := reader.svarint()
	if err != nil {
		return nil, err
	}
	width, err := reader.varint()
	if err != nil {
		return nil, err
	}
	height, err := reader.varint()
	if err != nil {
		return nil, err
	}
	rotation, err := reader.svarint()
	if err != nil {
		return nil, err
	}
	return transformPayload{
		BlockID: blockID, PageID: pageID,
		X: dequantize(x), Y: dequantize(y),
		Width: dequantizeUnsigned(width), Height: dequantizeUnsigned(height),
		Rotation: float64(rotation) / 100,
	}, nil
}

func quantizedSigned(value float64) (int32, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, errMalformedBinaryFrame
	}
	quantized := roundLikeJavaScript(value / quantization)
	if quantized < -2147483648 || quantized > 2147483647 {
		return 0, errMalformedBinaryFrame
	}
	return int32(quantized), nil
}

func quantizedUnsigned(value float64) (uint32, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, errMalformedBinaryFrame
	}
	quantized := roundLikeJavaScript(value / quantization)
	if quantized < 0 || quantized > math.MaxUint32 {
		return 0, errMalformedBinaryFrame
	}
	return uint32(quantized), nil
}

func quantizedRotation(value float64) (int32, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, errMalformedBinaryFrame
	}
	quantized := roundLikeJavaScript(value * 100)
	if quantized < -2147483648 || quantized > 2147483647 {
		return 0, errMalformedBinaryFrame
	}
	return int32(quantized), nil
}

func dequantize(value int32) float64          { return float64(value) * quantization }
func dequantizeUnsigned(value uint32) float64 { return float64(value) * quantization }

// JavaScript's Math.round rounds half values toward +infinity, while Go's
// math.Round rounds them away from zero. The protocol must use the browser's
// rule so a point such as -0.125 has the same quantized coordinate on both
// sides of the wire.
func roundLikeJavaScript(value float64) float64 { return math.Floor(value + 0.5) }

func pressureByte(value float64) byte {
	return byte(math.Round(math.Max(0, math.Min(1, value)) * 255))
}

type writer struct{ buf []byte }

func newWriter(capacity int) *writer { return &writer{buf: make([]byte, 0, capacity)} }
func (w *writer) bytes() []byte      { return w.buf }
func (w *writer) header(code byte, seq uint32, flags byte) {
	w.buf = append(w.buf, magic, version, code, flags, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(w.buf[4:8], seq)
}
func (w *writer) u8(value byte) { w.buf = append(w.buf, value) }
func (w *writer) u64(value uint64) {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, value)
	w.buf = append(w.buf, bytes...)
}
func (w *writer) varint(value uint32) {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			w.u8(b)
			return
		}
		w.u8(b | 0x80)
	}
}
func (w *writer) svarint(value int32) {
	w.varint(uint32(value<<1) ^ uint32(value>>31))
}
func (w *writer) string(value string) {
	w.varint(uint32(len(value)))
	w.buf = append(w.buf, value...)
}
func (w *writer) optionalString(value *string) {
	if value == nil {
		w.u8(0)
		return
	}
	w.u8(1)
	w.string(*value)
}

type reader struct {
	data   []byte
	offset int
}

func newReader(data []byte) *reader { return &reader{data: data} }
func (r *reader) remaining() int    { return len(r.data) - r.offset }
func (r *reader) u8() (byte, error) {
	if r.remaining() < 1 {
		return 0, errMalformedBinaryFrame
	}
	value := r.data[r.offset]
	r.offset++
	return value, nil
}
func (r *reader) u64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, errMalformedBinaryFrame
	}
	value := binary.LittleEndian.Uint64(r.data[r.offset : r.offset+8])
	r.offset += 8
	return value, nil
}
func (r *reader) varint() (uint32, error) {
	var result uint32
	for index := 0; index < 5; index++ {
		value, err := r.u8()
		if err != nil {
			return 0, err
		}
		if index == 4 && value&0xf0 != 0 {
			return 0, errMalformedBinaryFrame
		}
		result |= uint32(value&0x7f) << (7 * index)
		if value&0x80 == 0 {
			return result, nil
		}
	}
	return 0, errMalformedBinaryFrame
}
func (r *reader) svarint() (int32, error) {
	value, err := r.varint()
	if err != nil {
		return 0, err
	}
	return int32(value>>1) ^ -int32(value&1), nil
}
func (r *reader) string() (string, error) {
	length, err := r.varint()
	if err != nil || uint64(length) > uint64(r.remaining()) {
		return "", errMalformedBinaryFrame
	}
	start := r.offset
	r.offset += int(length)
	return string(r.data[start:r.offset]), nil
}
