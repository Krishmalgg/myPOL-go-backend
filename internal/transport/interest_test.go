package transport

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/testsupport"
)

func interestPayload(pageID string, x, y, width, height int) string {
	return `{"pageId":"` + pageID + `","x":` + strconv.Itoa(x) + `,"y":` + strconv.Itoa(y) +
		`,"width":` + strconv.Itoa(width) + `,"height":` + strconv.Itoa(height) + `}`
}

// waitForCondition polls briefly for something to become true, for the one
// case a read-until-an-event pattern cannot cover: waiting for a frame that,
// by design, has no reply on the wire at all.
func waitForCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was never met")
}

// The end-to-end proof: a real client frame over a real socket reaches the
// index, and a real peer's real socket is filtered by it. Everything below
// this is a unit test of one layer; this is the seam across all of them.
//
// Proven without waiting on an absence — a socket read has no way to
// distinguish "correctly filtered" from "the server is just slow" — by
// sending a filtered event first and then an admitted one, and checking that
// the admitted one is the very next thing the peer's socket produces.
func TestInterestUpdateOverTheWireFiltersARealPeersSocket(t *testing.T) {
	h := newWSHarness(t)

	sender := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", UserID: "user-1"})
	readEnvelope(t, sender) // roster

	farViewer := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", UserID: "user-2"})
	readEnvelope(t, farViewer) // roster
	readEnvelope(t, sender)    // presence.joined for farViewer

	send(t, farViewer, application.EventInterestUpdate,
		interestPayload("page-1", 50000, 50000, 100, 100))

	// interest.update travels on farViewer's own connection and carries no
	// reply, so there is nothing on the wire to synchronise against before
	// sender's frame is sent on an entirely different connection. Waiting for
	// the harness's own index to reflect the update is what makes the next
	// send() meaningful rather than a race.
	waitForCondition(t, func() bool { return h.interest.Count() == 1 })

	// Filtered: on the reported page, but nowhere near the reported viewport.
	send(t, sender, "cursor.moved", `{"pageId":"page-1","x":10,"y":10}`)

	// Admitted: inside the reported viewport.
	send(t, sender, "cursor.moved", `{"pageId":"page-1","x":50010,"y":50010}`)

	envelope := readUntil(t, farViewer, "cursor.moved")
	var payload struct{ X float64 }
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.X != 50010 {
		t.Errorf("x = %v, want 50010 — the filtered event at x=10 must never have arrived", payload.X)
	}
}

// interest.update itself must never reach a peer — it is server-consumed
// control data, and broadcasting it would tell every peer exactly where this
// connection is looking.
func TestInterestUpdateIsNeverRelayed(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1"})
	readEnvelope(t, first)

	second := h.connect(t, testsupport.ClaimsInput{SessionID: "s2"})
	readEnvelope(t, second)
	readEnvelope(t, first) // presence.joined

	send(t, second, application.EventInterestUpdate, interestPayload("page-1", 0, 0, 100, 100))
	send(t, second, "cursor.moved", `{"pageId":"page-1","x":1,"y":1}`)

	envelope := readEnvelope(t, first)
	if envelope.Event != "cursor.moved" {
		t.Fatalf("event = %q — interest.update must never be relayed to a peer", envelope.Event)
	}
}

// A viewer may report its own interest — reading a canvas is not restricted
// to editors, and interest filtering exists to help every participant, not
// only those who may draw.
func TestAViewerMayReportInterest(t *testing.T) {
	h := newWSHarness(t)

	editor := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", Permission: "edit"})
	readEnvelope(t, editor)

	viewer := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", Permission: "view"})
	readEnvelope(t, viewer)
	readEnvelope(t, editor)

	send(t, viewer, application.EventInterestUpdate, interestPayload("page-1", 0, 0, 100, 100))

	// Proven the same way: a subsequent, unrelated frame still round-trips,
	// so the interest.update did not get the connection rejected or closed.
	send(t, editor, "cursor.moved", `{"pageId":"page-1","x":1,"y":1}`)
	envelope := readEnvelope(t, viewer)
	if envelope.Event != "cursor.moved" {
		t.Fatalf("event = %q — the viewer's connection should still be healthy", envelope.Event)
	}
}

// The metrics the plan names explicitly — recipients per event and filtered
// recipients — must be observable through the actual scrape endpoint, not
// only through direct access to the counters in a unit test.
func TestInterestMetricsAreServedOverTheMetricsEndpoint(t *testing.T) {
	h := newWSHarness(t)

	near := h.connect(t, testsupport.ClaimsInput{SessionID: "s1"})
	readEnvelope(t, near) // roster

	far := h.connect(t, testsupport.ClaimsInput{SessionID: "s2"})
	readEnvelope(t, far)
	readEnvelope(t, near) // presence.joined

	send(t, far, application.EventInterestUpdate, interestPayload("page-1", 50000, 50000, 100, 100))
	waitForCondition(t, func() bool { return h.interest.Count() == 1 })

	sender := h.connect(t, testsupport.ClaimsInput{SessionID: "s3"})
	readEnvelope(t, sender)
	readEnvelope(t, near)
	readEnvelope(t, far)

	send(t, sender, "cursor.moved", `{"pageId":"page-1","x":1,"y":1}`)
	readEnvelope(t, near) // the one recipient this reaches

	resp, err := http.Get(h.server.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	var snapshot struct {
		InterestUpdatesTotal       int64   `json:"interestUpdatesTotal"`
		InterestEventsTotal        int64   `json:"interestEventsTotal"`
		InterestRecipientsTotal    int64   `json:"interestRecipientsTotal"`
		InterestFilteredTotal      int64   `json:"interestFilteredRecipientsTotal"`
		InterestRecipientsPerEvent float64 `json:"interestRecipientsPerEvent"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if snapshot.InterestUpdatesTotal < 1 {
		t.Error("interestUpdatesTotal should reflect the report far sent")
	}
	if snapshot.InterestEventsTotal < 1 {
		t.Error("interestEventsTotal should reflect the ephemeral event that was relayed")
	}
	// One recipient (near) out of two candidate peers (near, far): far was
	// filtered out by its own reported viewport.
	if snapshot.InterestFilteredTotal < 1 {
		t.Error("interestFilteredRecipientsTotal should show far was excluded")
	}
	if snapshot.InterestRecipientsPerEvent <= 0 {
		t.Error("interestRecipientsPerEvent should be derived once events have occurred")
	}
}
