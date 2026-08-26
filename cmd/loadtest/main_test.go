package main

import (
	"fmt"
	"testing"
)

func TestAssignmentsMatchScenarioTopology(t *testing.T) {
	viewports := makeAssignments(options{scenario: "viewports", connections: 12, canvases: 4, pages: 3, activeRatio: 0, activeDrawers: 0})
	for _, user := range viewports {
		if user.noteID != "bench-note-000" {
			t.Fatalf("viewports must stay in one canvas, got %s", user.noteID)
		}
	}

	hotspot := makeAssignments(options{scenario: "hotspot", connections: 12, canvases: 4, pages: 3, activeRatio: 0, activeDrawers: 0})
	for _, user := range hotspot {
		if user.noteID != "bench-note-000" || user.pageID != "bench-page-000" || user.x != 512 || user.y != 384 {
			t.Fatalf("hotspot users must share one page/point, got %+v", user)
		}
	}

	distributed := makeAssignments(options{scenario: "distributed", connections: 12, canvases: 3, pages: 2, activeRatio: 0, activeDrawers: 0})
	seen := map[string]bool{}
	for _, user := range distributed {
		seen[user.noteID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("distributed scenario should use all canvases, got %d", len(seen))
	}
}

func TestMultiPageDistributesUsersAcrossTwentyPages(t *testing.T) {
	assignments := makeAssignments(options{
		scenario:      "multi-page",
		connections:   100,
		canvases:      1,
		pages:         20,
		activeRatio:   0,
		activeDrawers: 0,
	})
	counts := map[string]int{}
	for _, user := range assignments {
		counts[user.pageID]++
	}
	if len(counts) != 20 {
		t.Fatalf("multi-page should use all 20 pages, got %d", len(counts))
	}
	for page := 0; page < 20; page++ {
		pageID := fmt.Sprintf("bench-page-%03d", page)
		if counts[pageID] != 5 {
			t.Fatalf("%s has %d users, want 5", pageID, counts[pageID])
		}
	}
}

func TestMultiPageEvenlyDistributesTwoPageLoads(t *testing.T) {
	for _, connections := range []int{200, 500} {
		assignments := makeAssignments(options{
			scenario:      "multi-page",
			connections:   connections,
			canvases:      1,
			pages:         2,
			activeRatio:   0,
			activeDrawers: 0,
		})
		counts := map[string]int{}
		for _, user := range assignments {
			counts[user.pageID]++
		}
		wantPerPage := connections / 2
		for page := 0; page < 2; page++ {
			pageID := fmt.Sprintf("bench-page-%03d", page)
			if counts[pageID] != wantPerPage {
				t.Fatalf("%d users: %s has %d users, want %d", connections, pageID, counts[pageID], wantPerPage)
			}
		}
	}
}

func TestPreviewOffRatioIsSpreadAcrossDrawersAndViewers(t *testing.T) {
	assignments := makeAssignments(options{
		scenario:        "multi-page",
		connections:     200,
		canvases:        1,
		pages:           2,
		activeDrawers:   40,
		previewOffRatio: .5,
	})

	activeOff, activeOn, viewerOff, viewerOn := 0, 0, 0, 0
	perPage := map[string]struct{ off, on int }{}
	for _, user := range assignments {
		counts := perPage[user.pageID]
		if user.previewOff {
			counts.off++
		} else {
			counts.on++
		}
		perPage[user.pageID] = counts
		switch {
		case user.active && user.previewOff:
			activeOff++
		case user.active:
			activeOn++
		case user.previewOff:
			viewerOff++
		default:
			viewerOn++
		}
	}
	if activeOff != 20 || activeOn != 20 || viewerOff != 80 || viewerOn != 80 {
		t.Fatalf("unexpected Preview-off distribution: active off/on=%d/%d viewers off/on=%d/%d", activeOff, activeOn, viewerOff, viewerOn)
	}
	for pageID, counts := range perPage {
		if counts.off != 50 || counts.on != 50 {
			t.Fatalf("%s Preview-off distribution = off/on %d/%d, want 50/50", pageID, counts.off, counts.on)
		}
	}
}

func TestPercentileUsesSortedSamples(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}
	if got := percentile(values, .50); got != 3 {
		t.Fatalf("p50 = %v, want 3", got)
	}
	if got := percentile(values, .99); got != 5 {
		t.Fatalf("p99 = %v, want 5", got)
	}
}
