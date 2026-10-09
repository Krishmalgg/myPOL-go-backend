package transport

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/testsupport"
)

// Opt-in cross-repository test. No developer signing keys or accounts are used.
func TestFrontendAdapterIntegration(t *testing.T) {
	if os.Getenv("MYPOL_FRONTEND_INTEGRATION") != "1" {
		t.Skip("set MYPOL_FRONTEND_INTEGRATION=1 to run the production TypeScript adapter against Go")
	}
	h := newWSHarnessWithIdle(t, 45*time.Second)
	const note = "22222222-2222-2222-2222-222222222222"
	const actor = "11111111-1111-1111-1111-111111111111"
	tokenA, err := h.keys.Sign(testsupport.Claims(testsupport.ClaimsInput{UserID: actor, NoteID: note}))
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := h.keys.Sign(testsupport.Claims(testsupport.ClaimsInput{
		UserID: "55555555-5555-5555-5555-555555555555", NoteID: note,
		SessionID: "66666666-6666-6666-6666-666666666666", TokenID: "77777777-7777-7777-7777-777777777777",
	}))
	if err != nil {
		t.Fatal(err)
	}
	const permit = "frontend-history-permit"
	err = h.rooms.HistoryPreviews.Register(application.HistoryPreviewPermit{
		ID: permit, NoteID: note, UserID: actor, ExpiresAt: time.Now().Add(30 * time.Second).UnixMilli(),
		Payload: json.RawMessage(`{"entryId":"fixture-entry","operationId":"fixture-operation","undone":false,"changes":[],"undoText":[],"redoText":[]}`),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	app, err := filepath.Abs(filepath.Join("..", "..", "..", "my-app"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "node", filepath.Join(app, "node_modules", "vitest", "vitest.mjs"),
		"run", "src/features/canvas-realtime/adapters/go-integration.test.ts", "--maxWorkers=1")
	command.Dir = app
	command.Env = append(os.Environ(), "CANVAS_RT_URL="+h.server.URL, "CANVAS_RT_TOKEN="+tokenA,
		"CANVAS_RT_TOKEN_B="+tokenB, "CANVAS_RT_NOTE="+note, "CANVAS_RT_HISTORY_PERMIT="+permit)
	output, err := command.CombinedOutput()
	// The child test prints assertions/timings only, never its token environment.
	t.Log(string(output))
	if err != nil {
		t.Fatalf("frontend transport integration failed: %v", err)
	}
}
