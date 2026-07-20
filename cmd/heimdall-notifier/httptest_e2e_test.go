package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/silence"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// newFakeTelegramServer is a minimal httptest stand-in for the Telegram Bot
// API: it answers sendMessage/answerCallbackQuery with the {"ok":true,
// "result":...} envelope internal/telegram.Client expects. The real
// Telegram is BLOCKED on operator creds (no BotFather token yet); this is
// the httptest fake the brief requires in its place — never a live
// Telegram.
func newFakeTelegramServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 1}})
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		default:
			http.NotFound(w, r)
		}
	}))
}

// newFakeAlertmanagerServer is a minimal httptest stand-in for Alertmanager's
// v2 silence API: an in-memory silence set behind GET/POST
// /api/v2/silences and DELETE /api/v2/silence/{id}, in the wire shape
// internal/silence.Client expects. The real Alertmanager is BLOCKED on
// operator creds; this is the httptest fake in its place.
func newFakeAlertmanagerServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	silences := map[string]map[string]any{}
	nextID := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/silences":
			list := make([]map[string]any, 0, len(silences))
			for _, s := range silences {
				list = append(list, s)
			}
			_ = json.NewEncoder(w).Encode(list)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/silences":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			nextID++
			id := fmt.Sprintf("sil-%d", nextID)
			body["id"] = id
			body["status"] = map[string]string{"state": "active"}
			silences[id] = body
			_ = json.NewEncoder(w).Encode(map[string]string{"silenceID": id})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/silence/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/v2/silence/")
			delete(silences, id)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestEndToEndOverHTTPTestFakes drives the REAL *telegram.Client and
// *silence.Client (real JSON wire encoding, real HTTP round trips) against
// httptest fakes standing in for the operator-creds-blocked Telegram/
// Alertmanager, exercising handleUpdates -> notify.Dispatch and runCycle ->
// notify.Drain/notify.ReconcileSilences end to end. This is deliberately
// NOT a test of runLoop's infinite for loop (see loop.go's doc: "an
// infinite for loop cannot itself be unit tested") — it calls the same
// testable functions runLoop calls, just with real clients wired to
// httptest instead of the in-memory fakes the other tests in this package
// use, so the actual HTTP/JSON wiring between this binary and
// internal/telegram+internal/silence is exercised at least once.
func TestEndToEndOverHTTPTestFakes(t *testing.T) {
	ob := openTestOutbox(t)
	sup := openTestSuppress(t)

	tgServer := newFakeTelegramServer(t)
	defer tgServer.Close()
	amServer := newFakeAlertmanagerServer(t)
	defer amServer.Close()

	tg := telegram.NewClient(tgServer.URL, "fake-token-not-a-real-secret", tgServer.Client())
	sc := silence.NewClient(amServer.URL, amServer.Client())

	if _, err := ob.Enqueue(fixedNow, outbox.ChannelMain, "disk check firing", "escalate-[hb:node--c1-deadman]"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	nd := notify.Deps{
		TG: tg, Outbox: ob, Suppress: sup,
		MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
		AllowedUsers: map[int64]bool{fakeAllowedUser: true},
	}

	// A callback press dispatched through the REAL telegram.Client: its
	// AnswerCallbackQuery call is a genuine HTTP round trip to tgServer.
	updates := []telegram.Update{callbackUpdate(1, fakeAllowedUser, "n|node--c1-deadman")}
	_, dispatchErrors := handleUpdates(context.Background(), fixedNow, nd, updates, 0)
	if dispatchErrors != 0 {
		t.Fatalf("handleUpdates dispatchErrors = %d, want 0", dispatchErrors)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) after dispatch = %d, want 1", len(rows))
	}

	cd := cycleDeps{
		Notify: nd, Silence: sc, Suppress: sup,
		TextfileDir: t.TempDir(), TG: tg, MainChatID: fakeMainChatID,
	}
	if err := runCycle(context.Background(), fixedNow, cd, dispatchErrors); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// Drain sent the outbox entry over the REAL telegram.Client -> httptest.
	pending, err := ob.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Pending after runCycle = %d, want 0 (entry sent+marked via the real telegram.Client)", len(pending))
	}

	// ReconcileSilences created a silence for the mute Dispatch wrote, over
	// the REAL silence.Client -> httptest.
	all, err := sc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("len(silences) after runCycle = %d, want 1 (created via the real silence.Client)", len(all))
	}
}
