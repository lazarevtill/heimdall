package telegram_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/telegram"
)

// fakeToken/fakeChatID are obviously-fake fixtures: the base URL comes from
// httptest.Server's own loopback URL (never a real api.telegram.org
// literal), and the token/chat id are placeholders, never real credentials.
const (
	fakeToken  = "test-bot-token"
	fakeChatID = int64(1001)
)

func newTestClient(t *testing.T, h http.HandlerFunc) *telegram.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return telegram.NewClient(srv.URL, fakeToken, srv.Client())
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	return m
}

// --- GetUpdates ---

func TestGetUpdatesDecodesMessageAndCallbackQuery(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"ok":true,"result":[
			{"update_id":10,"message":{"message_id":1,"from":{"id":5,"username":"opsuser"},"chat":{"id":1001},"text":"hello"}},
			{"update_id":11,"callback_query":{"id":"cbq1","from":{"id":5},"message":{"message_id":2,"chat":{"id":1001}},"data":"mute:node-a"}}
		]}`))
	})

	updates, err := c.GetUpdates(context.Background(), 42, 30)
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	wantPath := "/bot" + fakeToken + "/getUpdates"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if o, _ := gotBody["offset"].(float64); int64(o) != 42 {
		t.Errorf("request offset = %v, want 42", gotBody["offset"])
	}
	if tm, _ := gotBody["timeout"].(float64); int(tm) != 30 {
		t.Errorf("request timeout = %v, want 30", gotBody["timeout"])
	}

	if len(updates) != 2 {
		t.Fatalf("len(updates) = %d, want 2", len(updates))
	}
	msgUpd := updates[0]
	if msgUpd.UpdateID != 10 || msgUpd.Message == nil || msgUpd.CallbackQuery != nil {
		t.Errorf("updates[0] = %+v, want a message-only update with id 10", msgUpd)
	}
	if msgUpd.Message.Text != "hello" || msgUpd.Message.Chat.ID != fakeChatID {
		t.Errorf("updates[0].Message = %+v, want text=hello chat.id=%d", msgUpd.Message, fakeChatID)
	}
	if msgUpd.Message.From == nil || msgUpd.Message.From.Username != "opsuser" {
		t.Errorf("updates[0].Message.From = %+v, want username opsuser", msgUpd.Message.From)
	}

	cbUpd := updates[1]
	if cbUpd.UpdateID != 11 || cbUpd.CallbackQuery == nil || cbUpd.Message != nil {
		t.Errorf("updates[1] = %+v, want a callback_query-only update with id 11", cbUpd)
	}
	if cbUpd.CallbackQuery.Data != "mute:node-a" || cbUpd.CallbackQuery.ID != "cbq1" {
		t.Errorf("updates[1].CallbackQuery = %+v, want data=mute:node-a id=cbq1", cbUpd.CallbackQuery)
	}
}

func TestGetUpdatesAPINotOK(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	})
	_, err := c.GetUpdates(context.Background(), 0, 0)
	if err == nil {
		t.Fatal("GetUpdates: want error on ok:false, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "Unauthorized") {
		t.Errorf("error = %q, want it to contain the API description %q", got, "Unauthorized")
	}
}

func TestGetUpdatesNon200(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	})
	if _, err := c.GetUpdates(context.Background(), 0, 0); err == nil {
		t.Fatal("GetUpdates: want error on 500, got nil")
	}
}

// --- SendMessage ---

func TestSendMessageWithButtonsAndParseModeOmitted(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"ok":true,"result":{"message_id":77}}`))
	})

	req := telegram.SendMessageRequest{
		ChatID: fakeChatID,
		Text:   "disk pressure on node-a",
		Buttons: []telegram.Button{
			{Text: "Mute 1h", CallbackData: "mute:node-a:1h"},
			{Text: "Escalate", CallbackData: "escalate:node-a"},
		},
	}
	msgID, err := c.SendMessage(context.Background(), req)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if msgID != 77 {
		t.Errorf("message id = %d, want 77", msgID)
	}
	wantPath := "/bot" + fakeToken + "/sendMessage"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if _, present := gotBody["parse_mode"]; present {
		t.Errorf("request body has parse_mode = %v, want omitted when ParseMode is \"\"", gotBody["parse_mode"])
	}
	rm, ok := gotBody["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("request reply_markup = %v, want an object", gotBody["reply_markup"])
	}
	rows, ok := rm["inline_keyboard"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("inline_keyboard = %v, want a single row", rm["inline_keyboard"])
	}
	row, ok := rows[0].([]any)
	if !ok || len(row) != 2 {
		t.Fatalf("inline_keyboard[0] = %v, want 2 buttons", rows[0])
	}
	btn0, _ := row[0].(map[string]any)
	if btn0["text"] != "Mute 1h" || btn0["callback_data"] != "mute:node-a:1h" {
		t.Errorf("button[0] = %v, want text=Mute 1h callback_data=mute:node-a:1h", btn0)
	}
}

func TestSendMessageWithExplicitParseMode(t *testing.T) {
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	})
	req := telegram.SendMessageRequest{ChatID: fakeChatID, Text: "plain", ParseMode: "HTML"}
	if _, err := c.SendMessage(context.Background(), req); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if gotBody["parse_mode"] != "HTML" {
		t.Errorf("parse_mode = %v, want HTML", gotBody["parse_mode"])
	}
	if _, present := gotBody["reply_markup"]; present {
		t.Errorf("reply_markup = %v, want omitted when no buttons", gotBody["reply_markup"])
	}
}

func TestSendMessageAPINotOK(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"description":"chat not found"}`))
	})
	_, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: "x"})
	if err == nil {
		t.Fatal("SendMessage: want error on ok:false, got nil")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "chat not found")
	}
}

func TestSendMessageNon200(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if _, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: "x"}); err == nil {
		t.Fatal("SendMessage: want error on 502, got nil")
	}
}

// --- AnswerCallbackQuery ---

func TestAnswerCallbackQueryIssuesRightPost(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"ok":true,"result":true}`))
	})
	if err := c.AnswerCallbackQuery(context.Background(), "cbq1", "muted for 1h"); err != nil {
		t.Fatalf("AnswerCallbackQuery: %v", err)
	}
	wantPath := "/bot" + fakeToken + "/answerCallbackQuery"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody["callback_query_id"] != "cbq1" {
		t.Errorf("callback_query_id = %v, want cbq1", gotBody["callback_query_id"])
	}
	if gotBody["text"] != "muted for 1h" {
		t.Errorf("text = %v, want %q", gotBody["text"], "muted for 1h")
	}
}

func TestAnswerCallbackQueryNon200(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if err := c.AnswerCallbackQuery(context.Background(), "cbq1", ""); err == nil {
		t.Fatal("AnswerCallbackQuery: want error on 500, got nil")
	}
}

// --- EditReplyMarkup ---

func TestEditReplyMarkupSetsButtons(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"ok":true,"result":true}`))
	})
	buttons := []telegram.Button{{Text: "Ack", CallbackData: "ack:1"}}
	if err := c.EditReplyMarkup(context.Background(), fakeChatID, 77, buttons); err != nil {
		t.Fatalf("EditReplyMarkup: %v", err)
	}
	wantPath := "/bot" + fakeToken + "/editMessageReplyMarkup"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if id, _ := gotBody["message_id"].(float64); int64(id) != 77 {
		t.Errorf("message_id = %v, want 77", gotBody["message_id"])
	}
	rm, _ := gotBody["reply_markup"].(map[string]any)
	rows, _ := rm["inline_keyboard"].([]any)
	if len(rows) != 1 {
		t.Fatalf("inline_keyboard = %v, want 1 row", rm["inline_keyboard"])
	}
}

func TestEditReplyMarkupClearsWhenNoButtons(t *testing.T) {
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"ok":true,"result":true}`))
	})
	if err := c.EditReplyMarkup(context.Background(), fakeChatID, 77, nil); err != nil {
		t.Fatalf("EditReplyMarkup: %v", err)
	}
	rm, ok := gotBody["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("reply_markup = %v, want present (not omitted) even when clearing", gotBody["reply_markup"])
	}
	rows, ok := rm["inline_keyboard"].([]any)
	if !ok || len(rows) != 0 {
		t.Errorf("inline_keyboard = %v, want an empty array", rm["inline_keyboard"])
	}
}

func TestEditReplyMarkupNon200(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	if err := c.EditReplyMarkup(context.Background(), fakeChatID, 77, nil); err == nil {
		t.Fatal("EditReplyMarkup: want error on 403, got nil")
	}
}

// --- Credential hygiene ---

// net/http embeds the full request URL in its transport errors, and the Bot
// API puts the token IN the path. Every error a Client returns must
// therefore have the token scrubbed out, or one DNS blip writes the bot
// credential into the journal. An unreachable loopback port produces exactly
// that error shape without any network.
func TestErrorsNeverCarryTheToken(t *testing.T) {
	const token = "123456789:AAHfakeTokenValueForTests_abcdefghij"
	c := telegram.NewClient("http://127.0.0.1:1", token, nil)

	calls := []struct {
		name string
		call func() error
	}{
		{"getUpdates", func() error { _, err := c.GetUpdates(context.Background(), 0, 0); return err }},
		{"sendMessage", func() error {
			_, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: "x"})
			return err
		}},
		{"answerCallbackQuery", func() error { return c.AnswerCallbackQuery(context.Background(), "cbq1", "") }},
		{"editMessageReplyMarkup", func() error { return c.EditReplyMarkup(context.Background(), fakeChatID, 1, nil) }},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("want a transport error against a closed port, got nil")
			}
			if strings.Contains(err.Error(), token) {
				t.Errorf("error leaks the bot token: %q", err)
			}
			if !strings.Contains(err.Error(), "[REDACTED:telegram-token]") {
				t.Errorf("error = %q, want the token replaced by a visible marker", err)
			}
		})
	}
}

// A body echoed back by a hostile or misconfigured proxy is scrubbed too.
func TestNon200BodyEchoingTheTokenIsScrubbed(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("upstream failed for " + r.URL.Path))
	})
	_, err := c.GetUpdates(context.Background(), 0, 0)
	if err == nil {
		t.Fatal("want error on 502, got nil")
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("error leaks the bot token: %q", err)
	}
}

// --- Rate limiting ---

// Telegram answers flood control with HTTP 429 and a machine-readable
// parameters.retry_after. The caller needs the value, not just the text, so
// it can stop hammering the API for exactly that long.
func TestTooManyRequestsCarriesRetryAfter(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 35","parameters":{"retry_after":35}}`))
	})
	_, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: "x"})
	var apiErr *telegram.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a *telegram.APIError reachable via errors.As", err)
	}
	got := struct {
		Status, Code int
		RetryAfter   time.Duration
	}{apiErr.StatusCode, apiErr.ErrorCode, apiErr.RetryAfter()}
	want := struct {
		Status, Code int
		RetryAfter   time.Duration
	}{http.StatusTooManyRequests, 429, 35 * time.Second}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("APIError mismatch (-want +got):\n%s", diff)
	}
	if !strings.Contains(err.Error(), "retry after 35") {
		t.Errorf("error = %q, want the API description kept", err)
	}
}

func TestAPIErrorWithoutRetryAfterReportsZero(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	})
	_, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: "x"})
	var apiErr *telegram.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a *telegram.APIError", err)
	}
	if apiErr.RetryAfter() != 0 {
		t.Errorf("RetryAfter = %v, want 0 when the API sent none", apiErr.RetryAfter())
	}
}

// --- Message length ---

func TestTextLengthCountsUTF16CodeUnits(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"ascii", "abc", 3},
		{"two-byte runes count once", "ééé", 3},
		{"astral runes count twice", "🔬x", 3},
		{"an invalid byte counts once (JSON sends it as U+FFFD)", "a\xffb", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := telegram.TextLength(tc.in); got != tc.want {
				t.Errorf("TextLength(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitTextNeverSplitsARuneAndLosesNothing(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		limit int
		want  []string
	}{
		{"fits", "abcd", 4, []string{"abcd"}},
		{"empty stays one empty chunk", "", 4, []string{""}},
		{"exact multiple", "abcdef", 3, []string{"abc", "def"}},
		{"remainder", "abcdefg", 3, []string{"abc", "def", "g"}},
		{"multi-byte runes are atomic", "ééééé", 2, []string{"éé", "éé", "é"}},
		// A surrogate pair must never be split across two messages.
		{"astral rune moves to the next chunk whole", "ab🔬cd", 3, []string{"ab", "🔬c", "d"}},
		{"invalid bytes pass through verbatim", "a\xffbc", 2, []string{"a\xff", "bc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := telegram.SplitText(tc.in, tc.limit)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("SplitText(%q, %d) mismatch (-want +got):\n%s", tc.in, tc.limit, diff)
			}
			if strings.Join(got, "") != tc.in {
				t.Errorf("chunks do not concatenate back to the input byte-for-byte")
			}
		})
	}
}

// A body over Telegram's 4096-character cap is rejected by the API forever,
// which would pin that outbox entry pending with no way out. The transport
// sends it as ordered chunks instead: every byte still arrives, in order,
// and the inline buttons ride on the LAST chunk so they sit under the whole
// message.
func TestSendMessageSplitsAnOverlongPlainTextBody(t *testing.T) {
	var bodies []map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		bodies = append(bodies, decodeBody(t, r))
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d}}`, 100+len(bodies))
	})
	text := strings.Repeat("x", telegram.MaxMessageLength) + strings.Repeat("y", 10)
	buttons := []telegram.Button{{Text: "Ack", CallbackData: "a|k"}}

	msgID, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: text, Buttons: buttons})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("sendMessage calls = %d, want 2 chunks", len(bodies))
	}
	var rejoined string
	for _, b := range bodies {
		rejoined += b["text"].(string)
	}
	if rejoined != text {
		t.Error("chunks do not reassemble into the original body")
	}
	if _, present := bodies[0]["reply_markup"]; present {
		t.Error("the first chunk carries reply_markup; buttons belong on the last chunk only")
	}
	if _, present := bodies[1]["reply_markup"]; !present {
		t.Error("the last chunk is missing the buttons")
	}
	if msgID != 102 {
		t.Errorf("message id = %d, want the LAST chunk's id (102), the one carrying the buttons", msgID)
	}
}

// Splitting entity markup mid-tag would turn a formatted message into a
// parse error, so only plain text is split; a caller that sets ParseMode owns
// its own length.
func TestSendMessageDoesNotSplitFormattedText(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	})
	text := strings.Repeat("x", telegram.MaxMessageLength+1)
	if _, err := c.SendMessage(context.Background(), telegram.SendMessageRequest{ChatID: fakeChatID, Text: text, ParseMode: "HTML"}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if calls != 1 {
		t.Errorf("sendMessage calls = %d, want 1 (formatted text is never split)", calls)
	}
}
