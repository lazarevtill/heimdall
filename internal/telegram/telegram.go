// Package telegram is a thin stdlib-net/http client for the Telegram Bot
// API. It is pure transport — no policy, no state, no clock reads — so the
// notifier (S7-b) can drive it against a real httptest server or a fake.
//
// Secret hygiene: the Bot API puts the token IN THE URL PATH
// (<base>/bot<token>/<method>), and net/http embeds the full request URL in
// every transport error (`Post "https://…/bot<token>/getUpdates": dial tcp
// …`). Without scrubbing, one DNS blip or timeout writes the bot
// credential into the journal, which ships off the host. Every error a
// Client returns therefore passes through sanitizeErr — the same belt-and-
// braces shape internal/gotify and internal/synology use for their own
// credentials.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxMessageLength is Telegram's hard cap on one sendMessage text, in the
// units the Bot API counts (UTF-16 code units; see TextLength). A longer
// text is rejected with a 400 on every attempt, which is why SendMessage
// splits rather than sends it.
const MaxMessageLength = 4096

// maxErrBodyBytes bounds how much of a failing response body is folded into
// a returned error, for diagnostics only.
const maxErrBodyBytes = 4096

// maxRespBytes bounds a successful response read (getUpdates returns at
// most 100 updates; anything near this size is not the Bot API).
const maxRespBytes = 4 << 20

// Client is a Telegram Bot API client. baseURL is the API root
// (e.g. "https://api.telegram.org"); token is the bot token. The client
// composes method URLs as <baseURL>/bot<token>/<method>. Safe for use by the
// single notifier poller goroutine.
type Client struct {
	baseURL string
	token   string
	httpc   *http.Client
}

// NewClient returns a Client for the given base URL (trailing slash
// trimmed) and bot token. If httpc is nil, a default http.Client is used;
// callers SHOULD pass one with a timeout, but the primary deadline
// mechanism is the ctx passed to each call.
func NewClient(baseURL, token string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpc:   httpc,
	}
}

// Update is one item from getUpdates: either an incoming message or a
// callback query (an inline-button press), never both.
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

// Message is an incoming (or previously sent) chat message.
type Message struct {
	MessageID int64  `json:"message_id"`
	From      *User  `json:"from,omitempty"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text,omitempty"`
}

// CallbackQuery is fired when a user presses an inline-keyboard button.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data,omitempty"` // the button's callback_data
}

// User is a Telegram user/bot account.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username,omitempty"`
}

// Chat is a Telegram chat (the notifier addresses chats by ID only).
type Chat struct {
	ID int64 `json:"id"`
}

// Button is one inline-keyboard button: a label + the callback_data emitted
// when pressed. Telegram hard-limits callback_data to 64 bytes — the
// CALLER is responsible for staying within that budget; this client neither
// validates nor truncates it.
type Button struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// inlineKeyboardMarkup is the wire shape of reply_markup for a single-row
// inline keyboard: {"inline_keyboard": [[button, ...]]}.
type inlineKeyboardMarkup struct {
	InlineKeyboard [][]Button `json:"inline_keyboard"`
}

// SendMessageRequest is one outgoing message. Buttons is an optional single
// row of inline buttons (the notifier's lifecycle/hypothesis rows are one
// row); ParseMode "" sends no parse_mode field at all (plain text — the
// hypothesis path requires this: no markdown injection from LLM-authored
// text).
type SendMessageRequest struct {
	ChatID    int64
	Text      string
	Buttons   []Button
	ParseMode string // "" | "MarkdownV2" | "HTML" — default "" (plain)
}

// apiResponse is the Bot API's uniform response envelope:
// {"ok":bool,"result":...,"error_code":int,"description":string,
// "parameters":{"retry_after":int}}. Result is left raw so each method can
// decode it against its own expected shape.
type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// APIError is a request the Bot API itself refused: an "ok":false envelope,
// whatever HTTP status carried it (Telegram answers flood control with HTTP
// 429 AND an envelope). It is reachable through errors.As on anything a
// Client returns, so a caller can react to the machine-readable fields
// instead of parsing the description.
type APIError struct {
	Method      string
	StatusCode  int // HTTP status
	ErrorCode   int // the envelope's error_code; 0 when absent
	Description string
	// RetryAfterSeconds is parameters.retry_after: how long flood control
	// wants the bot to stay quiet. 0 when the API sent none.
	RetryAfterSeconds int
}

func (e *APIError) Error() string {
	if e.StatusCode == http.StatusOK {
		return fmt.Sprintf("telegram: %s: api error: %s", e.Method, e.Description)
	}
	return fmt.Sprintf("telegram: %s: status %d: api error: %s", e.Method, e.StatusCode, e.Description)
}

// RetryAfter is the server-imposed backoff as a Duration (0 when none). A
// duration, not a deadline: this package reads no clock, so turning it into
// "not before T" is the caller's job, against the caller's injected now.
func (e *APIError) RetryAfter() time.Duration {
	return time.Duration(e.RetryAfterSeconds) * time.Second
}

// call POSTs body (marshaled as JSON; nil sends no body) to
// <baseURL>/bot<token>/<method> and decodes the response envelope. On
// success it unmarshals Result into out (skipped if out is nil or Result is
// empty). Fail-closed: a transport error, non-200 status, or an "ok":false
// envelope (an *APIError carrying the API's description) all return a
// non-nil error — never a partial or fabricated result. Every error is
// scrubbed of the token before it leaves (see the package doc).
func (c *Client) call(ctx context.Context, method string, body, out any) error {
	if err := c.doCall(ctx, method, body, out); err != nil {
		return c.sanitizeErr(err)
	}
	return nil
}

// doCall is call without the scrubbing; never return its errors directly.
func (c *Client) doCall(ctx context.Context, method string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("telegram: %s: marshal request: %w", method, err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/bot"+c.token+"/"+method, rdr)
	if err != nil {
		return fmt.Errorf("telegram: %s: build request: %w", method, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: %s: %w", method, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodyBytes))
		// Flood control (429) and most client errors still carry the
		// envelope; decode it so the caller gets an *APIError with
		// retry_after rather than an opaque string.
		var ar apiResponse
		if json.Unmarshal(raw, &ar) == nil && !ar.OK && ar.Description != "" {
			return &APIError{
				Method: method, StatusCode: resp.StatusCode, ErrorCode: ar.ErrorCode,
				Description: ar.Description, RetryAfterSeconds: ar.Parameters.RetryAfter,
			}
		}
		return fmt.Errorf("telegram: %s: unexpected status %d: %s", method, resp.StatusCode, bytes.TrimSpace(raw))
	}
	var ar apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&ar); err != nil {
		return fmt.Errorf("telegram: %s: decode response: %w", method, err)
	}
	if !ar.OK {
		return &APIError{
			Method: method, StatusCode: resp.StatusCode, ErrorCode: ar.ErrorCode,
			Description: ar.Description, RetryAfterSeconds: ar.Parameters.RetryAfter,
		}
	}
	if out != nil && len(ar.Result) > 0 {
		if err := json.Unmarshal(ar.Result, out); err != nil {
			return fmt.Errorf("telegram: %s: decode result: %w", method, err)
		}
	}
	return nil
}

// sanitize replaces the bot token with a marker wherever it appears, in its
// raw form and in the path-escaped form a re-encoded URL would carry. Only
// ever a no-op when the token is empty (a misconfiguration the notifier's
// config loader rejects before constructing a Client).
func (c *Client) sanitize(s string) string {
	if c.token == "" {
		return s
	}
	s = strings.ReplaceAll(s, c.token, "[REDACTED:telegram-token]")
	if esc := url.PathEscape(c.token); esc != c.token {
		s = strings.ReplaceAll(s, esc, "[REDACTED:telegram-token]")
	}
	return s
}

// sanitizeErr wraps err so its Error() text has the token scrubbed. The
// original error is preserved for errors.Is/As via Unwrap, so an *APIError
// (which never contains the token: it is built from the response body, not
// the URL) is still reachable.
func (c *Client) sanitizeErr(err error) error {
	if err == nil {
		return nil
	}
	scrubbed := c.sanitize(err.Error())
	if scrubbed == err.Error() {
		return err
	}
	return &sanitizedError{msg: scrubbed, err: err}
}

// sanitizedError carries a scrubbed message while keeping the original
// error reachable through errors.Is / errors.As.
type sanitizedError struct {
	msg string
	err error
}

func (e *sanitizedError) Error() string { return e.msg }
func (e *sanitizedError) Unwrap() error { return e.err }

// TextLength is the length of s as Telegram counts it against
// MaxMessageLength: UTF-16 code units, so a rune outside the Basic
// Multilingual Plane (most emoji) counts twice. An invalid UTF-8 byte counts
// once, because JSON encoding transmits it as U+FFFD.
func TextLength(s string) int {
	n := 0
	for _, r := range s {
		n += utf16Units(r)
	}
	return n
}

func utf16Units(r rune) int {
	if r > 0xFFFF && r <= utf8.MaxRune {
		return 2
	}
	return 1
}

// SplitText cuts s into ordered chunks of at most limit TextLength units
// each, only ever on a rune boundary, so the chunks concatenate back to s
// byte-for-byte: nothing is re-encoded, re-wrapped or dropped (the
// verbatim-body contract of internal/notify.Sink holds across the split). A
// text that already fits — including the empty string — is returned as its
// single chunk. A limit below 2 is raised to 2, the width of the widest
// rune, so a chunk can always make progress.
func SplitText(s string, limit int) []string {
	if limit < 2 {
		limit = 2
	}
	if TextLength(s) <= limit {
		return []string{s}
	}
	var chunks []string
	start, units := 0, 0
	for i, r := range s {
		w := utf16Units(r)
		if units+w > limit {
			chunks = append(chunks, s[start:i])
			start, units = i, 0
		}
		units += w
	}
	return append(chunks, s[start:])
}

// getUpdatesRequest is the body posted to getUpdates.
type getUpdatesRequest struct {
	Offset  int64 `json:"offset"`
	Timeout int   `json:"timeout"`
}

// GetUpdates long-polls for updates newer than offset (Telegram's ack
// model: pass last_update_id+1). timeoutSeconds is the server-side
// long-poll wait; the ctx deadline should exceed it. Returns the decoded
// updates or an error (transport, non-200, or "ok":false with the API
// description).
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]Update, error) {
	req := getUpdatesRequest{Offset: offset, Timeout: timeoutSeconds}
	var updates []Update
	if err := c.call(ctx, "getUpdates", req, &updates); err != nil {
		return nil, err
	}
	return updates, nil
}

// sendMessageBody is the wire shape POSTed to sendMessage. ParseMode and
// ReplyMarkup are both omitted (via omitempty / nil pointer) when unset, so
// a buttonless plain-text send carries neither field.
type sendMessageBody struct {
	ChatID      int64                 `json:"chat_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode,omitempty"`
	ReplyMarkup *inlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

// sentMessage is the minimal result shape of sendMessage that SendMessage
// needs.
type sentMessage struct {
	MessageID int64 `json:"message_id"`
}

// SendMessage posts sendMessage and returns the sent message_id. Fail-closed
// on transport/non-200/"ok":false.
//
// A plain-text (ParseMode "") Text longer than MaxMessageLength would be
// refused by the API on every attempt — a message stuck pending forever.
// It is instead sent as ordered SplitText chunks: every byte still arrives,
// in order, and the Buttons ride on the LAST chunk so they sit under the
// whole message; the returned id is that last chunk's. Delivery is
// at-least-once per chunk: if chunk k fails, the error is returned and a
// retry re-sends from chunk 1. Formatted text (ParseMode set) is never
// split, because a cut inside an entity would turn it into a parse error;
// such a caller owns its own length.
func (c *Client) SendMessage(ctx context.Context, req SendMessageRequest) (messageID int64, err error) {
	chunks := []string{req.Text}
	if req.ParseMode == "" {
		chunks = SplitText(req.Text, MaxMessageLength)
	}
	for i, chunk := range chunks {
		body := sendMessageBody{
			ChatID:    req.ChatID,
			Text:      chunk,
			ParseMode: req.ParseMode,
		}
		if i == len(chunks)-1 && len(req.Buttons) > 0 {
			body.ReplyMarkup = &inlineKeyboardMarkup{InlineKeyboard: [][]Button{req.Buttons}}
		}
		var sent sentMessage
		if err := c.call(ctx, "sendMessage", body, &sent); err != nil {
			if len(chunks) > 1 {
				return 0, fmt.Errorf("telegram: sendMessage chunk %d of %d: %w", i+1, len(chunks), err)
			}
			return 0, err
		}
		messageID = sent.MessageID
	}
	return messageID, nil
}

// answerCallbackQueryBody is the wire shape POSTed to answerCallbackQuery.
type answerCallbackQueryBody struct {
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text,omitempty"`
}

// AnswerCallbackQuery acks a button press (removes the client's loading
// spinner) with an optional toast text. Best-effort semantics but still
// returns errors.
func (c *Client) AnswerCallbackQuery(ctx context.Context, callbackQueryID, text string) error {
	body := answerCallbackQueryBody{CallbackQueryID: callbackQueryID, Text: text}
	return c.call(ctx, "answerCallbackQuery", body, nil)
}

// editMessageReplyMarkupBody is the wire shape POSTed to
// editMessageReplyMarkup. ReplyMarkup is always present (never omitted) so
// an empty inline_keyboard array unambiguously clears the keyboard rather
// than leaving the field's effect up to Telegram's handling of an absent
// parameter.
type editMessageReplyMarkupBody struct {
	ChatID      int64                `json:"chat_id"`
	MessageID   int64                `json:"message_id"`
	ReplyMarkup inlineKeyboardMarkup `json:"reply_markup"`
}

// EditReplyMarkup replaces a message's inline keyboard (e.g. to disable
// buttons after a press so a mute can't be double-applied from the UI).
// Passing no buttons clears the keyboard.
func (c *Client) EditReplyMarkup(ctx context.Context, chatID, messageID int64, buttons []Button) error {
	rows := [][]Button{}
	if len(buttons) > 0 {
		rows = [][]Button{buttons}
	}
	body := editMessageReplyMarkupBody{
		ChatID:      chatID,
		MessageID:   messageID,
		ReplyMarkup: inlineKeyboardMarkup{InlineKeyboard: rows},
	}
	return c.call(ctx, "editMessageReplyMarkup", body, nil)
}
