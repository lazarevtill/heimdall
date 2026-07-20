// Package telegram is a thin stdlib-net/http client for the Telegram Bot
// API. It is pure transport — no policy, no state, no clock reads — so the
// notifier (S7-b) can drive it against a real httptest server or a fake.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

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
// {"ok":bool,"result":...,"description":string}. Result is left raw so each
// method can decode it against its own expected shape.
type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
}

// call POSTs body (marshaled as JSON; nil sends no body) to
// <baseURL>/bot<token>/<method> and decodes the response envelope. On
// success it unmarshals Result into out (skipped if out is nil or Result is
// empty). Fail-closed: a transport error, non-200 status, or an "ok":false
// envelope (error carries the API's description) all return a non-nil
// error — never a partial or fabricated result.
func (c *Client) call(ctx context.Context, method string, body, out any) error {
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
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("telegram: %s: unexpected status %d: %s", method, resp.StatusCode, bytes.TrimSpace(raw))
	}
	var ar apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&ar); err != nil {
		return fmt.Errorf("telegram: %s: decode response: %w", method, err)
	}
	if !ar.OK {
		return fmt.Errorf("telegram: %s: api error: %s", method, ar.Description)
	}
	if out != nil && len(ar.Result) > 0 {
		if err := json.Unmarshal(ar.Result, out); err != nil {
			return fmt.Errorf("telegram: %s: decode result: %w", method, err)
		}
	}
	return nil
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
func (c *Client) SendMessage(ctx context.Context, req SendMessageRequest) (messageID int64, err error) {
	body := sendMessageBody{
		ChatID:    req.ChatID,
		Text:      req.Text,
		ParseMode: req.ParseMode,
	}
	if len(req.Buttons) > 0 {
		body.ReplyMarkup = &inlineKeyboardMarkup{InlineKeyboard: [][]Button{req.Buttons}}
	}
	var sent sentMessage
	if err := c.call(ctx, "sendMessage", body, &sent); err != nil {
		return 0, err
	}
	return sent.MessageID, nil
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
