// Package telegram is the Telegram facade: long-polled getUpdates only
// (the hub listens for nothing), a (chat, sender) allowlist, the lock's
// masked screen in HTML with every agent-provided string escaped.
package telegram

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Config is the Telegram facade's configuration.
type Config struct {
	Chats []chatconf.TelegramChat
	// Token is the bot token (from BotFather).
	Token string
	// API is the Bot API base (default https://api.telegram.org).
	API  string
	HTTP *http.Client
	// Poll is the getUpdates long-poll timeout (default 30s).
	Poll time.Duration
}

// Telegram implements chat.Transport.
type Telegram struct {
	c Config
	// handles maps callback data (64 bytes at most on Telegram) to the
	// ticket it answers.
	mu      sync.Mutex
	handles map[string][2]string
}

// New checks c and returns the transport.
func New(c Config) (*Telegram, error) {
	if err := (&chatconf.Telegram{Chats: c.Chats}).Validate(); err != nil {
		return nil, err
	}
	if id, _, ok := strings.Cut(c.Token, ":"); !ok || id == "" || strings.ContainsAny(c.Token, " /\t\r\n") {
		return nil, errors.New("telegram: the bot token is not <id>:<secret>")
	}
	if c.API == "" {
		c.API = "https://api.telegram.org"
	}
	if c.Poll == 0 {
		c.Poll = 30 * time.Second
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: c.Poll + 20*time.Second}
	}
	return &Telegram{c: c, handles: map[string][2]string{}}, nil
}

// Facade implements chat.Transport.
func (t *Telegram) Facade() string { return route.Telegram }

// Escape makes untrusted text inert in Telegram HTML: hidden characters
// made visible, then & < > " ' as entities, so no tag or link can be
// formed.
func Escape(s string) string { return html.EscapeString(chat.Inert(s)) }

// Telegram's limit is 4096 characters per message: fields are clipped
// before they are wrapped, never after.
const (
	maxField = 200
	maxBody  = 1200
)

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for i := n; i > 0; i-- {
		if s[i]&0xC0 != 0x80 {
			return s[:i] + "…"
		}
	}
	return ""
}

// code is s escaped and clipped, in <code>. A cut can only end inside an
// entity ("&am"), which is inert: the tag is added after.
func code(s string) string {
	if s == "" {
		return "<code>-</code>"
	}
	return "<code>" + clip(Escape(s), maxField) + "</code>"
}

// Text renders c in Telegram HTML; outcome, when set, ends it.
func Text(c chat.Card, outcome string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b> · %s · %s", clip(Escape(c.Risk), maxField), code(c.Lock), code(c.Instance))
	if c.Production {
		b.WriteString(" · <b>PRODUCTION</b>")
	}
	fmt.Fprintf(&b, "\nticket %s · workspace %s\nrequester (unverified): %s", code(c.ID), code(c.Workspace), code(c.Requester))
	if c.Header != "" {
		b.WriteString("\n" + code(c.Header))
	}
	if len(c.Body) > 0 {
		var lines []string
		for _, l := range c.Body {
			lines = append(lines, Escape(l))
		}
		b.WriteString("\n<pre>" + clip(strings.Join(lines, "\n"), maxBody) + "</pre>")
	}
	if c.Note != "" {
		b.WriteString("\nnote (agent): " + code(c.Note))
	}
	for i, w := range c.Warnings {
		if i == 3 {
			fmt.Fprintf(&b, "\n⚠ and %d more", len(c.Warnings)-3)
			break
		}
		b.WriteString("\n⚠ " + code(w))
	}
	if len(c.PII) > 0 {
		b.WriteString("\npersonal data touched (masked): " + code(strings.Join(c.PII, ", ")))
	}
	switch {
	case outcome != "":
		b.WriteString("\n<i>" + clip(Escape(outcome), maxField) + "</i>")
	case !c.Answerable:
		b.WriteString("\n<i>" + clip(Escape(c.Why), maxField) + "</i>")
	}
	return b.String()
}

func (t *Telegram) handle(c chat.Card) string {
	h := sha256.Sum256([]byte(c.Instance + "/" + c.ID))
	k := hex.EncodeToString(h[:12])
	t.mu.Lock()
	t.handles[k] = [2]string{c.Instance, c.ID}
	t.mu.Unlock()
	return k
}

func (t *Telegram) call(ctx context.Context, method string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", t.c.API+"/bot"+t.c.Token+"/"+method, bytes.NewReader(b))
	if err != nil {
		// url.Parse's error quotes the URL, which holds the token.
		return fmt.Errorf("%s: bad bot token or API URL", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.c.HTTP.Do(req)
	if err != nil {
		// The URL holds the token: never let it reach a log.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("%s: %w", method, ue.Err)
		}
		return fmt.Errorf("%s: request failed", method)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var r struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(rb, &r); err != nil {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	if !r.OK {
		return fmt.Errorf("%s: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (t *Telegram) chats() []int64 {
	var out []int64
	for _, c := range t.c.Chats {
		if !slices.Contains(out, c.Chat) {
			out = append(out, c.Chat)
		}
	}
	return out
}

func (t *Telegram) message(c chat.Card, outcome string) map[string]any {
	m := map[string]any{"text": Text(c, outcome), "parse_mode": "HTML",
		"link_preview_options": map[string]any{"is_disabled": true}}
	if outcome == "" && c.Answerable {
		h := t.handle(c)
		m["reply_markup"] = map[string]any{"inline_keyboard": [][]map[string]string{{
			{"text": "Approve", "callback_data": "a:" + h}, {"text": "Deny", "callback_data": "d:" + h},
		}}}
	}
	return m
}

// Post implements chat.Transport: one message per allowed chat; the
// reference lists them as chat:message pairs.
func (t *Telegram) Post(ctx context.Context, c chat.Card) (string, error) {
	var refs []string
	var errs []error
	for _, ch := range t.chats() {
		m := t.message(c, "")
		m["chat_id"] = ch
		var r struct {
			MessageID int64 `json:"message_id"`
		}
		if err := t.call(ctx, "sendMessage", m, &r); err != nil {
			errs = append(errs, err)
			continue
		}
		refs = append(refs, fmt.Sprintf("%d:%d", ch, r.MessageID))
	}
	if len(refs) == 0 {
		return "", errors.Join(errs...)
	}
	return strings.Join(refs, ","), nil
}

// Close implements chat.Transport.
func (t *Telegram) Close(ctx context.Context, ref string, c chat.Card, outcome string) error {
	var errs []error
	gone := 0
	for _, r := range strings.Split(ref, ",") {
		ch, id, _ := strings.Cut(r, ":")
		m := t.message(c, outcome)
		m["chat_id"], _ = strconv.ParseInt(ch, 10, 64)
		m["message_id"], _ = strconv.ParseInt(id, 10, 64)
		switch err := t.call(ctx, "editMessageText", m, nil); {
		case err == nil:
		case strings.Contains(err.Error(), "message is not modified"):
			// Already rewritten (a retry of a close that failed in
			// another chat).
		case strings.Contains(err.Error(), "message to edit not found") || strings.Contains(err.Error(), "message can't be edited"):
			gone++
			errs = append(errs, err)
		default:
			errs = append(errs, err)
		}
	}
	h := sha256.Sum256([]byte(c.Instance + "/" + c.ID))
	t.mu.Lock()
	delete(t.handles, hex.EncodeToString(h[:12]))
	t.mu.Unlock()
	if len(errs) > 0 && gone == len(errs) {
		// Every message that failed is gone: retrying cannot help.
		return fmt.Errorf("%w: %w", chat.ErrGone, errors.Join(errs...))
	}
	return errors.Join(errs...)
}

type update struct {
	UpdateID int64 `json:"update_id"`
	Callback *struct {
		ID   string `json:"id"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message *struct {
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

// Listen implements chat.Transport: getUpdates, callback queries only.
func (t *Telegram) Listen(ctx context.Context, answers chan<- chat.Answer) error {
	var offset int64
	backoff := time.Second
	for {
		var ups []update
		err := t.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": int(t.c.Poll / time.Second),
			"allowed_updates": []string{"callback_query"}}, &ups)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if strings.Contains(err.Error(), "Unauthorized") {
				return err
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, u := range ups {
			offset = max(offset, u.UpdateID+1)
			a, ok, replied := t.answer(ctx, u)
			if u.Callback != nil && !ok && !replied {
				// Stop the button's spinner; say nothing to a stranger.
				t.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": u.Callback.ID}, nil)
			}
			if !ok {
				continue
			}
			select {
			case answers <- a:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// answer turns a callback into an Answer when its (chat, sender) pair is
// allowed; replied says it already answered the callback itself.
func (t *Telegram) answer(ctx context.Context, u update) (a chat.Answer, ok, replied bool) {
	cb := u.Callback
	if cb == nil || cb.Message == nil {
		return chat.Answer{}, false, false
	}
	pair := chatconf.TelegramChat{Chat: cb.Message.Chat.ID, From: cb.From.ID}
	if !slices.Contains(t.c.Chats, pair) {
		return chat.Answer{}, false, false
	}
	act, h, cut := strings.Cut(cb.Data, ":")
	if !cut || (act != "a" && act != "d") {
		return chat.Answer{}, false, false
	}
	t.mu.Lock()
	ref, known := t.handles[h]
	t.mu.Unlock()
	id := cb.ID
	reply := func(ctx context.Context, msg string) {
		m := map[string]any{"callback_query_id": id}
		if msg != "" {
			m["text"], m["show_alert"] = clip(chat.Inert(msg), 190), true
		}
		t.call(ctx, "answerCallbackQuery", m, nil)
	}
	if !known {
		reply(ctx, "this ticket is no longer pending")
		return chat.Answer{}, false, true
	}
	return chat.Answer{Instance: ref[0], ID: ref[1], Approve: act == "a",
		ApproverID: fmt.Sprintf("telegram:%d:%d", pair.Chat, pair.From), Display: fmt.Sprintf("telegram %d", pair.From),
		Reply: reply}, true, false
}
