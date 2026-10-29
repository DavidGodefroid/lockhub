// Package slack is the Slack facade: Socket Mode only (an outbound
// websocket; the hub listens for nothing), a team and user allowlist,
// the lock's masked screen with every agent-provided string escaped.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Config is the Slack facade's configuration.
type Config struct {
	// Team is the workspace id (T…); Users are the member ids (U…) who
	// may answer; Channel is where tickets are posted (C…).
	Team    string
	Users   []string
	Channel string
	// AppToken (xapp-…) opens the Socket Mode connection; BotToken
	// (xoxb-…) posts and updates messages.
	AppToken, BotToken string
	// API is the Web API base (default https://slack.com/api/).
	API  string
	HTTP *http.Client
}

// Slack implements chat.Transport.
type Slack struct{ c Config }

// New checks c and returns the transport.
func New(c Config) (*Slack, error) {
	switch {
	case c.Team == "" || len(c.Users) == 0 || c.Channel == "":
		return nil, errors.New("slack: team, users and channel are required")
	case !strings.HasPrefix(c.AppToken, "xapp-"):
		return nil, errors.New("slack: the app token is not an xapp- token")
	case !strings.HasPrefix(c.BotToken, "xoxb-"):
		return nil, errors.New("slack: the bot token is not an xoxb- token")
	}
	if c.API == "" {
		c.API = "https://slack.com/api/"
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	return &Slack{c}, nil
}

// Facade implements chat.Transport.
func (s *Slack) Facade() string { return route.Slack }

// Escape makes untrusted text inert in mrkdwn: terminal controls, bidi
// and zero-width marks are made visible, & < > become entities (so no
// <!channel>, <@U…> or <url|label> can be formed), and backticks are
// replaced so the text cannot leave the code span it is put in (where
// Slack neither formats nor links).
func Escape(s string) string {
	s = chat.Inert(s)
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "`", "ˋ").Replace(s)
	return s
}

// code is s escaped and clipped, in an inline code span. Untrusted text
// is clipped before the delimiters are added, never after: a cut can
// never drop a closing backtick.
func code(s string) string {
	if s == "" {
		return "`-`"
	}
	return "`" + clip(Escape(s), maxField) + "`"
}

// Lengths keep every text within Slack's 3000 limit: a section holds at
// most three fields, or one body.
const (
	maxField = 700
	maxBody  = 2800
)

// clip cuts escaped text s to n bytes on a rune boundary. A cut may end
// inside an entity ("&am"), which is inert.
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

type text struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func md(s string) map[string]any {
	return map[string]any{"type": "section", "text": text{"mrkdwn", s}}
}

// Blocks renders c. outcome, when set, replaces the buttons.
func Blocks(c chat.Card, outcome string) []map[string]any {
	head := fmt.Sprintf("*%s* · %s · %s", clip(Escape(c.Risk), maxField), code(c.Lock), code(c.Instance))
	if c.Production {
		head += " · *PRODUCTION*"
	}
	if c.Red {
		head = ":red_circle: " + head
	}
	bl := []map[string]any{md(head),
		md(fmt.Sprintf("ticket %s · workspace %s · requester (unverified): %s", code(c.ID), code(c.Workspace), code(c.Requester)))}
	if c.Header != "" {
		bl = append(bl, md(code(c.Header)))
	}
	if len(c.Body) > 0 {
		var lines []string
		for _, l := range c.Body {
			lines = append(lines, Escape(l))
		}
		bl = append(bl, md("```"+clip(strings.Join(lines, "\n"), maxBody)+"```"))
	}
	if c.Note != "" {
		bl = append(bl, md("note (agent): "+code(c.Note)))
	}
	for _, w := range c.Warnings {
		bl = append(bl, md(":warning: "+code(w)))
	}
	if len(c.PII) > 0 {
		bl = append(bl, md("personal data touched (masked): "+code(strings.Join(c.PII, ", "))))
	}
	switch {
	case outcome != "":
		bl = append(bl, map[string]any{"type": "context", "elements": []text{{"mrkdwn", clip(Escape(outcome), maxField)}}})
	case c.Answerable:
		v := c.Instance + "/" + c.ID
		bl = append(bl, map[string]any{"type": "actions", "elements": []map[string]any{
			{"type": "button", "action_id": "approve", "value": v, "style": "primary", "text": text{"plain_text", "Approve"}},
			{"type": "button", "action_id": "deny", "value": v, "style": "danger", "text": text{"plain_text", "Deny"}},
		}})
	default:
		bl = append(bl, map[string]any{"type": "context", "elements": []text{{"mrkdwn", clip(Escape(c.Why), maxField)}}})
	}
	return bl
}

func fallback(c chat.Card) string {
	return fmt.Sprintf("%s ticket from %s", Escape(c.Risk), code(c.Instance))
}

// call posts a Web API method with the bot or app token.
func (s *Slack) call(ctx context.Context, token, method string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.c.API+method, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := s.c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rb, &r); err != nil {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	if !r.OK {
		return fmt.Errorf("%s: %s", method, r.Error)
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

func (s *Slack) message(c chat.Card, outcome string) map[string]any {
	return map[string]any{"channel": s.c.Channel, "text": fallback(c), "blocks": Blocks(c, outcome),
		"unfurl_links": false, "unfurl_media": false, "link_names": false}
}

// Post implements chat.Transport.
func (s *Slack) Post(ctx context.Context, c chat.Card) (string, error) {
	var r struct {
		TS string `json:"ts"`
	}
	if err := s.call(ctx, s.c.BotToken, "chat.postMessage", s.message(c, ""), &r); err != nil {
		return "", err
	}
	return r.TS, nil
}

// Close implements chat.Transport.
func (s *Slack) Close(ctx context.Context, ref string, c chat.Card, outcome string) error {
	m := s.message(c, outcome)
	m["ts"] = ref
	return s.call(ctx, s.c.BotToken, "chat.update", m, nil)
}

// envelope is a Socket Mode frame.
type envelope struct {
	EnvelopeID string          `json:"envelope_id"`
	Type       string          `json:"type"`
	Payload    json.RawMessage `json:"payload"`
}

// interaction is the part of a block_actions payload the facade reads.
type interaction struct {
	Type string `json:"type"`
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID     string `json:"id"`
		TeamID string `json:"team_id"`
	} `json:"user"`
	Channel struct {
		ID string `json:"id"`
	} `json:"channel"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
}

// Listen implements chat.Transport: Socket Mode, reconnecting.
func (s *Slack) Listen(ctx context.Context, answers chan<- chat.Answer) error {
	backoff := time.Second
	for {
		err := s.session(ctx, answers)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var fatal fatalErr
		if errors.As(err, &fatal) {
			return err
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = min(backoff*2, time.Minute)
	}
}

type fatalErr struct{ error }

// session is one Socket Mode connection, until Slack asks to reconnect
// or the connection drops.
func (s *Slack) session(ctx context.Context, answers chan<- chat.Answer) error {
	var open struct {
		URL string `json:"url"`
	}
	if err := s.call(ctx, s.c.AppToken, "apps.connections.open", map[string]any{}, &open); err != nil {
		if strings.Contains(err.Error(), "invalid_auth") || strings.Contains(err.Error(), "not_authed") {
			return fatalErr{err}
		}
		return err
	}
	conn, _, err := websocket.Dial(ctx, open.URL, &websocket.DialOptions{HTTPClient: s.c.HTTP})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)
	for {
		_, b, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var e envelope
		if json.Unmarshal(b, &e) != nil {
			continue
		}
		if e.EnvelopeID != "" {
			ack, _ := json.Marshal(map[string]string{"envelope_id": e.EnvelopeID})
			if err := conn.Write(ctx, websocket.MessageText, ack); err != nil {
				return err
			}
		}
		switch e.Type {
		case "disconnect":
			return errors.New("slack asked to reconnect")
		case "interactive":
			if a, ok := s.answer(e.Payload); ok {
				select {
				case answers <- a:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

// answer turns a click into an Answer when it comes from an allowed user
// of the configured team, in the configured channel.
func (s *Slack) answer(p json.RawMessage) (chat.Answer, bool) {
	var in interaction
	if json.Unmarshal(p, &in) != nil || in.Type != "block_actions" || len(in.Actions) != 1 {
		return chat.Answer{}, false
	}
	team := in.Team.ID
	if team == "" {
		team = in.User.TeamID
	}
	if team != s.c.Team || !slices.Contains(s.c.Users, in.User.ID) || in.Channel.ID != s.c.Channel {
		return chat.Answer{}, false
	}
	act := in.Actions[0]
	if act.ActionID != "approve" && act.ActionID != "deny" {
		return chat.Answer{}, false
	}
	inst, id, ok := strings.Cut(act.Value, "/")
	if !ok || inst == "" || id == "" {
		return chat.Answer{}, false
	}
	user := in.User.ID
	return chat.Answer{Instance: inst, ID: id, Approve: act.ActionID == "approve",
		ApproverID: "slack:" + team + ":" + user, Display: "slack " + user,
		Reply: func(ctx context.Context, msg string) {
			s.call(ctx, s.c.BotToken, "chat.postEphemeral", map[string]any{"channel": s.c.Channel, "user": user, "text": Escape(msg)}, nil)
		}}, true
}
