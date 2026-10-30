// Package approve is `lock approve`: the terminal facade. It follows the
// hub's queue over the host facade socket, shows each ticket's screen (as
// the lock masked it) and sends the human's answer.
package approve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
)

// Client talks to the facade socket.
type Client struct{ http *http.Client }

// Dial returns a client for the facade socket at path.
func Dial(path string) *Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
	return &Client{http: &http.Client{Transport: tr}}
}

// NewClient wraps an HTTP client whose requests reach the facade API
// (tests).
func NewClient(c *http.Client) *Client { return &Client{http: c} }

const base = "http://lockhub"

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		var e api.Error
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return &HubError{Status: resp.StatusCode, Kind: e.Error, Message: e.Message}
		}
		return &HubError{Status: resp.StatusCode, Message: resp.Status}
	}
	return json.Unmarshal(b, out)
}

// HubError is an error answer of the hub.
type HubError struct {
	Status        int
	Kind, Message string
}

func (e *HubError) Error() string { return e.Message }

// Queue fetches the pending tickets and the queue version, waiting up to
// wait for a change after version since.
func (c *Client) Queue(ctx context.Context, since uint64, wait time.Duration) ([]api.QueueItem, uint64, error) {
	r, err := c.QueueAll(ctx, since, wait)
	return r.Tickets, r.Version, err
}

// QueueAll is Queue with the expired tickets offered for re-approval.
func (c *Client) QueueAll(ctx context.Context, since uint64, wait time.Duration) (api.QueueResult, error) {
	var r api.QueueResult
	err := c.do(ctx, "GET", fmt.Sprintf("/v1/queue?since=%d&wait=%d", since, int(wait/time.Second)), nil, &r)
	return r, err
}

func ticketPath(instance, id, verb string) string {
	return "/v1/tickets/" + url.PathEscape(instance) + "/" + url.PathEscape(id) + "/" + verb
}

// Reveal asks the lock, through the hub, for the clear screen of a
// ticket sealed to req.Key, and returns the lock's signed answer.
func (c *Client) Reveal(ctx context.Context, instance, id string, req api.RevealRequest) ([]byte, error) {
	var r api.RevealResult
	err := c.do(ctx, "POST", ticketPath(instance, id, "reveal"), req, &r)
	return r.Answer, err
}

// Renew asks the lock, through the hub, again for an expired ticket.
func (c *Client) Renew(ctx context.Context, instance, id string, req api.RenewRequest) (api.RenewResult, error) {
	var r api.RenewResult
	err := c.do(ctx, "POST", ticketPath(instance, id, "renew"), req, &r)
	return r, err
}

// Decide sends a decision.
func (c *Client) Decide(ctx context.Context, instance, id string, req api.DecideRequest) error {
	var r api.DecideResult
	return c.do(ctx, "POST", ticketPath(instance, id, "decide"), req, &r)
}

// Screen renders a queue item for the terminal. Everything that comes
// from the lock or the agent goes through sanitize.Terminal.
func Screen(it api.QueueItem, now time.Time) (string, *ticket.Ticket, error) {
	var t ticket.Ticket
	if err := json.Unmarshal(it.Ticket, &t); err != nil {
		return "", nil, fmt.Errorf("ticket %s: %w", it.ID, err)
	}
	clean := func(s string) string { return sanitize.Terminal(s, false) }
	var b strings.Builder
	rule := strings.Repeat("─", 64)
	fmt.Fprintln(&b, rule)
	prod := ""
	if t.Flags.Production {
		prod = "  PRODUCTION"
	}
	fmt.Fprintf(&b, "%s · %s · %s%s\n", clean(t.Source.Lock), clean(it.Instance), clean(it.Risk), prod)
	fmt.Fprintf(&b, "ticket %s · asked by (unverified) %s · workspace %s\n", clean(it.ID), clean(t.Requester.Agent), clean(t.Workspace))
	if it.Expires != nil {
		fmt.Fprintf(&b, "expires in %s\n", it.Expires.Sub(now).Round(time.Minute))
	}
	fmt.Fprintln(&b, rule)
	if t.Screen.Header != "" {
		fmt.Fprintln(&b, clean(t.Screen.Header))
	}
	for _, l := range t.Screen.Body {
		fmt.Fprintln(&b, "  "+sanitize.Terminal(l, true))
	}
	if t.Screen.Note != "" {
		fmt.Fprintln(&b, clean(t.Screen.Note))
	}
	for _, w := range t.Screen.Warnings {
		fmt.Fprintln(&b, "! "+clean(w))
	}
	if len(t.PII.Touched) > 0 {
		fmt.Fprintf(&b, "personal data touched: %s (masked)\n", clean(strings.Join(t.PII.Touched, ", ")))
	}
	if r := t.Renews; r != nil {
		why := "it expired before a decision"
		if r.Reason == ticket.RenewApprovalExpired {
			why = "its approval expired before the run"
			if r.ApprovedAt != nil {
				why += " (approved " + r.ApprovedAt.Local().Format("2006-01-02 15:04") + ")"
			}
		}
		fmt.Fprintf(&b, "asks again for ticket %s: %s\n", clean(r.Of), why)
		switch {
		case !r.Checked:
			fmt.Fprintln(&b, "the lock could not compare the plan's inputs with the expired ticket's (the run still checks the plan)")
		case len(r.Changes) == 0:
			fmt.Fprintln(&b, "nothing changed since then")
		default:
			fmt.Fprintln(&b, "changed since then:")
			for _, c := range r.Changes {
				fmt.Fprintf(&b, "  %s: %s\n", clean(c.Input), changeWords(c.Change))
			}
		}
	}
	return b.String(), &t, nil
}

// changeWords says what happened to a plan-hash input since the expired
// ticket (lockkit ticket.Change kinds).
func changeWords(kind string) string {
	switch kind {
	case ticket.ChangeChanged, ticket.ChangeNew, ticket.ChangeGone:
		return kind
	case ticket.ChangeUnchecked:
		return "not checked now — the run checks it"
	}
	return sanitize.Terminal(kind, false)
}

// RenderClear renders a revealed clear screen, clearly set apart from
// the masked one. It is the lock's and the agent's words: escaped like
// the masked screen.
func RenderClear(s ticket.Screen) string {
	clean := func(x string) string { return sanitize.Terminal(x, false) }
	var b strings.Builder
	fmt.Fprintln(&b, "════ CLEAR VALUES · sealed by the lock to this terminal, not kept ════")
	if s.Header != "" {
		fmt.Fprintln(&b, clean(s.Header))
	}
	for _, l := range s.Body {
		fmt.Fprintln(&b, "  "+sanitize.Terminal(l, true))
	}
	if s.Note != "" {
		fmt.Fprintln(&b, clean(s.Note))
	}
	for _, w := range s.Warnings {
		fmt.Fprintln(&b, "! "+clean(w))
	}
	fmt.Fprintln(&b, "════ end of clear values ════")
	return b.String()
}

// lockCodes are the human words of a lock's answer codes (lockkit
// hubclient Code*). A lock's own text never reaches the terminal.
var lockCodes = map[string]string{
	"facade_refused":  "the lock does not pin this terminal's facade key (run lock up)",
	"not_pending":     "the ticket is no longer pending at the lock: nothing to reveal",
	"no_clear_screen": "the lock kept no clear screen for this ticket",
	"not_renewable":   "the lock cannot ask again for this ticket (not expired there, or gone)",
	"recheck_failed":  "the lock could not check the plan again",
	"policy_changed":  "the policy changed: the agent must plan again",
	"rate_limited":    "the lock limits new tickets right now: try again later",
	"failed":          "the lock could not answer",
}

// Explain is the human message of a hub error.
func Explain(err error) string {
	var he *HubError
	if !errors.As(err, &he) {
		return sanitize.Terminal(err.Error(), false)
	}
	switch he.Kind {
	case "lock_refused":
		if m, ok := lockCodes[he.Message]; ok {
			return m
		}
		return "the lock refused"
	case "timeout":
		return "the lock did not answer in time (is it running?)"
	}
	return sanitize.Terminal(he.Message, false)
}

// Session is one `lock approve` run.
type Session struct {
	C       *Client
	In      *bufio.Reader
	Out     io.Writer
	Display string // the human's name for screens ($USER)
	Now     func() time.Time
	// Once stops when the queue is empty instead of waiting.
	Once bool
	// FacadeKey is this terminal's facade key (tty), which the locks pin:
	// with it, Ctrl-O shows a ticket's clear values. Nil: no reveal.
	FacadeKey ed25519.PrivateKey
	// LockKeys are the lock keys pinned by lock up, by instance: a
	// revealed screen opens only if its lock signed it.
	LockKeys map[string]ed25519.PublicKey
}

var errQuit = errors.New("quit")

// Run answers tickets until the queue is empty (Once), the human quits,
// or ctx ends.
func (s *Session) Run(ctx context.Context) error {
	if s.Now == nil {
		s.Now = time.Now
	}
	skipped := map[string]bool{}
	wait := time.Duration(0)
	var ver uint64
	for {
		q, err := s.C.QueueAll(ctx, ver, wait)
		ver = q.Version
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("hub: %w", err)
		}
		var todo, expired []api.QueueItem
		for _, it := range q.Tickets {
			if !skipped[it.Instance+"/"+it.ID] {
				todo = append(todo, it)
			}
		}
		for _, it := range q.Expired {
			if !skipped["expired:"+it.Instance+"/"+it.ID] && local(it.Facades) {
				expired = append(expired, it)
			}
		}
		if len(todo) == 0 && len(expired) > 0 {
			it := expired[0]
			skipped["expired:"+it.Instance+"/"+it.ID] = true
			if err := s.renew(ctx, it); errors.Is(err, errQuit) {
				return nil
			} else if err != nil && !errors.Is(err, errSkip) {
				return err
			}
			wait = 0
			continue
		}
		if len(todo) == 0 {
			if s.Once {
				fmt.Fprintln(s.Out, "no ticket waiting")
				return nil
			}
			if wait == 0 {
				fmt.Fprintln(s.Out, "waiting for tickets (Ctrl-C to stop)…")
			}
			wait = 30 * time.Second
			continue
		}
		wait = 0
		for _, it := range todo {
			err := s.answer(ctx, it)
			switch {
			case errors.Is(err, errQuit):
				return nil
			case errors.Is(err, errSkip):
				skipped[it.Instance+"/"+it.ID] = true
			case err != nil:
				var he *HubError
				if errors.As(err, &he) {
					fmt.Fprintln(s.Out, "hub refused:", Explain(he))
					skipped[it.Instance+"/"+it.ID] = true
					continue
				}
				return err
			}
		}
	}
}

var errSkip = errors.New("skip")

func (s *Session) line(prompt string) (string, error) {
	fmt.Fprint(s.Out, prompt)
	l, err := s.In.ReadString('\n')
	if err != nil && l == "" {
		return "", errQuit
	}
	return strings.TrimRight(l, "\r\n"), nil
}

func (s *Session) answer(ctx context.Context, it api.QueueItem) error {
	text, t, err := Screen(it, s.Now())
	if err != nil {
		fmt.Fprintln(s.Out, err)
		return errSkip
	}
	fmt.Fprint(s.Out, text)
	if !local(it.Facades) {
		fmt.Fprintln(s.Out, "this ticket cannot be answered here")
		return errSkip
	}
	prompt := "approve? [y]es / [n]o <reason> / [s]kip / [q]uit: "
	if s.FacadeKey != nil {
		prompt = "approve? [y]es / [n]o <reason> / [o] clear values / [s]kip / [q]uit: "
	}
	for {
		a, err := s.line(prompt)
		if err != nil {
			return err
		}
		verb, reason, _ := strings.Cut(strings.TrimSpace(a), " ")
		req := api.DecideRequest{Facade: "tty", Display: s.Display, Reason: strings.TrimSpace(reason)}
		switch strings.ToLower(verb) {
		case "o", "\x0f":
			// o is the key. Ctrl-O works where the terminal passes it
			// (Linux: 0x0F before the Enter of the line); macOS takes
			// ^O for itself (VDISCARD) and never delivers it.
			s.reveal(ctx, it, t)
			continue
		case "y", "yes":
			req.Approved = true
			if t.Flags.Production && t.Flags.Retype != "" {
				typed, err := s.line(fmt.Sprintf("production: type %q to approve: ", sanitize.Terminal(t.Flags.Retype, false)))
				if err != nil {
					return err
				}
				if typed != t.Flags.Retype {
					fmt.Fprintln(s.Out, "does not match: not approved")
					continue
				}
				req.Retype = typed
			}
		case "n", "no":
		case "s", "skip":
			return errSkip
		case "q", "quit":
			return errQuit
		default:
			continue
		}
		if err := s.C.Decide(ctx, it.Instance, it.ID, req); err != nil {
			return err
		}
		if req.Approved {
			fmt.Fprintln(s.Out, "approved")
		} else {
			fmt.Fprintln(s.Out, "denied")
		}
		return nil
	}
}

// reveal shows the clear values of t: an ephemeral key signed by the tty
// facade key goes to the lock through the hub; the lock seals the clear
// screen to it and signs the answer; it opens here only, and the key is
// dropped once shown.
func (s *Session) reveal(ctx context.Context, it api.QueueItem, t *ticket.Ticket) {
	if s.FacadeKey == nil {
		fmt.Fprintln(s.Out, "no facade key: clear values cannot be shown here (run lock up)")
		return
	}
	lockPub := s.LockKeys[it.Instance]
	if lockPub == nil || ticket.KeyID(lockPub) != t.Source.KeyID {
		fmt.Fprintln(s.Out, "this lock's key is not the one lock up pinned: clear values cannot be shown")
		return
	}
	rk, priv, err := ticket.NewRevealKey(s.FacadeKey, ticket.FacadeTTY, t, s.Now())
	if err != nil {
		fmt.Fprintln(s.Out, "reveal:", sanitize.Terminal(err.Error(), false))
		return
	}
	kb, _ := json.Marshal(rk)
	fmt.Fprintln(s.Out, "asking the lock for the clear values…")
	ans, err := s.C.Reveal(ctx, it.Instance, it.ID, api.RevealRequest{Facade: ticket.FacadeTTY, Display: s.Display, Key: kb})
	if err != nil {
		fmt.Fprintln(s.Out, "no clear values:", Explain(err))
		return
	}
	// priv lives in this call only: once it returns, the reveal cannot
	// be opened again.
	scr, err := ticket.OpenReveal(lockPub, priv, rk, ans)
	if err != nil {
		fmt.Fprintln(s.Out, "the answer does not verify under the pinned lock key: not shown")
		return
	}
	fmt.Fprint(s.Out, RenderClear(scr))
}

// renew offers an expired ticket for re-approval.
func (s *Session) renew(ctx context.Context, it api.QueueItem) error {
	text, _, err := Screen(it, s.Now())
	if err != nil {
		fmt.Fprintln(s.Out, err)
		return errSkip
	}
	fmt.Fprintln(s.Out, "EXPIRED: this ticket can no longer run")
	fmt.Fprint(s.Out, text)
	for {
		a, err := s.line("approve again? [r] (approved now if nothing changed; otherwise review it) / [s]kip / [q]uit: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(a)) {
		case "r":
		case "s", "skip":
			return errSkip
		case "q", "quit":
			return errQuit
		default:
			continue
		}
		fmt.Fprintln(s.Out, "asking the lock again…")
		res, err := s.C.Renew(ctx, it.Instance, it.ID, api.RenewRequest{Facade: ticket.FacadeTTY, Display: s.Display})
		switch {
		case err != nil:
			fmt.Fprintln(s.Out, "not renewed:", Explain(err))
		case res.AutoApproved:
			fmt.Fprintf(s.Out, "approved again as ticket %s: nothing changed since the expired ticket\n", sanitize.Terminal(res.Ticket, false))
		default:
			fmt.Fprintf(s.Out, "the lock asks again with ticket %s: review it\n", sanitize.Terminal(res.Ticket, false))
		}
		return nil
	}
}

func local(facades []string) bool {
	for _, f := range facades {
		if f == "tty" {
			return true
		}
	}
	return false
}
