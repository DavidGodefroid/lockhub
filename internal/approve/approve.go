// Package approve is `lock approve`: the terminal facade. It follows the
// hub's queue over the host facade socket, shows each ticket's screen (as
// the lock masked it) and sends the human's answer.
package approve

import (
	"bufio"
	"bytes"
	"context"
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
	var r api.QueueResult
	err := c.do(ctx, "GET", fmt.Sprintf("/v1/queue?since=%d&wait=%d", since, int(wait/time.Second)), nil, &r)
	return r.Tickets, r.Version, err
}

// Decide sends a decision.
func (c *Client) Decide(ctx context.Context, instance, id string, req api.DecideRequest) error {
	var r api.DecideResult
	return c.do(ctx, "POST", "/v1/tickets/"+url.PathEscape(instance)+"/"+url.PathEscape(id)+"/decide", req, &r)
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
	return b.String(), &t, nil
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
		items, v, err := s.C.Queue(ctx, ver, wait)
		ver = v
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("hub: %w", err)
		}
		var todo []api.QueueItem
		for _, it := range items {
			if !skipped[it.Instance+"/"+it.ID] {
				todo = append(todo, it)
			}
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
					fmt.Fprintln(s.Out, "hub refused:", sanitize.Terminal(he.Message, false))
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
	for {
		a, err := s.line("approve? [y]es / [n]o <reason> / [s]kip / [q]uit: ")
		if err != nil {
			return err
		}
		verb, reason, _ := strings.Cut(strings.TrimSpace(a), " ")
		req := api.DecideRequest{Facade: "tty", Display: s.Display, Reason: strings.TrimSpace(reason)}
		switch strings.ToLower(verb) {
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

func local(facades []string) bool {
	for _, f := range facades {
		if f == "tty" {
			return true
		}
	}
	return false
}
