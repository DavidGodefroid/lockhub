package family

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"

	"github.com/DavidGodefroid/lockhub/internal/hub"
)

// hubLimits asks the hub over the facade socket for its pending queue,
// which says it answers, and shows each lock's use of its pending cap.
// The caps are per lock instance, so in practice per workspace: every
// agent of a workspace shares one lock's quota, and one agent can use it
// up for the others.
func (d *Doctor) hubLimits(ctx context.Context, sock string, c *Config, ok, warn, fail func(string, ...any)) {
	cl := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "unix", sock)
		}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://lockhub/v1/queue", nil)
	if err != nil {
		fail("hub: %v", err)
		return
	}
	resp, err := cl.Do(req)
	if err != nil {
		fail("hub does not answer on the facade socket: %v (docker compose logs lockhub)", err)
		return
	}
	defer resp.Body.Close()
	var q struct {
		Tickets []struct {
			Instance string `json:"instance"`
		} `json:"tickets"`
	}
	if resp.StatusCode != http.StatusOK {
		fail("hub answers the facade socket with %s", resp.Status)
		return
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&q); err != nil {
		fail("hub queue: %v", err)
		return
	}
	ok("hub answers on the facade socket: %d ticket(s) pending", len(q.Tickets))
	pending := map[string]int{}
	for _, t := range q.Tickets {
		pending[t.Instance]++
	}
	ok("limits (lockkit defaults as this lox CLI was built): each lock keeps at most %d plans pending and pushes at most %d new tickets per %v (counted in memory, reset when the lock restarts); the hub holds at most %d per lock",
		hubclient.MaxPending, hubclient.RateN, hubclient.RateWindow, hub.DefaultMaxPending)
	ok("the quota is per lock instance, shared by every agent of the workspace: one agent can use it up for the others")
	if c == nil {
		return
	}
	for _, n := range c.Instances() {
		msg := fmt.Sprintf("pending %s on the hub: %d of %d (the lock also counts plans it could not push)", n, pending[n], hubclient.MaxPending)
		if pending[n]*5 >= hubclient.MaxPending*4 {
			warn("%s: near the cap, new requests are refused at it (answer them: lox approve)", msg)
		} else {
			ok("%s", msg)
		}
	}
}
