// Package mobilecli is `lock mobile`: pairing a phone with the hub's
// mobile facade at the host's terminal, listing and revoking devices,
// over the facade socket.
//
// Pairing binds the device to the human of this host: the code is shown
// here only, and the device is pinned only after the human confirmed, at
// this terminal, that the fingerprint shown here is the one the phone
// computed from its own keys.
package mobilecli

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

	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
	"github.com/DavidGodefroid/lockhub/internal/family"
)

// Client talks to the facade socket.
type Client struct{ HTTP *http.Client }

// Dial is a client for the facade socket at path.
func Dial(path string) *Client {
	return &Client{HTTP: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://lockhub"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("hub facade socket: %w (is the hub up, with the mobile facade? lock up)", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/v1/mobile/pairings") && method == http.MethodPost && !strings.Contains(path, "confirm") {
		return errors.New("the hub runs no mobile facade: add mobile to hub.facades with hub.mobile.origin, then lock up")
	}
	if resp.StatusCode/100 != 2 {
		var e struct{ Error, Message string }
		json.Unmarshal(b, &e)
		return fmt.Errorf("hub: %s", sanitize.Terminal(e.Message, false))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Pair runs one pairing: the code, the wait for the phone, the human's
// confirmation of the fingerprint, then the device pinned in state (lock
// up's state directory of the workspace).
//
// origin is hub.mobile.origin from lockfamily.yaml: a device registered
// at any other origin (a phishing page relaying the code) is refused.
func Pair(ctx context.Context, c *Client, name, origin, state string, in *bufio.Reader, out io.Writer) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("hub.mobile.origin: not an https origin")
	}
	var start mobile.PairStartResult
	if err := c.do(ctx, http.MethodPost, "/v1/mobile/pairings", mobile.PairStart{Name: name}, &start); err != nil {
		return err
	}
	code := start.Code
	if len(code) == 8 {
		code = code[:4] + " " + code[4:]
	}
	fmt.Fprintf(out, "On the phone, open %s and enter the pairing code:\n\n    %s\n\n(valid until %s)\nWaiting for the phone…\n",
		sanitize.Terminal(start.URL, false), code, start.Expires.Local().Format("15:04:05"))
	var st mobile.PairStateResult
	for {
		if err := c.do(ctx, http.MethodGet, "/v1/mobile/pairings/"+url.PathEscape(start.ID)+"?wait=30", nil, &st); err != nil {
			// Interrupted: the code stops working now, not in 5 minutes.
			c.do(context.Background(), http.MethodPost, "/v1/mobile/pairings/"+url.PathEscape(start.ID)+"/confirm", mobile.PairConfirm{Confirm: false}, nil)
			return err
		}
		if st.State != "waiting" {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if st.State != "registered" || st.Device == nil {
		return fmt.Errorf("pairing %s: start again with lock mobile pair", st.State)
	}
	// The fingerprint shown is computed here, from the record itself.
	fp, err := st.Device.Fingerprint()
	if err != nil || st.Device.Validate() != nil || fp != st.Fingerprint || st.Device.Name != name ||
		st.Device.Origin != origin || st.Device.RPID != u.Hostname() {
		c.do(ctx, http.MethodPost, "/v1/mobile/pairings/"+url.PathEscape(start.ID)+"/confirm", mobile.PairConfirm{Confirm: false}, nil)
		return errors.New("the hub sent an invalid device record: refused")
	}
	fmt.Fprintf(out, "\nA device registered as %q (%s).\nThe phone shows its fingerprint. This one is:\n\n    %s\n\nIs it exactly the one on the phone? [y/N] ",
		st.Device.Name, st.Device.ID, fp)
	a, _ := in.ReadString('\n')
	ok := strings.ToLower(strings.TrimSpace(a)) == "y"
	var conf mobile.PairConfirmResult
	if err := c.do(ctx, http.MethodPost, "/v1/mobile/pairings/"+url.PathEscape(start.ID)+"/confirm", mobile.PairConfirm{Confirm: ok, Fingerprint: fp}, &conf); err != nil {
		return err
	}
	if !ok {
		return errors.New("not confirmed: the device was not paired")
	}
	devs, err := ticket.ParseDevices([]byte(`{"devices":[` + string(conf.Record) + `],"v":1}`))
	if err != nil {
		return fmt.Errorf("the hub recorded an invalid device: %w", err)
	}
	if got, _ := devs[0].Fingerprint(); got != fp || devs[0].Origin != origin {
		return errors.New("the hub recorded another device than the one confirmed: not pinned; revoke it with lock mobile revoke")
	}
	if err := family.PinDevice(state, devs[0]); err != nil {
		return err
	}
	fmt.Fprintf(out, "Paired %s. Run lock up to pin it at the locks: until then they refuse its decisions.\n", name)
	return nil
}

// List prints the hub's devices and whether lock up pins them.
func List(ctx context.Context, c *Client, state string, out io.Writer) error {
	var ds []mobile.DeviceInfo
	if err := c.do(ctx, http.MethodGet, "/v1/mobile/devices", nil, &ds); err != nil {
		return err
	}
	pinned, err := family.ReadDevices(state)
	if err != nil {
		return err
	}
	isPinned := map[string]bool{}
	for _, d := range pinned {
		isPinned[d.ID] = true
	}
	if len(ds) == 0 {
		fmt.Fprintln(out, "no device paired (lock mobile pair --name NAME)")
	}
	for _, d := range ds {
		p := "not pinned at the locks"
		if isPinned[d.ID] {
			p = "pinned"
		}
		fmt.Fprintf(out, "%-16s %s  %-7s  %s  %s\n", sanitize.Terminal(d.Name, false), d.ID, d.State, d.Fingerprint, p)
	}
	return nil
}

// Revoke revokes a device (by name or id) at the hub and unpins it.
func Revoke(ctx context.Context, c *Client, which, state string, out io.Writer) error {
	var ds []mobile.DeviceInfo
	if err := c.do(ctx, http.MethodGet, "/v1/mobile/devices", nil, &ds); err != nil {
		return err
	}
	id := ""
	for _, d := range ds {
		if d.ID == which || (d.Name == which && d.State == "active") {
			id = d.ID
		}
	}
	if id == "" {
		// Unknown at the hub: still unpin it here.
		for _, d := range mustDevices(state) {
			if d.ID == which || d.Name == which {
				id = d.ID
			}
		}
	}
	if id == "" {
		return fmt.Errorf("no device %q", which)
	}
	if err := c.do(ctx, http.MethodPost, "/v1/mobile/devices/"+url.PathEscape(id)+"/revoke", struct{}{}, nil); err != nil && !strings.Contains(err.Error(), "no such device") {
		return err
	}
	if _, err := family.UnpinDevice(state, id); err != nil {
		return err
	}
	fmt.Fprintf(out, "Revoked %s at the hub. Run lock up to unpin it at the locks.\n", id)
	return nil
}

func mustDevices(state string) []ticket.Device {
	d, _ := family.ReadDevices(state)
	return d
}
