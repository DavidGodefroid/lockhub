package mobile

// Web Push (optional, --mobile-push): when a ticket the phone may answer
// becomes pending, the hub asks the push service of each active device's
// subscriptions to wake it. The push carries no payload (nothing about the
// ticket reaches the push service, so no RFC 8291 encryption is needed);
// the service worker shows a generic notification and the web app reads
// the queue from the hub as usual. The hub authenticates to the push
// service with VAPID (RFC 8292): an ES256 JWT for the endpoint's origin,
// signed with a P-256 key kept in the hub's data directory.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Web Push settings.
const (
	// VAPIDLifetime is how long a VAPID token is valid (RFC 8292 allows up
	// to 24 h).
	VAPIDLifetime = 12 * time.Hour
	// PushTTL is how long a push service keeps a push for an offline phone.
	PushTTL = 30 * time.Minute
	// PushTopic replaces a push still queued at the push service by the
	// next one: a phone coming online gets one wake-up, not one per ticket.
	PushTopic = "lockhub-pending"
	// PushInterval is the least time between two rounds of pushes: tickets
	// arriving meanwhile are coalesced into the next round.
	PushInterval = 30 * time.Second
	// MaxPushSubscriptions per device (the oldest go).
	MaxPushSubscriptions = 4
	maxEndpoint          = 2048
	pushTimeout          = 10 * time.Second
)

// pushHosts are the push services' hosts, exactly; pushSuffixes those
// they use under a domain of theirs: one more label, no deeper.
var (
	pushHosts    = []string{"fcm.googleapis.com", "updates.push.services.mozilla.com"}
	pushSuffixes = []struct{ suffix, prefix string }{
		{".push.apple.com", ""},
		{".notify.windows.com", "wns2-"},
	}
)

// checkEndpoint accepts a subscription endpoint only on a known push
// service: https, its default port, a host name (no IP, no user info, no
// fragment). The hub POSTs to no other host.
func checkEndpoint(raw string) (*url.URL, error) {
	bad := errors.New("not a push service endpoint")
	if raw == "" || len(raw) > maxEndpoint || strings.ContainsAny(raw, " \t\r\n\\") {
		return nil, bad
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.Contains(raw, "#") ||
		u.Host == "" || u.Host != u.Hostname() || u.Port() != "" || len(u.Path) < 2 || u.Path[0] != '/' {
		return nil, bad
	}
	h := u.Host
	if _, err := netip.ParseAddr(h); err == nil {
		return nil, bad
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return nil, bad
		}
	}
	for _, x := range pushHosts {
		if h == x {
			return u, nil
		}
	}
	for _, x := range pushSuffixes {
		if l, ok := strings.CutSuffix(h, x.suffix); ok && validLabel(l) && strings.HasPrefix(l, x.prefix) && len(l) > len(x.prefix) {
			return u, nil
		}
	}
	return nil, bad
}

func validLabel(l string) bool {
	return l != "" && len(l) <= 63 && !strings.Contains(l, ".") && l[0] != '-' && l[len(l)-1] != '-'
}

// pusher sends the pushes. Its hooks (client, allow, interval) are
// replaced by tests only (export_test.go).
type pusher struct {
	key      *ecdsa.PrivateKey
	pub      string // the uncompressed point, base64url: applicationServerKey
	sub      string
	client   *http.Client
	allow    func(string) (*url.URL, error)
	interval time.Duration
	kick     chan struct{}
}

func newPusher(key *ecdsa.PrivateKey, subject string) (*pusher, error) {
	ek, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("mobile: vapid key: %w", err)
	}
	return &pusher{key: key, pub: b64.EncodeToString(ek.Bytes()), sub: subject, client: pushClient(),
		allow: checkEndpoint, interval: PushInterval, kick: make(chan struct{}, 1)}, nil
}

// pushClient reaches the push services only: no proxy, no redirect
// followed, public addresses only (an allowed name that resolves to a
// non-public address is refused at dial time), short timeouts.
func pushClient() *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !publicAddr(ap.Addr()) {
			return fmt.Errorf("push: %s is not a public address", ap.Addr())
		}
		return nil
	}}
	tr := &http.Transport{Proxy: nil, DialContext: d.DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: pushTimeout, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second}
	return &http.Client{Transport: tr, Timeout: pushTimeout + 5*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// specialRanges are special-purpose ranges (IANA registries) that
// netip's IsGlobalUnicast lets through: no push service lives there.
var specialRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // this network
		"100.64.0.0/10",   // shared address space (CGNAT)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"192.88.99.0/24",  // 6to4 relay anycast
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved
		"64:ff9b::/96",    // NAT64 (embeds any IPv4)
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard-only
		"2001::/23",       // IETF protocol assignments (Teredo, ORCHID, …)
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4 (embeds any IPv4)
		"3fff::/20",       // documentation
		"fec0::/10",       // site-local (deprecated)
		"::ffff:0:0:0/96", // IPv4-translated
		"5f00::/16",       // SRv6 SIDs
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// publicAddr reports whether a is a public unicast address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range specialRanges {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// vapidToken is the VAPID JWT (RFC 8292) for aud, a push service origin.
func (p *pusher) vapidToken(aud string, now time.Time) (string, error) {
	hdr := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{aud, now.Add(VAPIDLifetime).Unix(), p.sub})
	if err != nil {
		return "", err
	}
	in := hdr + "." + b64.EncodeToString(claims)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64.EncodeToString(sig), nil
}

// onPending wakes the push loop for a ticket the phone may answer (the
// queue's visibility and routing): never blocks the lock API.
func (s *Service) onPending(p hub.Pending) {
	rules := s.c.Hub.Routes()
	if !visible(rules, p.Instance) || rules.Allowed(p.Instance, route.Mobile, p.Risk) != nil {
		return
	}
	select {
	case s.push.kick <- struct{}{}:
	default: // a round is due already
	}
}

// RunPush sends the pushes until ctx ends (nothing without push).
func (s *Service) RunPush(ctx context.Context) {
	p := s.push
	if p == nil {
		return
	}
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
		}
		if !last.IsZero() {
			if w := p.interval - time.Since(last); w > 0 {
				t := time.NewTimer(w)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
		}
		// Tickets that came while waiting are in this round.
		select {
		case <-p.kick:
		default:
		}
		last = time.Now()
		s.pushAll(ctx)
	}
}

func (s *Service) logf(format string, a ...any) {
	if s.c.Log != nil {
		fmt.Fprintf(s.c.Log, "lockhub: mobile push: "+format+"\n", a...)
	}
}

// pushAll pushes to every subscription of an active device.
func (s *Service) pushAll(ctx context.Context) {
	subs, err := s.c.Hub.Store().PushSubscriptions(ctx, "")
	if err != nil {
		if ctx.Err() == nil {
			s.logf("subscriptions unavailable: %v", err)
		}
		return
	}
	for _, sub := range subs {
		if ctx.Err() != nil {
			return
		}
		s.pushOne(ctx, sub)
	}
}

// pushOne sends one payload-less push. Only the endpoint's host is ever
// logged: its path is the subscription's secret.
func (s *Service) pushOne(ctx context.Context, sub store.PushSubscription) {
	p := s.push
	u, err := p.allow(sub.Endpoint)
	if err != nil {
		s.c.Hub.Store().DeletePushSubscription(ctx, "", sub.Endpoint)
		return
	}
	tok, err := p.vapidToken(u.Scheme+"://"+u.Host, s.c.Now())
	if err != nil {
		s.logf("vapid: %v", err)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, u.String(), http.NoBody)
	if err != nil {
		return
	}
	req.Header.Set("TTL", strconv.Itoa(int(PushTTL/time.Second)))
	req.Header.Set("Urgency", "high")
	req.Header.Set("Topic", PushTopic)
	req.Header.Set("Authorization", "vapid t="+tok+", k="+p.pub)
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			s.logf("%s: unreachable", u.Host)
		}
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		// The subscription ended (unsubscribed, expired): forget it.
		s.c.Hub.Store().DeletePushSubscription(ctx, "", sub.Endpoint)
		s.logf("%s: subscription gone, removed", u.Host)
	case resp.StatusCode/100 != 2:
		s.logf("%s: status %d", u.Host, resp.StatusCode)
	}
}

// --- /m/v1/push ----------------------------------------------------------

// PushInfo answers GET /m/v1/push: the hub's VAPID public key (the web
// app's applicationServerKey) and how many subscriptions this device has.
type PushInfo struct {
	Key           string `json:"key"`
	Subscriptions int    `json:"subscriptions"`
}

// PushSubscribe is POST /m/v1/push/subscribe and /unsubscribe: the
// subscription's endpoint (its keys are not needed: pushes carry no
// payload).
type PushSubscribe struct {
	Endpoint string `json:"endpoint"`
}

func (s *Service) pushInfo(w http.ResponseWriter, r *http.Request) {
	subs, err := s.c.Hub.Store().PushSubscriptions(r.Context(), deviceOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "subscriptions unavailable")
		return
	}
	writeJSON(w, http.StatusOK, PushInfo{Key: s.push.pub, Subscriptions: len(subs)})
}

func (s *Service) pushSubscribe(w http.ResponseWriter, r *http.Request) {
	var req PushSubscribe
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a subscription")
		return
	}
	if _, err := s.push.allow(req.Endpoint); err != nil {
		writeErr(w, http.StatusBadRequest, "endpoint", "this browser's push service is not one the hub reaches")
		return
	}
	err := s.c.Hub.Store().PutPushSubscription(r.Context(), deviceOf(r), req.Endpoint, MaxPushSubscriptions, s.c.Now())
	switch {
	case errors.Is(err, store.ErrDeviceInactive):
		writeErr(w, http.StatusUnauthorized, "login", "this device is no longer active")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal", "cannot record the subscription")
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (s *Service) pushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	var req PushSubscribe
	if err := readJSON(r, &req); err != nil || req.Endpoint == "" || len(req.Endpoint) > maxEndpoint {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a subscription")
		return
	}
	if err := s.c.Hub.Store().DeletePushSubscription(r.Context(), deviceOf(r), req.Endpoint); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "cannot drop the subscription")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
