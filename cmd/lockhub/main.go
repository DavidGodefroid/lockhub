// Command lockhub is the Lock Family approval hub: locks push approval
// tickets to it, facades let a human decide them, and the hub signs the
// decisions the locks then verify.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
	"github.com/DavidGodefroid/lockhub/internal/facade/slack"
	"github.com/DavidGodefroid/lockhub/internal/facade/telegram"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lockhub: the Lock Family approval hub

Usage:
  lockhub serve [--listen ADDR] [--data DIR] [--facade-socket PATH] [--mobile-listen ADDR --mobile-origin URL]
                                               serve the lock API (default :8443, /var/lib/lockhub),
                                               the facade API on a unix socket (lock approve, lea deck)
                                               and the mobile web app on its own listener, reached through
                                               the human's TLS reverse proxy or tunnel at URL
  lockhub keygen [--data DIR]                  create the hub's signing key, print its public half
  lockhub version                              print the version
  lockhub help                    show this help
`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "lockhub", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "serve":
		return serve(ctx, args[1:], stderr)
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lockhub: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// codec is the ticket format (lockkit's ticket package).
var codec hub.Codec = ticketcodec.Codec{}

func keygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "/var/lib/lockhub", "the hub's data directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pub, err := keys.Generate(filepath.Join(*data, "hub.key"))
	if err != nil {
		fmt.Fprintln(stderr, "lockhub keygen:", err)
		return 1
	}
	fmt.Fprintln(stdout, keys.Public(pub))
	return 0
}

// openHub opens the hub on data: hub.key, locks.json, hub.db,
// tickets.jsonl. Anything missing or wrong refuses to start.
func openHub(data string) (*hub.Hub, func(), error) {
	if codec == nil {
		return nil, nil, errors.New("built without a ticket codec")
	}
	key, err := keys.Load(filepath.Join(data, "hub.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("hub key: %w (run lockhub keygen)", err)
	}
	locks, err := keys.LoadLocks(filepath.Join(data, "locks.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("lock instances: %w", err)
	}
	st, err := store.Open(filepath.Join(data, "hub.db"))
	if err != nil {
		return nil, nil, err
	}
	al, err := audit.OpenSigned(filepath.Join(data, "tickets.jsonl"), key)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	routes, err := loadRoutes(filepath.Join(data, "routing.json"), locks)
	if err != nil {
		al.Close()
		st.Close()
		return nil, nil, err
	}
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: codec, Key: key, Locks: locks, Routes: routes})
	// Committed changes whose audit records a crash left in the outbox
	// are logged before anything else happens.
	if err := h.FlushAudit(context.Background()); err != nil {
		al.Close()
		st.Close()
		return nil, nil, err
	}
	return h, func() { al.Close(); st.Close() }, nil
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8443", "address to listen on")
	data := fs.String("data", "/var/lib/lockhub", "the hub's data directory")
	facadeSock := fs.String("facade-socket", "", "unix socket for local facades; only the host's human may reach it (empty: none)")
	facadeMode := fs.String("facade-socket-mode", "0600", "file mode of the facade socket")
	mobileListen := fs.String("mobile-listen", "", "address of the mobile facade's listener (with --mobile-origin; empty: none)")
	mobileOrigin := fs.String("mobile-origin", "", "the https origin phones reach the mobile facade at, through a reverse proxy or tunnel")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*mobileListen == "") != (*mobileOrigin == "") {
		fmt.Fprintln(stderr, "lockhub: --mobile-listen and --mobile-origin go together")
		return 2
	}
	h, closeHub, err := openHub(*data)
	if err != nil {
		fmt.Fprintln(stderr, "lockhub:", err)
		return 1
	}
	defer closeHub()
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.LockHandler(h, version),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	chats, err := chatFacades(h, *data, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lockhub:", err)
		return 1
	}
	go sweep(ctx, h, stderr)
	errc := make(chan error, 2)
	for _, c := range chats {
		// A chat facade that fails for good (a revoked token) stops alone:
		// the hub and its other facades keep serving.
		go func() {
			if err := c.Run(ctx); ctx.Err() == nil {
				fmt.Fprintf(stderr, "lockhub: %s facade stopped: %v\n", c.T.Facade(), err)
			}
		}()
	}
	go func() { errc <- srv.ListenAndServe() }()
	var extra []func(*http.ServeMux)
	if *mobileListen != "" {
		if r := h.Routes(); len(r.Enabled) > 0 && !slices.Contains(r.Enabled, route.Mobile) {
			fmt.Fprintln(stderr, "lockhub: --mobile-listen, and routing.json has mobile not enabled (run lock up)")
			return 1
		}
		m, err := mobile.New(mobile.Config{Hub: h, Origin: *mobileOrigin, HubKeyID: ticket.KeyID(h.PublicKey()), Log: stderr})
		if err != nil {
			fmt.Fprintln(stderr, "lockhub:", err)
			return 1
		}
		// WriteTimeout above the queue's long poll (mobile.MaxWait).
		msrv := &http.Server{Addr: *mobileListen, Handler: m.Handler(), ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: mobile.MaxWait + 30*time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
		go func() { errc <- msrv.ListenAndServe() }()
		defer msrv.Close()
		extra = append(extra, m.FacadeRoutes)
		fmt.Fprintf(stderr, "lockhub %s: mobile facade on %s for %s\n", version, *mobileListen, *mobileOrigin)
	} else if r := h.Routes(); slices.Contains(r.Enabled, route.Mobile) {
		fmt.Fprintln(stderr, "lockhub: routing.json enables mobile, and no --mobile-listen/--mobile-origin (run lock up)")
		return 1
	}
	if *facadeSock != "" {
		fsrv, err := listenFacade(h, *facadeSock, *facadeMode, errc, extra...)
		if err != nil {
			fmt.Fprintln(stderr, "lockhub: facade socket:", err)
			return 1
		}
		defer fsrv.Close()
	}
	fmt.Fprintf(stderr, "lockhub %s: listening on %s\n", version, *listen)
	select {
	case err := <-errc:
		fmt.Fprintln(stderr, "lockhub:", err)
		return 1
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "lockhub: shutdown:", err)
		return 1
	}
	return 0
}

// chatFacades are the chat facades routing.json enables, with their
// settings (chat.json) and secrets. A facade that is not enabled reads
// no secret; one enabled without them refuses to start the hub.
func chatFacades(h *hub.Hub, data string, log io.Writer) ([]*chat.Facade, error) {
	s, err := chatconf.Load(filepath.Join(data, chatconf.File))
	if err != nil {
		return nil, err
	}
	secret := func(name, what, add string) (string, error) {
		v, err := chatconf.ReadSecret(filepath.Join(data, name))
		if err != nil {
			return "", fmt.Errorf("%s: %w (run lock add %s)", what, err, add)
		}
		return v, nil
	}
	enabled := func(f string, configured bool) (bool, error) {
		on := slices.Contains(h.Routes().Enabled, f)
		switch {
		case on && !configured:
			return false, fmt.Errorf("%s is enabled but chat.json has no %s section (run lock up)", f, f)
		case !on && configured:
			return false, fmt.Errorf("chat.json configures %s but routing.json has it not enabled (run lock up)", f)
		}
		return on, nil
	}
	var out []*chat.Facade
	if on, err := enabled(route.Slack, s.Slack != nil); err != nil {
		return nil, err
	} else if on {
		app, err := secret(chatconf.SlackAppToken, "slack app token", "slack")
		if err != nil {
			return nil, err
		}
		bot, err := secret(chatconf.SlackBotToken, "slack bot token", "slack")
		if err != nil {
			return nil, err
		}
		t, err := slack.New(slack.Config{Team: s.Slack.Team, Channel: s.Slack.Channel, Users: s.Slack.Users, AppToken: app, BotToken: bot})
		if err != nil {
			return nil, err
		}
		out = append(out, &chat.Facade{H: h, T: t, Log: log})
	}
	if on, err := enabled(route.Telegram, s.Telegram != nil); err != nil {
		return nil, err
	} else if on {
		tok, err := secret(chatconf.TelegramToken, "telegram bot token", "telegram")
		if err != nil {
			return nil, err
		}
		t, err := telegram.New(telegram.Config{Chats: s.Telegram.Chats, Token: tok})
		if err != nil {
			return nil, err
		}
		out = append(out, &chat.Facade{H: h, T: t, Log: log})
	}
	return out, nil
}

// loadRoutes reads routing.json (written by lock up); missing: defaults.
func loadRoutes(path string, locks map[string]ed25519.PublicKey) (route.Rules, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return route.Rules{}, nil
	} else if err != nil {
		return route.Rules{}, err
	}
	var r route.Rules
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return route.Rules{}, fmt.Errorf("%s: %w", path, err)
	}
	for _, f := range r.Enabled {
		if !route.KnownFacade(f) {
			return route.Rules{}, fmt.Errorf("%s: unknown facade %q", path, f)
		}
	}
	for inst := range r.Only {
		if _, ok := locks[inst]; !ok {
			return route.Rules{}, fmt.Errorf("%s: unknown instance %q", path, inst)
		}
	}
	return r, nil
}

// listenFacade serves the facade API on a unix socket created with mode
// (0600 by default: the hub's own account only; lock up maps that account
// to the host user).
func listenFacade(h *hub.Hub, path, mode string, errc chan<- error, extra ...func(*http.ServeMux)) (*http.Server, error) {
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil || m&0o007 != 0 {
		return nil, fmt.Errorf("mode %q: an octal mode without access for others", mode)
	}
	// The socket's directory must be private: the socket is reachable
	// through it only, whatever the socket's own mode in the instant
	// between listen and chmod.
	dir := filepath.Dir(path)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: want a directory of mode 0700", dir)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		// Do not take over a socket another hub still serves.
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s: another hub is serving it", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, os.FileMode(m)); err != nil {
		ln.Close()
		return nil, err
	}
	srv := &http.Server{Handler: api.FacadeHandler(h, extra...), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10, ConnContext: peer.ConnContext}
	go func() { errc <- srv.Serve(ln) }()
	return srv, nil
}

// sweep expires tickets past their TTL every 30 s.
func sweep(ctx context.Context, h *hub.Hub, stderr io.Writer) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := h.Sweep(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintln(stderr, "lockhub: sweep:", err)
			}
		}
	}
}
