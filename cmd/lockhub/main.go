// Command lockhub is the Lock Family approval hub: locks push approval
// tickets to it, facades let a human decide them, and the hub signs the
// decisions the locks then verify.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lockhub: the Lock Family approval hub

Usage:
  lockhub serve [--listen ADDR] [--data DIR] [--facade-socket PATH]
                                               serve the lock API (default :8443, /var/lib/lockhub)
                                               and the facade API on a unix socket (lock approve, lea deck)
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
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: codec, Key: key, Locks: locks})
	return h, func() { al.Close(); st.Close() }, nil
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8443", "address to listen on")
	data := fs.String("data", "/var/lib/lockhub", "the hub's data directory")
	facadeSock := fs.String("facade-socket", "", "unix socket for local facades; only the host's human may reach it (empty: none)")
	facadeMode := fs.String("facade-socket-mode", "0600", "file mode of the facade socket")
	if err := fs.Parse(args); err != nil {
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
	go sweep(ctx, h, stderr)
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServe() }()
	if *facadeSock != "" {
		fsrv, err := listenFacade(h, *facadeSock, *facadeMode, errc)
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

// listenFacade serves the facade API on a unix socket created with mode
// (0600 by default: the hub's own account only; lock up maps that account
// to the host user).
func listenFacade(h *hub.Hub, path, mode string, errc chan<- error) (*http.Server, error) {
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil || m&0o007 != 0 {
		return nil, fmt.Errorf("mode %q: an octal mode without access for others", mode)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		os.Remove(path)
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, os.FileMode(m)); err != nil {
		ln.Close()
		return nil, err
	}
	srv := &http.Server{Handler: api.FacadeHandler(h), ReadHeaderTimeout: 10 * time.Second, ConnContext: peer.ConnContext}
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
