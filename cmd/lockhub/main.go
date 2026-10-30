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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lockhub: the Lock Family approval hub

Usage:
  lockhub serve [--listen ADDR]   serve the hub API (default :8443)
  lockhub version                 print the version
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
	default:
		fmt.Fprintf(stderr, "lockhub: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8443", "address to listen on")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(version),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
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
