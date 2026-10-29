// Command lock is the Lock Family CLI on the host: it answers approvals
// in a terminal (lock approve) and, with the issues that add them, sets
// up the hub and the locks of a workspace (lock up, add, import, doctor).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/approve"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lock: the Lock Family CLI

Usage:
  lock approve [--socket PATH] [--once]   answer approval tickets in this terminal
  lock version                            print the version
  lock help                               show this help

Coming: lock up, lock audit verify, lock add, lock import, lock doctor.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "lock", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "approve":
		return approveCmd(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lock: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// defaultSocket is where lock up publishes the hub's facade socket.
func defaultSocket() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("lockhub-%d", os.Getuid()))
	}
	return filepath.Join(dir, "lockhub", "facade.sock")
}

func approveCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	once := fs.Bool("once", false, "answer what is waiting, then exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Approvals are typed by a human at a terminal, never piped.
	if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stderr, "lock approve: stdin is not a terminal")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &approve.Session{C: approve.Dial(*sock), In: bufio.NewReader(stdin), Out: stdout, Display: os.Getenv("USER"), Once: *once}
	if err := s.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "lock approve:", err)
		return 1
	}
	return 0
}
