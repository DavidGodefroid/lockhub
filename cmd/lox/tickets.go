package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// ticketsHub is what lox tickets and lox withdraw need of the hub's
// facade socket (approve.Client).
type ticketsHub interface {
	QueueAll(ctx context.Context, since uint64, wait time.Duration) (api.QueueResult, error)
	Withdraw(ctx context.Context, instance, id string, req api.WithdrawRequest) (api.WithdrawResult, error)
}

// pinnedLockKeys are the lock keys lox run pinned (none: every ticket is
// listed unverified, never as an error).
func pinnedLockKeys(dir string, stderr io.Writer, cmd string) map[string]ed25519.PublicKey {
	k, err := keys.LoadLocks(filepath.Join(dir, family.LockKeysFile))
	if err != nil {
		fmt.Fprintln(stderr, cmd+": no pinned lock keys in", dir, "(", err, "): tickets are listed unchecked")
		return map[string]ed25519.PublicKey{}
	}
	return k
}

// pendingTickets lists the hub's pending tickets, of lock (an instance;
// "" all), only those lox run cannot verify with errOnly.
func pendingTickets(ctx context.Context, h ticketsHub, lks map[string]ed25519.PublicKey, lock string, errOnly bool) ([]loxrun.PendingTicket, error) {
	res, err := h.QueueAll(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	var out []loxrun.PendingTicket
	for _, p := range loxrun.Pending(res.Tickets, lks) {
		if (lock == "" || p.Instance == lock) && (!errOnly || p.Unverifiable) {
			out = append(out, p)
		}
	}
	return out, nil
}

// ticketsCmd is lox tickets: the tickets pending at the hub, oldest
// first, with their age, as lox run's w overlay lists them.
func ticketsCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tickets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	keysDir := fs.String("facade-keys", family.FacadeKeysDir(stateHome()), "the pinned lock keys, as lox run wrote them")
	lock := fs.String("lock", "", "only this lock instance's tickets")
	fs.Bool("pending", true, "every pending ticket (the default)")
	errOnly := fs.Bool("error", false, "only the tickets lox run cannot verify")
	asJSON := fs.Bool("json", false, "one JSON object per ticket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox tickets: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return listTickets(ctx, approve.Dial(*sock), pinnedLockKeys(*keysDir, stderr, "lox tickets"), *lock, *errOnly, *asJSON, time.Now(), stdout, stderr)
}

func listTickets(ctx context.Context, h ticketsHub, lks map[string]ed25519.PublicKey, lock string, errOnly, asJSON bool, now time.Time, stdout, stderr io.Writer) int {
	ps, err := pendingTickets(ctx, h, lks, lock, errOnly)
	if err != nil {
		fmt.Fprintln(stderr, "lox tickets:", approve.Explain(err))
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		for _, p := range ps {
			_ = enc.Encode(p)
		}
		return 0
	}
	if len(ps) == 0 {
		fmt.Fprintln(stdout, "nothing pending")
		return 0
	}
	for _, p := range ps {
		state := "pending"
		switch {
		case p.Unverifiable:
			state = "unverifiable: " + p.Error
		case !p.Answerable:
			state = "not answerable in lox run"
		}
		fmt.Fprintf(stdout, "%-8s %s/%s  %s  %s  %s\n", shortAge(now.Sub(p.Created)), p.Instance, p.ID, p.Risk, state, p.Summary)
	}
	fmt.Fprintf(stdout, "%d pending; lox withdraw INSTANCE/ID… or --lock NAME --all-pending takes them back\n", len(ps))
	return 0
}

// shortAge is a duration as lox run shows a ticket's age.
func shortAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", max(int(d/time.Second), 0))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
}

// withdrawCmd is lox withdraw: the human takes back pending tickets
// without lox run (scripts, recovery). Each ends withdrawn at the hub,
// audited with the human, and its lock is told (it ends the plan and
// frees its queue).
func withdrawCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("withdraw", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	keysDir := fs.String("facade-keys", family.FacadeKeysDir(stateHome()), "the pinned lock keys, as lox run wrote them")
	lock := fs.String("lock", "", "the lock instance whose tickets to withdraw (with --all-pending or --error)")
	all := fs.Bool("all-pending", false, "with --lock: every pending ticket of the lock")
	errOnly := fs.Bool("error", false, "with --lock: every pending ticket of the lock that lox run cannot verify")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	const use = "usage: lox withdraw INSTANCE/ID… | --lock NAME --all-pending|--error"
	if (len(pos) > 0) == (*lock != "") || (*lock != "") != (*all || *errOnly) || (*all && *errOnly) {
		fmt.Fprintln(stderr, use)
		return 2
	}
	var refs [][2]string
	for _, p := range pos {
		in, id, ok := strings.Cut(p, "/")
		if !ok || in == "" || id == "" {
			fmt.Fprintln(stderr, "lox withdraw: not INSTANCE/ID:", p)
			return 2
		}
		refs = append(refs, [2]string{in, id})
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := approve.Dial(*sock)
	if *lock != "" {
		ps, err := pendingTickets(ctx, c, pinnedLockKeys(*keysDir, stderr, "lox withdraw"), *lock, *errOnly)
		if err != nil {
			fmt.Fprintln(stderr, "lox withdraw:", approve.Explain(err))
			return 1
		}
		for _, p := range ps {
			refs = append(refs, [2]string{p.Instance, p.ID})
		}
		if len(refs) == 0 {
			fmt.Fprintln(stdout, "nothing to withdraw for", *lock)
			return 0
		}
	}
	return withdrawTickets(ctx, c, refs, os.Getenv("USER"), stdout, stderr)
}

func withdrawTickets(ctx context.Context, h ticketsHub, refs [][2]string, display string, stdout, stderr io.Writer) int {
	code, n := 0, 0
	for _, r := range refs {
		res, err := h.Withdraw(ctx, r[0], r[1], api.WithdrawRequest{Facade: route.TTY, Display: display, Via: hub.ViaCLI})
		if err != nil {
			fmt.Fprintf(stderr, "lox withdraw: %s/%s: %s\n", r[0], r[1], approve.Explain(err))
			code = 1
			continue
		}
		n++
		told := "its lock is told"
		if !res.Told {
			told = "the hub cannot verify it: its lock ends it with its TTL"
		}
		fmt.Fprintf(stdout, "withdrawn %s/%s (%s)\n", r[0], r[1], told)
	}
	fmt.Fprintf(stdout, "%d of %d withdrawn\n", n, len(refs))
	return code
}
