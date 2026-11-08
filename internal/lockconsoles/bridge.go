// Package lockconsoles reaches the locks' consoles at their terminals for
// lox run: it attaches to each lock's container through a pseudo-terminal
// of its own, reads the question the console waits for (the file lockkit
// records next to its socket, lockkit v0.12.1 or later) and the lines it
// printed above it, and types the human's answer there.
//
// An answer goes from lox run's memory to the console's terminal through
// Docker only: never through the hub, never to a log (the consoles have
// none, and the pty echoes nothing). An agent cannot answer: it has no
// Docker, and the question file is the console account's (0600).
package lockconsoles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// ErrUnsupported: no pseudo-terminal on this system.
var ErrUnsupported = errors.New("no pseudo-terminal on this system")

// Lock is a console to follow: its instance and lock type.
type Lock struct {
	Instance, Type string
}

// Docker runs the docker commands of a bridge (Exec: the docker CLI).
type Docker interface {
	// Container is the container of the compose service, "" when it has
	// none; running whether it runs.
	Container(ctx context.Context, service string) (id string, running bool, err error)
	// Question is the console's pending question in its socket directory
	// (dir), "" when it asks nothing.
	Question(ctx context.Context, id, dir string) (string, error)
	// Attach is the command that attaches to the container's terminal.
	Attach(ctx context.Context, id string) *exec.Cmd
}

// Logger is a Docker that reads what a container printed (docker logs):
// the bridge reads the lines a console printed before it attached (its
// start, a policy change refused there) for the lock's feed.
type Logger interface {
	// Logs is what container id printed since since, or its last tail
	// lines when since is zero.
	Logs(ctx context.Context, id string, since time.Time, tail int) ([]byte, error)
}

// Exec is Docker through the docker CLI, on the compose project lox run
// applied.
type Exec struct {
	// Compose is the docker compose arguments that name the project
	// ("-p", project, "--project-directory", dir, "-f", file…).
	Compose []string
}

func (d Exec) Container(ctx context.Context, service string) (string, bool, error) {
	args := append(append([]string{"compose"}, d.Compose...), "ps", "-a", "-q", service)
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return "", false, cmdErr(err)
	}
	id := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if id == "" {
		return "", false, nil
	}
	st, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", id).Output()
	if err != nil {
		return id, false, cmdErr(err)
	}
	return id, strings.TrimSpace(string(st)) == "true", nil
}

func (d Exec) Question(ctx context.Context, id, dir string) (string, error) {
	// As the container's own user, the console account that owns the file.
	out, err := exec.CommandContext(ctx, "docker", "exec", id, "sh", "-c", `cat "$1"/*.question 2>/dev/null; exit 0`, "q", dir).Output()
	if err != nil {
		return "", cmdErr(err)
	}
	q, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(q), nil
}

func (d Exec) Logs(ctx context.Context, id string, since time.Time, tail int) ([]byte, error) {
	args := []string{"logs"}
	if since.IsZero() {
		args = append(args, "--tail", strconv.Itoa(tail))
	} else {
		args = append(args, "--since", since.UTC().Format(time.RFC3339Nano))
	}
	// A console runs in a terminal: its output is all on stdout.
	out, err := exec.CommandContext(ctx, "docker", append(args, id)...).Output()
	if err != nil {
		return nil, cmdErr(err)
	}
	return out, nil
}

func (d Exec) Attach(ctx context.Context, id string) *exec.Cmd {
	// --sig-proxy=false: stopping lox run never signals the console; the
	// bridge leaves with the detach keys.
	return exec.CommandContext(ctx, "docker", "attach", "--sig-proxy=false", "--detach-keys", "ctrl-p,ctrl-q", id)
}

// detachKeys end a docker attach as Ctrl-P Ctrl-Q does: the console keeps
// running.
const detachKeys = "\x10\x11"

// detachWait is how long the attach has to end on the detach keys before
// it is killed.
var detachWait = 2 * time.Second

func cmdErr(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		msg, _, _ := strings.Cut(strings.TrimSpace(string(ee.Stderr)), "\n")
		return errors.New(msg)
	}
	return err
}

// Timings of a bridge.
var (
	// poll is how often a console's question file is read when nothing
	// happens at its terminal; settle how long its output must have
	// stopped before it is read after the console printed something.
	poll   = 2 * time.Second
	settle = 200 * time.Millisecond
	// retry is how long a stopped console is waited for before lox run
	// looks again (Docker restarts it: unless-stopped).
	retry = time.Second
)

// Bridge follows the consoles of a workspace (loxrun.Consoles).
type Bridge struct {
	d      Docker
	events chan loxrun.ConsoleEvent
	mu     sync.Mutex
	cons   map[string]*console
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

var (
	_ loxrun.Consoles         = (*Bridge)(nil)
	_ loxrun.ConsoleCommander = (*Bridge)(nil)
	_ Logger                  = Exec{}
)

// console is one lock's console as the bridge follows it.
type console struct {
	Lock
	// The fields below are the bridge's mu's.
	master *os.File // the pty, while attached
	scr    screen
	// question is the one it waits for (nil: none known); seq counts them.
	question *loxrun.ConsoleQuestion
	seq      int
	// answered: an answer was typed and the console printed nothing
	// since; its question file may still be the answered one's.
	answered bool
	// printed counts the reads of its terminal's output.
	printed uint64
	output  chan struct{}
	state   loxrun.ConsoleState
	err     string
	// id is the container attached to; detached when the last attach
	// ended (the next one reads the logs printed since); statusAsked: the
	// console's :status was typed in this attach.
	id          string
	detached    time.Time
	statusAsked bool
}

// backlog is how many of a console's last lines are read at the first
// attach.
const backlog = 200

// Start follows locks until ctx ends or Close. On a system without a
// pseudo-terminal each one is reported unreachable (lox attach reaches
// it).
func Start(ctx context.Context, d Docker, locks []Lock) *Bridge {
	ctx, cancel := context.WithCancel(ctx)
	b := &Bridge{d: d, events: make(chan loxrun.ConsoleEvent, 64), cons: map[string]*console{}, cancel: cancel}
	for _, l := range locks {
		c := &console{Lock: l, output: make(chan struct{}, 1)}
		b.cons[l.Instance] = c
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.follow(ctx, c)
		}()
	}
	return b
}

// Close detaches from every console (they keep running) and waits until
// no docker attach is left: lox run must not leave one behind.
func (b *Bridge) Close() {
	b.cancel()
	b.wg.Wait()
}

// Events are the consoles' changes.
func (b *Bridge) Events() <-chan loxrun.ConsoleEvent { return b.events }

// Answer types answer and Enter at instance's console, if it still waits
// for question seq.
func (b *Bridge) Answer(instance string, seq int, answer []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.cons[instance]
	if !ok {
		return fmt.Errorf("no console %q", instance)
	}
	if c.master == nil || c.question == nil || c.question.Seq != seq {
		return errors.New("the console no longer asks this question")
	}
	buf := append(slices.Clone(answer), '\r')
	defer clear(buf)
	if _, err := c.master.Write(buf); err != nil {
		return fmt.Errorf("cannot type at the console's terminal: %w", err)
	}
	c.question, c.answered = nil, true
	c.scr.Mark()
	return nil
}

// Command types line (one of the console's own commands: :review,
// :status) and Enter at instance's console, when it serves and asks
// nothing: its question file is read again first, so that a line is
// never typed as the answer to a question.
func (b *Bridge) Command(instance, line string) error {
	b.mu.Lock()
	c, ok := b.cons[instance]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("no console %q", instance)
	}
	id, printed := c.id, c.printed
	serving := c.master != nil && c.question == nil && c.state == loxrun.ConsoleServing
	b.mu.Unlock()
	if !serving {
		return errors.New("the console is not serving, or it asks something")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, err := b.d.Question(ctx, id, "/run/"+c.Type)
	if err != nil {
		return err
	}
	if q != "" {
		return errors.New("the console asks something: answer it first")
	}
	return b.typeLine(c, line, printed)
}

// typeLine types line and Enter at c's terminal, if it is attached, asks
// nothing and printed nothing since its question file was read (printed:
// c.printed then): what it printed may be a question's prompt.
func (b *Bridge) typeLine(c *console, line string, printed uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.master == nil || c.question != nil {
		return errors.New("the console is not serving, or it asks something")
	}
	if c.printed != printed {
		return errors.New("the console printed something meanwhile: try again")
	}
	if _, err := c.master.WriteString(line + "\r"); err != nil {
		return fmt.Errorf("cannot type at the console's terminal: %w", err)
	}
	return nil
}

// event is c's state as it is now. mu held.
func (c *console) event() loxrun.ConsoleEvent {
	e := loxrun.ConsoleEvent{Instance: c.Instance, Lock: c.Type, State: c.state, Err: c.err}
	if c.question != nil {
		q := *c.question
		q.Context = slices.Clone(q.Context)
		e.Question = &q
	}
	return e
}

// send hands e to lox run; mu is not held (lox run's loop may be in
// Answer).
func (b *Bridge) send(ctx context.Context, e loxrun.ConsoleEvent) {
	select {
	case b.events <- e:
	case <-ctx.Done():
	}
}

func (b *Bridge) set(ctx context.Context, c *console, s loxrun.ConsoleState, msg string) {
	b.mu.Lock()
	if c.state == s && c.err == msg {
		b.mu.Unlock()
		return
	}
	c.state, c.err, c.question = s, msg, nil
	e := c.event()
	b.mu.Unlock()
	b.send(ctx, e)
}

// follow attaches to c's console whenever its container runs, until ctx
// ends.
func (b *Bridge) follow(ctx context.Context, c *console) {
	b.set(ctx, c, loxrun.ConsoleStarting, "")
	for ctx.Err() == nil {
		id, running, err := b.d.Container(ctx, "lock-"+c.Instance)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			b.set(ctx, c, loxrun.ConsoleUnreachable, err.Error())
		case !running:
			b.set(ctx, c, loxrun.ConsoleStopped, b.lastLine(c))
		default:
			if err := b.attach(ctx, c, id); errors.Is(err, ErrUnsupported) {
				b.set(ctx, c, loxrun.ConsoleUnreachable, err.Error())
				return
			} else if err != nil && ctx.Err() == nil {
				b.set(ctx, c, loxrun.ConsoleUnreachable, err.Error())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// lastLine is the last line c's console printed (why it stopped).
func (b *Bridge) lastLine(c *console) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ls := c.scr.Last(maxLines)
	if len(ls) == 0 {
		return c.err
	}
	return strings.TrimSpace(ls[len(ls)-1])
}

// attach follows c's console through one docker attach, until the
// container stops or ctx ends.
func (b *Bridge) attach(ctx context.Context, c *console, id string) error {
	master, slave, err := pty.Open()
	if errors.Is(err, pty.ErrUnsupported) {
		return ErrUnsupported
	} else if err != nil {
		return err
	}
	if err := prepare(slave); err != nil {
		master.Close()
		slave.Close()
		return err
	}
	b.backlog(ctx, c, id)
	// The attach outlives ctx by the detach: it is killed only when it
	// does not end on the detach keys.
	actx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	cmd := b.d.Attach(actx, id)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = ownTerminal()
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return err
	}
	slave.Close()
	b.mu.Lock()
	c.master, c.question, c.answered, c.id, c.statusAsked = master, nil, false, id, false
	b.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				b.mu.Lock()
				c.scr.Write(buf[:n])
				c.answered = false
				c.printed++
				b.mu.Unlock()
				select {
				case c.output <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	b.look(ctx, c, id)
	tick := time.NewTicker(poll)
	defer tick.Stop()
	var settled <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			b.mu.Lock()
			_, _ = master.WriteString(detachKeys)
			b.mu.Unlock()
			select {
			case <-exited:
			case <-time.After(detachWait):
				cancel()
				<-exited
			}
			b.detach(c, master)
			<-done
			return nil
		case err := <-exited:
			b.detach(c, master)
			<-done
			if err != nil && !isExit(err) {
				return err
			}
			return nil
		case <-c.output:
			settled = time.After(settle)
		case <-settled:
			settled = nil
			b.look(ctx, c, id)
			b.flush(ctx, c)
		case <-tick.C:
			b.look(ctx, c, id)
			b.flush(ctx, c)
		}
	}
}

func isExit(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

func (b *Bridge) detach(c *console, master *os.File) {
	b.mu.Lock()
	c.master, c.question, c.detached = nil, nil, time.Now()
	b.mu.Unlock()
	master.Close()
}

// backlog hands lox run what c's console printed before this attach:
// its last lines at the first attach, what it printed since the last
// one after (a restart's start, a policy change refused there).
func (b *Bridge) backlog(ctx context.Context, c *console, id string) {
	lg, ok := b.d.(Logger)
	if !ok {
		return
	}
	b.mu.Lock()
	since := c.detached
	b.mu.Unlock()
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := lg.Logs(lctx, id, since, backlog)
	if err != nil || len(out) == 0 {
		return
	}
	var scr screen
	scr.Write(out)
	scr.endLine() // a last line without its newline (a prompt) is read too
	lines, status, set := scr.Take()
	b.send(ctx, loxrun.ConsoleEvent{Instance: c.Instance, Lock: c.Type,
		Feed: &loxrun.ConsoleFeed{Lines: lines, Status: status, StatusSet: set, Backlog: true}})
}

// flush hands lox run the lines c's console printed since the last
// flush, for the lock's feed. Once per attach, when the console serves
// (its status row is drawn) and asks nothing, it types :status for the
// limits in force (a line typed counts as the human's activity for the
// console's idle timeout: once per attach only).
func (b *Bridge) flush(ctx context.Context, c *console) {
	b.mu.Lock()
	lines, status, set := c.scr.Take()
	ask := !c.statusAsked && c.scr.status != "" && c.question == nil && !c.answered &&
		c.state == loxrun.ConsoleServing && c.master != nil
	if ask {
		c.statusAsked = true
	}
	b.mu.Unlock()
	if len(lines) > 0 || set {
		b.send(ctx, loxrun.ConsoleEvent{Instance: c.Instance, Lock: c.Type,
			Feed: &loxrun.ConsoleFeed{Lines: lines, Status: status, StatusSet: set}})
	}
	if ask {
		_ = b.Command(c.Instance, ":status")
	}
}

// look reads c's pending question and tells what changed.
func (b *Bridge) look(ctx context.Context, c *console, id string) {
	b.mu.Lock()
	skip := c.answered
	b.mu.Unlock()
	if skip {
		return // the answered question's file may still be there
	}
	q, err := b.d.Question(ctx, id, "/run/"+c.Type)
	if err != nil || ctx.Err() != nil {
		return
	}
	b.mu.Lock()
	if c.answered || c.master == nil {
		b.mu.Unlock()
		return
	}
	changed := false
	switch {
	case q == "":
		if c.state != loxrun.ConsoleServing {
			c.state, c.err, c.question = loxrun.ConsoleServing, "", nil
			changed = true
		}
	case c.question == nil || c.question.Prompt != q:
		c.seq++
		c.question = &loxrun.ConsoleQuestion{Seq: c.seq, Prompt: q, Context: contextOf(c.scr.Last(maxLines), q)}
		c.state, c.err = loxrun.ConsoleWaiting, ""
		changed = true
	}
	e := c.event()
	b.mu.Unlock()
	if changed {
		b.send(ctx, e)
	}
}

// contextOf is the lines above a question: at most the last 16 since
// the previous answer, the prompt itself left out when it ends them.
func contextOf(lines []string, prompt string) []string {
	if n := len(lines); n > 0 && strings.TrimSpace(lines[n-1]) == prompt {
		lines = lines[:n-1]
	}
	if len(lines) > 16 {
		lines = lines[len(lines)-16:]
	}
	return lines
}

var _ io.Writer = (*screen)(nil)
