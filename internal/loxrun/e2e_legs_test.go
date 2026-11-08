package loxrun_test

import (
	"context"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/lazyconn"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// A profile reached through an SSH bastion, both legs "ask" (#165): the
// lock sends a connect ticket for the bastion, then one for the
// database right after it. lox run asks each leg its own password once,
// seals each its own, and once both connections closed idle the profile
// reconnects on the session's approval with each leg's password, asking
// nothing.
func TestRunE2EBastionLegs(t *testing.T) {
	const sshPassword = "pw-of-the-bastion"
	w := newWorld(t)
	// The bastion leg: a second pool of the same lock, profile A, its own
	// endpoint and password (as locksql dials its SSH tunnel first).
	bastion, err := lazyconn.New(lazyconn.Config[*conn]{
		Lock: "locksql", Asker: w.lock,
		Profile: func(name string) (lazyconn.Profile, error) {
			return lazyconn.Profile{Endpoint: "bastion.internal:22", Credential: ticket.CredentialAsk, NeedSecret: true,
				PolicyFP: policyFP}, nil
		},
		Dial: func(_ context.Context, name string, g lazyconn.Grant) (*conn, error) {
			c := &conn{profile: name + "@bastion", secret: string(g.Secret)}
			w.mu.Lock()
			w.dials = append(w.dials, c)
			w.mu.Unlock()
			return c, nil
		},
		AfterFunc: func(_ time.Duration, f func()) lazyconn.Timer { w.idle <- f; return stopper{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bastion.Close() })
	acquire := func(p *lazyconn.Pool[*conn]) chan error {
		done := make(chan error, 1)
		go func() {
			_, release, err := p.Acquire(context.Background(), lazyconn.Request{Profile: "A",
				Requester: ticket.Requester{Agent: "dev-1", Session: "s1"}, Workspace: "~/e2e"})
			if err == nil {
				release()
			}
			done <- err
		}()
		return done
	}
	connect := func(p *lazyconn.Pool[*conn], leg, typedPw, want string) {
		t.Helper()
		done := acquire(p)
		if typedPw != "" {
			q := w.wait(loxrun.EvQuestion, "")
			w.press(loxrun.R('y'))
			w.press(typed(typedPw)...)
			if d := w.wait(loxrun.EvDecided, q.ID); !d.Approved {
				t.Fatalf("%s: %+v", leg, d)
			}
		} else if d := w.wait(loxrun.EvDecided, ""); !d.Approved || d.Rule != "session:connect" {
			t.Fatalf("%s reconnect: %+v, want session:connect, nothing asked", leg, d)
		}
		if err := <-done; err != nil {
			t.Fatalf("%s: %v", leg, err)
		}
		if c := w.lastDial(); c.secret != want {
			t.Fatalf("%s dialed %+v, want its own password", leg, c)
		}
		w.wait(loxrun.EvResult, "") // consumed: the lock connected
	}

	// Each leg asked once, its own password typed.
	connect(bastion, "bastion", sshPassword, sshPassword)
	connect(w.pool, "database", password, password)

	// Both close idle; the profile reconnects, nothing asked.
	(<-w.idle)()
	(<-w.idle)()
	if bastion.Connected("A") || w.pool.Connected("A") {
		t.Fatal("A still connected after its idle close")
	}
	connect(bastion, "bastion", "", sshPassword)
	connect(w.pool, "database", "", password)
	w.bells(2)
}
