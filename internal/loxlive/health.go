package loxlive

import (
	"sync"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// A lock's state in the health.
const (
	// Serving: its console runs and asks nothing.
	Serving = "serving"
	// NeedsEnrolment: what would start is not what a human enrolled, or
	// its console asks a human to review its policy or type its
	// production profile's name.
	NeedsEnrolment = "needs_enrolment"
	// MissingSecret: it needs a secret lox live does not hold (a password
	// a human types, a Vault token the host cannot give).
	MissingSecret = "missing_secret"
	// Refused: its console asks a question lox live never answers.
	Refused = "refused"
	// Down: not started, stopped, unreachable, or not known yet.
	Down = "down"
)

// What the health's detail says: one fixed word, never a configuration
// line, a console's prompt or a command's error (those go to lox live's
// journal, which its operator reads; the status socket is read by another
// Unix user).
const (
	DetailServing     = "serving"
	DetailStarting    = "starting"
	DetailEnrolment   = "needs_enrolment"   // nothing started: not what was enrolled
	DetailStartFailed = "start_failed"      // the start failed (the engine?): tried again
	DetailStopped     = "stopped"           // lox live is stopping
	DetailHubDown     = "hub_unreachable"   // the hub does not answer
	DetailHubOld      = "hub_too_old"       // the hub's image predates lox live
	DetailLocks       = "locks_not_serving" // a lock is not serving: see locks
)

// Health is GET /v1/health of the status socket, and lox live status
// --json. Serving: the hub answers and every lock of the workspace
// serves. Detail is one of the Detail words.
type Health struct {
	Serving bool              `json:"serving"`
	Locks   map[string]string `json:"locks"`
	Pending int               `json:"pending"`
	Detail  string            `json:"detail"`
}

type lockState struct {
	state string
	fixed bool
}

// Tracker is lox live's health as it goes, safe for concurrent use.
type Tracker struct {
	mu    sync.Mutex
	locks map[string]*lockState
	// phase is why nothing serves yet ("" once started); hub is why the
	// hub does not serve lox live ("" when it does).
	phase, hub string
}

// NewTracker is a tracker of a lox live that has not started anything.
func NewTracker() *Tracker {
	return &Tracker{locks: map[string]*lockState{}, phase: DetailStarting, hub: DetailHubDown}
}

func (t *Tracker) reset(instances []string, state, phase string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locks = map[string]*lockState{}
	for _, n := range instances {
		t.locks[n] = &lockState{state: state}
	}
	t.phase, t.hub = phase, DetailHubDown
}

// NeedsEnrolment: nothing was started for want of an enrolment; every
// lock of instances waits for it.
func (t *Tracker) NeedsEnrolment(instances []string) {
	t.reset(instances, NeedsEnrolment, DetailEnrolment)
}

// Failed: the start failed for another reason: nothing serves.
func (t *Tracker) Failed(instances []string) { t.reset(instances, Down, DetailStartFailed) }

// Started: the stack was brought up for instances; nothing is known of
// the hub and the consoles yet.
func (t *Tracker) Started(instances []string) { t.reset(instances, Down, "") }

// Stopped: lox live serves no more.
func (t *Tracker) Stopped() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.locks {
		l.state, l.fixed = Down, false
	}
	t.phase, t.hub = DetailStopped, DetailHubDown
}

// Hub records whether the hub serves lox live: why not (DetailHubDown,
// DetailHubOld), "" when it does.
func (t *Tracker) Hub(why string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hub = why
}

// Fixed pins instance to state whatever its console says (a lock lox
// live knows it cannot serve: credentials a human types, a lock not
// started, rules it could not read).
func (t *Tracker) Fixed(instance, state string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locks[instance] = &lockState{state: state, fixed: true}
}

// Console records instance's console as the session saw it.
func (t *Tracker) Console(instance string, c loxrun.ConsoleStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.locks[instance]
	if !ok {
		l = &lockState{}
		t.locks[instance] = l
	}
	if l.fixed {
		return
	}
	switch {
	case c.State == loxrun.ConsoleServing:
		l.state = Serving
	case c.State == loxrun.ConsoleWaiting && c.Blocked == loxrun.BlockedSecret:
		l.state = MissingSecret
	case c.State == loxrun.ConsoleWaiting && c.Blocked == loxrun.BlockedEnrolment:
		l.state = NeedsEnrolment
	case c.State == loxrun.ConsoleWaiting && c.Blocked == loxrun.BlockedRefused:
		l.state = Refused
	default:
		l.state = Down
	}
}

// Health is the health now (Pending is the status socket's to fill).
func (t *Tracker) Health() Health {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := Health{Locks: map[string]string{}, Detail: DetailServing}
	all := true
	for n, l := range t.locks {
		h.Locks[n] = l.state
		all = all && l.state == Serving
	}
	switch {
	case t.phase != "":
		h.Detail = t.phase
	case t.hub != "":
		h.Detail = t.hub
	case !all:
		h.Detail = DetailLocks
	default:
		h.Serving = true
	}
	return h
}
