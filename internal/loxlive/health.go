package loxlive

import (
	"slices"
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

// Health is GET /v1/health of the status socket, and lox live status
// --json. Serving: the hub answers and every lock of the workspace
// serves.
type Health struct {
	Serving bool              `json:"serving"`
	Locks   map[string]string `json:"locks"`
	Pending int               `json:"pending"`
	Detail  string            `json:"detail"`
}

type lockState struct {
	state, detail string
	fixed         bool
}

// Tracker is lox live's health as it goes, safe for concurrent use.
type Tracker struct {
	mu    sync.Mutex
	locks map[string]*lockState
	// phase is why nothing serves yet ("" once started).
	phase  string
	hubOK  bool
	hubErr string
}

// NewTracker is a tracker of a lox live that has not started anything.
func NewTracker() *Tracker {
	return &Tracker{locks: map[string]*lockState{}, phase: "lox live is starting"}
}

func (t *Tracker) reset(instances []string, state, detail, phase string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locks = map[string]*lockState{}
	for _, n := range instances {
		t.locks[n] = &lockState{state: state, detail: detail}
	}
	t.phase, t.hubOK, t.hubErr = phase, false, ""
}

// NeedsEnrolment: nothing was started, why says what differs from the
// enrolment; every lock of instances waits for it.
func (t *Tracker) NeedsEnrolment(instances []string, why string) {
	t.reset(instances, NeedsEnrolment, why, "needs enrolment: "+why)
}

// Failed: the start failed for another reason (why): nothing serves.
func (t *Tracker) Failed(instances []string, why string) {
	t.reset(instances, Down, why, "not started: "+why)
}

// Started: the stack was brought up for instances; nothing is known of
// the hub and the consoles yet.
func (t *Tracker) Started(instances []string) {
	t.reset(instances, Down, "its console is not reached yet", "")
}

// Stopped: lox live serves no more (why).
func (t *Tracker) Stopped(why string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.locks {
		l.state, l.detail, l.fixed = Down, why, false
	}
	t.phase, t.hubOK = why, false
}

// Hub records whether the hub answers lox live (err: why not).
func (t *Tracker) Hub(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hubOK, t.hubErr = err == nil, ""
	if err != nil {
		t.hubErr = err.Error()
	}
}

// Fixed pins instance to state whatever its console says (a lock lox
// live knows it cannot serve: credentials a human types, a lock not
// started).
func (t *Tracker) Fixed(instance, state, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locks[instance] = &lockState{state: state, detail: detail, fixed: true}
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
	l.detail = c.Detail
	switch {
	case c.State == loxrun.ConsoleServing:
		l.state, l.detail = Serving, ""
	case c.State == loxrun.ConsoleWaiting && c.Blocked == loxrun.BlockedSecret:
		l.state = MissingSecret
	case c.State == loxrun.ConsoleWaiting && c.Blocked == loxrun.BlockedEnrolment:
		l.state = NeedsEnrolment
	case c.State == loxrun.ConsoleWaiting && c.Blocked == loxrun.BlockedRefused:
		l.state = Refused
	default:
		l.state = Down
		if l.detail == "" {
			l.detail = "its console is " + string(c.State)
		}
	}
}

// Health is the health now (Pending is the status socket's to fill).
func (t *Tracker) Health() Health {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := Health{Locks: map[string]string{}}
	names := make([]string, 0, len(t.locks))
	for n, l := range t.locks {
		h.Locks[n] = l.state
		names = append(names, n)
	}
	slices.Sort(names)
	switch {
	case t.phase != "":
		h.Detail = t.phase
	case !t.hubOK:
		h.Detail = "the hub does not answer"
		if t.hubErr != "" {
			h.Detail = "the hub does not answer lox live: " + t.hubErr
		}
	default:
		for _, n := range names {
			if l := t.locks[n]; l.state != Serving {
				h.Detail = "lock " + n + " " + l.state
				if l.detail != "" {
					h.Detail += ": " + l.detail
				}
				break
			}
		}
		if h.Detail == "" {
			h.Serving, h.Detail = true, "serving"
		}
	}
	if len(h.Detail) > 400 {
		h.Detail = h.Detail[:400]
	}
	return h
}
