// Package state is the life cycle of a ticket in the hub.
//
//	pending ──approve──► approved ──consume──► consumed
//	   ├────deny─────► denied     └──expire──► expired
//	   ├────withdraw─► withdrawn
//	   └────expire───► expired
//
// Every state but pending and approved is final. A ticket gets at most one
// decision. An approved ticket expires when the lock asks again for it
// (its approval aged past its risk class's TTL before the run, decision
// H1, and the lock pushed a renewal); an expired ticket is asked again by
// a new ticket, never reopened.
package state

import "fmt"

// State is a ticket's state.
type State string

const (
	Pending   State = "pending"
	Approved  State = "approved"
	Denied    State = "denied"
	Withdrawn State = "withdrawn"
	Expired   State = "expired"
	Consumed  State = "consumed"
)

// Event moves a ticket from one state to another.
type Event string

const (
	Approve  Event = "approve"
	Deny     Event = "deny"
	Withdraw Event = "withdraw"
	Expire   Event = "expire"
	Consume  Event = "consume"
)

var next = map[State]map[Event]State{
	Pending:  {Approve: Approved, Deny: Denied, Withdraw: Withdrawn, Expire: Expired},
	Approved: {Consume: Consumed, Expire: Expired},
}

// ErrTransition is a transition the life cycle does not allow.
type ErrTransition struct {
	From  State
	Event Event
}

func (e ErrTransition) Error() string {
	return fmt.Sprintf("ticket is %s: cannot %s", e.From, e.Event)
}

// Next is the state after ev, or ErrTransition.
func Next(from State, ev Event) (State, error) {
	if to, ok := next[from][ev]; ok {
		return to, nil
	}
	return from, ErrTransition{from, ev}
}

// Final reports whether no event can leave s.
func Final(s State) bool { return len(next[s]) == 0 }

// Valid reports whether s is a known state.
func Valid(s State) bool {
	switch s {
	case Pending, Approved, Denied, Withdrawn, Expired, Consumed:
		return true
	}
	return false
}
