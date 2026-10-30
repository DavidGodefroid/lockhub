package state

import (
	"errors"
	"testing"
)

func TestNext(t *testing.T) {
	states := []State{Pending, Approved, Denied, Withdrawn, Expired, Consumed}
	events := []Event{Approve, Deny, Withdraw, Expire, Consume}
	allowed := map[[2]string]State{
		{"pending", "approve"}:  Approved,
		{"pending", "deny"}:     Denied,
		{"pending", "withdraw"}: Withdrawn,
		{"pending", "expire"}:   Expired,
		{"approved", "consume"}: Consumed,
	}
	for _, s := range states {
		for _, e := range events {
			to, err := Next(s, e)
			want, ok := allowed[[2]string{string(s), string(e)}]
			if ok != (err == nil) || (ok && to != want) {
				t.Errorf("Next(%s, %s) = %s, %v", s, e, to, err)
			}
			var te ErrTransition
			if !ok && !errors.As(err, &te) {
				t.Errorf("Next(%s, %s): error %v is not ErrTransition", s, e, err)
			}
		}
	}
}

func TestFinal(t *testing.T) {
	for s, want := range map[State]bool{Pending: false, Approved: false, Denied: true, Withdrawn: true, Expired: true, Consumed: true} {
		if Final(s) != want {
			t.Errorf("Final(%s) = %v", s, !want)
		}
		if !Valid(s) {
			t.Errorf("Valid(%s) = false", s)
		}
	}
	if Valid("bogus") {
		t.Error("Valid(bogus) = true")
	}
}

// Only a renewal ends an approval: the table's Expire (the sweeper's)
// never does.
func TestRenewed(t *testing.T) {
	if _, err := Next(Approved, Expire); err == nil {
		t.Error("Expire ends an approved ticket")
	}
	for s, want := range map[State]State{Pending: Expired, Approved: Expired, Denied: Denied, Consumed: Consumed, Withdrawn: Withdrawn, Expired: Expired} {
		got, ok := Renewed(s)
		if got != want || ok != (s == Pending || s == Approved) {
			t.Errorf("Renewed(%s) = %s, %v", s, got, ok)
		}
	}
}
