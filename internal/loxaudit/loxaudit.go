// Package loxaudit is lox audit: it reads the hub's data directory (the
// tickets and signed decisions of hub.db, read only) and lox run's
// session journal, and makes of them the exchanges lox audit and lox
// run's audit view list: each ticket and its answer, as the hub keeps
// them. Tickets are masked by their locks before they reach the hub, so
// nothing here is ever a value in clear, a credential or a result row;
// the sealed parts of a ticket or a decision (a secret for the lock, a
// clear copy for a device) and the agent's free-text note are never
// read out.
package loxaudit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// RunsFile is lox run's session journal, in the workspace's state
// directory (next to hub-keys.pub): one RunEvent per line.
const RunsFile = "runs.jsonl"

// LogFile is the hub's signed audit log, in its data directory.
const LogFile = "tickets.jsonl"

// Source is where the audit is read from.
type Source struct {
	// Data is the hub's data directory (hub.db).
	Data string
	// HubKeys are the hub's pinned public keys, oldest first: a decision
	// is checked under each (nil: decisions are not checked).
	HubKeys []ed25519.PublicKey
	// LockKeys are the pinned lock keys, by instance: a ticket is checked
	// under its lock's (none: not checked).
	LockKeys map[string]ed25519.PublicKey
	// Runs is lox run's session journal ("" or missing: none).
	Runs string
	// Since keeps the tickets asked at or after it (zero: all); Limit the
	// newest Limit of them (0: all).
	Since time.Time
	Limit int
}

// Load reads the audit: the exchanges oldest first, and the lox run
// sessions since src.Since.
func Load(ctx context.Context, src Source) ([]loxrun.Exchange, []loxrun.RunEvent, error) {
	st, err := store.OpenReadOnly(filepath.Join(src.Data, "hub.db"))
	if err != nil {
		return nil, nil, fmt.Errorf("the hub's database: %w", err)
	}
	defer st.Close()
	// Created is kept in whole seconds: a ticket of the same second as
	// Since is read, then kept by its own time.
	since := src.Since
	if !since.IsZero() {
		since = since.Truncate(time.Second)
	}
	rows, err := st.History(ctx, since, src.Limit)
	if err != nil {
		return nil, nil, err
	}
	xs := make([]loxrun.Exchange, 0, len(rows))
	for _, r := range rows {
		x := Exchange(r, src.HubKeys, src.LockKeys)
		if !src.Since.IsZero() && x.At.Before(src.Since) {
			continue
		}
		xs = append(xs, x)
	}
	why := asked(filepath.Join(src.Data, LogFile), src.HubKeys, xs)
	for i := range xs {
		if xs[i].ByHuman() {
			xs[i].Asked = why[xs[i].Instance+"/"+xs[i].ID]
		}
	}
	var runs []loxrun.RunEvent
	if src.Runs != "" {
		if runs, err = ReadRuns(src.Runs, src.Since); err != nil {
			return nil, nil, err
		}
	}
	return xs, runs, nil
}

// Exchange is one stored ticket and its decision as an exchange.
func Exchange(r store.Exchange, hubKeys []ed25519.PublicKey, lockKeys map[string]ed25519.PublicKey) loxrun.Exchange {
	var notes []string
	checked, bad := 0, false
	var tk *ticket.Ticket
	if k, ok := lockKeys[r.Ticket.Instance]; ok {
		t, err := ticket.VerifyTicket(k, r.Ticket.Raw)
		switch {
		case err != nil:
			bad = true
			notes = append(notes, "the ticket does not verify under its lock's pinned key")
		case t.Source.Instance != r.Ticket.Instance || t.ID != r.Ticket.ID:
			bad = true
			notes = append(notes, "the hub keeps the ticket under another instance or id")
		default:
			tk = t
			checked++
			notes = append(notes, "ticket signed by its lock's pinned key")
		}
	} else {
		notes = append(notes, "ticket not checked (no pinned key for "+r.Ticket.Instance+")")
	}
	if tk == nil {
		var t ticket.Ticket
		if err := json.Unmarshal(r.Ticket.Raw, &t); err != nil {
			t = ticket.Ticket{ID: r.Ticket.ID, Source: ticket.Source{Instance: r.Ticket.Instance}, Risk: ticket.Risk(r.Ticket.Risk),
				Screen: ticket.Screen{Header: "unreadable ticket"}, Created: r.Ticket.Created}
		}
		tk = &t
	}
	x := loxrun.ExchangeOf(tk)
	// The hub's own record of where it stands.
	x.ID, x.Instance = clean(r.Ticket.ID), clean(r.Ticket.Instance)
	if x.At.IsZero() {
		x.At = r.Ticket.Created
	}
	x.State = string(r.Ticket.State)
	switch r.Ticket.State {
	case state.Consumed:
		x.Result = loxrun.ResRan
	case state.Expired:
		x.Result = loxrun.ResExpired
	case state.Withdrawn:
		x.Result = loxrun.ResWithdrawn
	case state.LockRemoved:
		x.Result = loxrun.ResRemoved
	}
	if r.Ticket.State != state.Pending && r.Ticket.State != state.Approved {
		x.Ended = r.Ticket.Updated
	}
	x.Status = loxrun.Waiting
	if r.Ticket.State != state.Pending && r.Decision.Raw == nil {
		x.Status = loxrun.Undecided
	}
	if r.Decision.Raw != nil {
		var d *ticket.Decision
		if len(hubKeys) > 0 {
			for i := len(hubKeys) - 1; i >= 0 && d == nil; i-- {
				d, _ = ticket.VerifyDecision(hubKeys[i], r.Decision.Raw)
			}
			if d == nil {
				bad = true
				notes = append(notes, "the decision does not verify under the hub's pinned keys")
			} else {
				checked++
				notes = append(notes, "decision signed by the hub key")
			}
		} else {
			notes = append(notes, "decision not checked (no pinned hub key)")
		}
		if d == nil {
			d = &ticket.Decision{}
			if err := json.Unmarshal(r.Decision.Raw, d); err != nil {
				d = &ticket.Decision{Decision: ticket.Denied, At: r.Decision.At}
			}
		}
		x.Reason = clean(d.Reason)
		x.Decided = d.At
		if x.Decided.IsZero() {
			x.Decided = r.Decision.At
		}
		if d.Auto() {
			x.Rule = clean(d.Rule.ID)
		} else {
			x.Facade, x.Approver = clean(d.Facade), clean(d.Approver.Display)
			if x.Approver == "" {
				x.Approver = clean(d.Approver.ID)
			}
		}
		if d.Decision == ticket.Approved {
			x.Status = loxrun.Approved
			if d.Auto() {
				x.Status = loxrun.AutoApproved
			} else {
				x.By = "human"
			}
		} else {
			x.Status = loxrun.Denied
		}
	}
	switch {
	case bad:
		x.Sig = loxrun.SigBad
	case checked > 0:
		x.Sig = loxrun.SigOK
	}
	x.SigNote = strings.Join(notes, "; ")
	return x
}

func clean(s string) string {
	// The hub's own fields (ids, instance names) are checked by the hub;
	// strip anything a terminal would act on all the same.
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// Filter keeps the exchanges lox audit's flags ask for.
type Filter struct {
	// Agent, Lock (an instance or a lock product: locksql…) and Profile
	// match exactly.
	Agent, Lock, Profile string
	// Since keeps the exchanges asked at or after it.
	Since time.Time
	// Decision is denied, human, auto, pending, or "" (any).
	Decision string
	// Writes keeps writes and DDL only.
	Writes bool
}

// Decisions lists the values of Filter.Decision.
var Decisions = []string{"denied", "human", "auto", "pending"}

// Match reports whether f keeps x.
func (f Filter) Match(x loxrun.Exchange) bool {
	switch {
	case f.Agent != "" && x.Agent != f.Agent,
		f.Lock != "" && x.Instance != f.Lock && x.Lock != f.Lock,
		f.Profile != "" && x.Profile != f.Profile,
		!f.Since.IsZero() && x.At.Before(f.Since),
		f.Writes && !x.Write():
		return false
	}
	switch f.Decision {
	case "denied":
		return x.Status == loxrun.Denied
	case "human":
		return x.ByHuman()
	case "auto":
		return x.Rule != ""
	case "pending":
		return x.Decision() == "pending"
	}
	return true
}

// Apply is xs that f keeps.
func (f Filter) Apply(xs []loxrun.Exchange) []loxrun.Exchange {
	var out []loxrun.Exchange
	for _, x := range xs {
		if f.Match(x) {
			out = append(out, x)
		}
	}
	return out
}

// ParseSince reads --since: a duration back from now (90s, 30m, 2h,
// 7d), a date (2006-01-02, local time) or a time (RFC 3339).
func ParseSince(s string, now time.Time, loc *time.Location) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		if d, err := strconv.Atoi(n); err == nil && d >= 0 {
			return now.AddDate(0, 0, -d), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, loc); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("--since: want a duration (30m, 2h, 7d), a date (2006-01-02) or a time (RFC 3339)")
}

// Find is the exchange named ref (INSTANCE/ID, or an ID or a unique
// prefix of one) among xs.
func Find(xs []loxrun.Exchange, ref string) (loxrun.Exchange, error) {
	inst, id, ok := strings.Cut(ref, "/")
	if !ok {
		inst, id = "", ref
	}
	var found []loxrun.Exchange
	for _, x := range xs {
		if (inst == "" || x.Instance == inst) && x.ID == id {
			return x, nil
		}
		if (inst == "" || x.Instance == inst) && id != "" && strings.HasPrefix(x.ID, id) {
			found = append(found, x)
		}
	}
	switch len(found) {
	case 0:
		return loxrun.Exchange{}, fmt.Errorf("no exchange %s in the hub's audit", ref)
	case 1:
		return found[0], nil
	}
	return loxrun.Exchange{}, fmt.Errorf("%s names %d exchanges: give more of the id, or INSTANCE/ID", ref, len(found))
}

// Changes is the exchanges of xs that are new since seen, or whose
// decision or state changed: what lox audit --follow prints. seen is
// updated.
func Changes(seen map[string]string, xs []loxrun.Exchange) []loxrun.Exchange {
	var out []loxrun.Exchange
	for _, x := range xs {
		k := x.Instance + "/" + x.ID
		v := fmt.Sprint(x.Status, x.Result, x.State)
		if seen[k] != v {
			seen[k] = v
			out = append(out, x)
		}
	}
	return out
}

// AppendRun appends e to the journal at path (created 0600).
func AppendRun(path string, e loxrun.RunEvent) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = e.At.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadRuns reads the journal at path, the events at or after since. A
// missing journal is none; a line that does not read is skipped (the
// journal is lox run's, unsigned: it only places the sessions).
func ReadRuns(path string, since time.Time) ([]loxrun.RunEvent, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []loxrun.RunEvent
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var e loxrun.RunEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.At.IsZero() {
			continue
		}
		switch e.Event {
		case loxrun.RunStart, loxrun.RunMode, loxrun.RunStop:
			e.Instance, e.Vault = "", ""
		case loxrun.RunVaultToken:
			if e.Vault != loxrun.VaultFromCLI && e.Vault != loxrun.VaultTyped {
				continue
			}
		default:
			continue
		}
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		e.User, e.Mode, e.Workspace, e.Instance = clean(e.User), clean(e.Mode), clean(e.Workspace), clean(e.Instance)
		out = append(out, e)
	}
	return out, nil
}

// asked is why the human was asked each exchange of xs a human decided
// (instance/id: reason), from the decision records of the hub's audit
// log at path: with hubKeys, only the records that verify under them
// (up to a break in the chain, which lox audit verify reports). A log
// missing or unreadable gives none: the listing does not depend on it.
func asked(path string, hubKeys []ed25519.PublicKey, xs []loxrun.Exchange) map[string]string {
	want := map[string]bool{}
	for _, x := range xs {
		if x.ByHuman() {
			want[x.Instance+"/"+x.ID] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]string{}
	keep := func(r audit.Record, _ int) {
		if k := r.Instance + "/" + r.Ticket; r.Asked != "" && r.Rule == "" && want[k] {
			out[k] = clean(r.Asked)
		}
	}
	if len(hubKeys) > 0 {
		_, _, _ = audit.VerifyKeys(f, hubKeys, keep)
		return out
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), audit.MaxLine+1)
	for sc.Scan() {
		var r audit.Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			keep(r, 0)
		}
	}
	return out
}
