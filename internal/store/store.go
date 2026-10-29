// Package store keeps the hub's tickets, decisions and request nonces in
// SQLite (pure Go, in the hub's volume).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/DavidGodefroid/lockhub/internal/state"
)

const schema = `
CREATE TABLE IF NOT EXISTS tickets (
	instance  TEXT NOT NULL,
	id        TEXT NOT NULL,
	risk      TEXT NOT NULL,
	plan_hash TEXT NOT NULL,
	state     TEXT NOT NULL,
	raw       BLOB NOT NULL,
	created   INTEGER NOT NULL,
	expires   INTEGER,          -- unix seconds, NULL: never
	updated   INTEGER NOT NULL,
	PRIMARY KEY (instance, id)
);
CREATE INDEX IF NOT EXISTS tickets_instance_state ON tickets(instance, state);
CREATE INDEX IF NOT EXISTS tickets_expires ON tickets(state, expires);
CREATE TABLE IF NOT EXISTS decisions (
	seq      INTEGER PRIMARY KEY AUTOINCREMENT,
	instance TEXT NOT NULL,
	ticket   TEXT NOT NULL,
	raw      BLOB NOT NULL,
	at       INTEGER NOT NULL,
	UNIQUE (instance, ticket),
	FOREIGN KEY (instance, ticket) REFERENCES tickets(instance, id)
);
CREATE INDEX IF NOT EXISTS decisions_instance_seq ON decisions(instance, seq);
CREATE TABLE IF NOT EXISTS nonces (
	instance TEXT NOT NULL,
	nonce    TEXT NOT NULL,
	at       INTEGER NOT NULL,
	PRIMARY KEY (instance, nonce)
);
`

var (
	// ErrNotFound is an unknown ticket.
	ErrNotFound = errors.New("no such ticket")
	// ErrConflict is a ticket id already stored with other content.
	ErrConflict = errors.New("ticket id already used by another ticket")
	// ErrReplay is a request nonce already seen.
	ErrReplay = errors.New("request nonce already used")
	// ErrStale is a state change on a ticket another change got to first.
	ErrStale = errors.New("ticket state changed meanwhile")
)

// Ref names a ticket: ids are unique per lock instance only.
type Ref struct{ Instance, ID string }

func (r Ref) String() string { return r.Instance + "/" + r.ID }

// Ticket is a stored ticket. Raw is the signed ticket as the lock sent it.
type Ticket struct {
	ID       string
	Instance string
	Risk     string
	PlanHash string
	State    state.State
	Raw      []byte
	Created  time.Time
	Expires  time.Time // zero: never
	Updated  time.Time
}

// Decision is a stored, signed decision. Seq orders an instance's
// decisions; locks poll from a Seq cursor.
type Decision struct {
	Seq      int64
	Ticket   string
	Instance string
	Raw      []byte
	At       time.Time
}

// Store is the database. Safe for concurrent use.
type Store struct{ db *sql.DB }

// Open opens or creates the database at path (0600).
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; SQLite serializes anyway
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Tx runs fn in a transaction; fn's error rolls it back.
func (s *Store) Tx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Tx{tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Tx is an open transaction.
type Tx struct{ tx *sql.Tx }

func unix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

// PutTicket stores a new pending ticket. The same ticket sent again
// (same raw bytes) is not an error: created is false.
func (t *Tx) PutTicket(tk Ticket) (created bool, err error) {
	var raw []byte
	err = t.tx.QueryRow(`SELECT raw FROM tickets WHERE instance = ? AND id = ?`, tk.Instance, tk.ID).Scan(&raw)
	switch {
	case err == nil:
		if string(raw) != string(tk.Raw) {
			return false, ErrConflict
		}
		return false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	_, err = t.tx.Exec(`INSERT INTO tickets(id, instance, risk, plan_hash, state, raw, created, expires, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tk.ID, tk.Instance, tk.Risk, tk.PlanHash, string(tk.State), tk.Raw, tk.Created.Unix(), unix(tk.Expires), tk.Updated.Unix())
	return err == nil, err
}

// Ticket reads one ticket.
func (t *Tx) Ticket(r Ref) (Ticket, error) {
	return scanTicket(t.tx.QueryRow(`SELECT id, instance, risk, plan_hash, state, raw, created, expires, updated FROM tickets WHERE instance = ? AND id = ?`, r.Instance, r.ID))
}

type row interface{ Scan(...any) error }

func scanTicket(r row) (Ticket, error) {
	var tk Ticket
	var st string
	var created, updated int64
	var expires sql.NullInt64
	err := r.Scan(&tk.ID, &tk.Instance, &tk.Risk, &tk.PlanHash, &st, &tk.Raw, &created, &expires, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, ErrNotFound
	}
	if err != nil {
		return Ticket{}, err
	}
	tk.State = state.State(st)
	tk.Created, tk.Updated = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	if expires.Valid {
		tk.Expires = time.Unix(expires.Int64, 0).UTC()
	}
	return tk, nil
}

// CountPending is the number of pending tickets of an instance.
func (t *Tx) CountPending(instance string) (int, error) {
	var n int
	err := t.tx.QueryRow(`SELECT count(*) FROM tickets WHERE instance = ? AND state = ?`, instance, string(state.Pending)).Scan(&n)
	return n, err
}

// SetState moves a ticket from one state to another, only if it is still
// in from.
func (t *Tx) SetState(r Ref, from, to state.State, now time.Time) error {
	res, err := t.tx.Exec(`UPDATE tickets SET state = ?, updated = ? WHERE instance = ? AND id = ? AND state = ?`, string(to), now.Unix(), r.Instance, r.ID, string(from))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrStale
	}
	return nil
}

// PutDecision stores the signed decision of a ticket and returns its seq.
func (t *Tx) PutDecision(d Decision) (int64, error) {
	res, err := t.tx.Exec(`INSERT INTO decisions(ticket, instance, raw, at) VALUES (?, ?, ?, ?)`, d.Ticket, d.Instance, d.Raw, d.At.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UseNonce records a request nonce; one already recorded is ErrReplay.
func (t *Tx) UseNonce(instance, nonce string, at time.Time) error {
	res, err := t.tx.Exec(`INSERT INTO nonces(instance, nonce, at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, instance, nonce, at.Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReplay
	}
	return nil
}

// Decisions lists an instance's decisions after seq since, oldest first.
func (s *Store) Decisions(ctx context.Context, instance string, since int64, limit int) ([]Decision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, ticket, instance, raw, at FROM decisions WHERE instance = ? AND seq > ? ORDER BY seq LIMIT ?`, instance, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var d Decision
		var at int64
		if err := rows.Scan(&d.Seq, &d.Ticket, &d.Instance, &d.Raw, &at); err != nil {
			return nil, err
		}
		d.At = time.Unix(at, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// AllDecisions lists every instance's decisions after seq since, oldest
// first (for read-only observers such as lea).
func (s *Store) AllDecisions(ctx context.Context, since int64, limit int) ([]Decision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, ticket, instance, raw, at FROM decisions WHERE seq > ? ORDER BY seq LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var d Decision
		var at int64
		if err := rows.Scan(&d.Seq, &d.Ticket, &d.Instance, &d.Raw, &at); err != nil {
			return nil, err
		}
		d.At = time.Unix(at, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// Tickets lists the tickets in a state, oldest first.
func (s *Store) Tickets(ctx context.Context, st state.State) ([]Ticket, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, instance, risk, plan_hash, state, raw, created, expires, updated FROM tickets WHERE state = ? ORDER BY created, id`, string(st))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ticket
	for rows.Next() {
		tk, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tk)
	}
	return out, rows.Err()
}

// DueForExpiry lists pending tickets whose expiry is at or before now.
func (s *Store) DueForExpiry(ctx context.Context, now time.Time) ([]Ref, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT instance, id FROM tickets WHERE state = ? AND expires IS NOT NULL AND expires <= ? ORDER BY expires`, string(state.Pending), now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []Ref
	for rows.Next() {
		var r Ref
		if err := rows.Scan(&r.Instance, &r.ID); err != nil {
			return nil, err
		}
		ids = append(ids, r)
	}
	return ids, rows.Err()
}

// PurgeNonces drops nonces recorded before t.
func (s *Store) PurgeNonces(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM nonces WHERE at < ?`, before.Unix())
	return err
}
