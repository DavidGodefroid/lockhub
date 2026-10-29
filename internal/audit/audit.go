// Package audit is the hub's append-only, hash-chained audit log
// (tickets.jsonl): one JSON line per ticket event, each line carrying the
// hash of the previous one, so that a removed, reordered or edited line is
// detected by Verify.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// MaxLine bounds one record, so that Verify can always read back what
// Append wrote.
const MaxLine = 64 << 10

// Genesis is the prev of the first record.
const Genesis = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Record is one line. Hash covers every other field.
type Record struct {
	Seq      int64  `json:"seq"`
	At       string `json:"at"`
	Event    string `json:"event"`
	Ticket   string `json:"ticket"`
	Instance string `json:"instance"`
	Risk     string `json:"risk,omitempty"`
	State    string `json:"state"`
	Approver string `json:"approver,omitempty"`
	Facade   string `json:"facade,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Decision is the hash of the signed decision, when there is one.
	Decision string `json:"decision,omitempty"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash"`
}

// hashOf hashes r without its Hash field. Field order is fixed by the
// struct, so the JSON is stable.
func hashOf(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Log appends to one file. Safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  int64
	prev string
	now  func() time.Time
}

// Open opens (or creates, 0600) the log at path, verifies it and resumes
// its chain. A broken chain refuses to open: the hub does not start on a
// log it cannot extend honestly.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	last, n, err := verify(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit %s: %w", path, err)
	}
	l := &Log{f: f, seq: n, prev: Genesis, now: time.Now}
	if n > 0 {
		l.prev = last.Hash
	}
	return l, nil
}

// Append chains r (Seq, At, Prev and Hash are set here), writes it and
// syncs. An error means the event is not recorded: callers refuse the
// event.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Seq = l.seq + 1
	r.At = l.now().UTC().Format(time.RFC3339Nano)
	r.Prev = l.prev
	r.Hash = hashOf(r)
	b, err := json.Marshal(r)
	if err != nil {
		return Record{}, err
	}
	if len(b) >= MaxLine {
		return Record{}, fmt.Errorf("audit record of %d bytes over the %d-byte limit", len(b), MaxLine)
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return Record{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Record{}, err
	}
	l.seq, l.prev = r.Seq, r.Hash
	return r, nil
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }

// ErrBroken is a chain that does not verify.
var ErrBroken = errors.New("audit chain broken")

// Verify reads a whole log and checks every link. It returns the number
// of records.
func Verify(r io.Reader) (int64, error) {
	_, n, err := verify(r)
	return n, err
}

func verify(r io.Reader) (Record, int64, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), MaxLine+1)
	prev, n := Genesis, int64(0)
	var last Record
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return last, n, fmt.Errorf("%w: empty line after record %d", ErrBroken, n)
		}
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return last, n, fmt.Errorf("%w: record %d: %v", ErrBroken, n+1, err)
		}
		switch {
		case rec.Seq != n+1:
			return last, n, fmt.Errorf("%w: record %d has seq %d", ErrBroken, n+1, rec.Seq)
		case rec.Prev != prev:
			return last, n, fmt.Errorf("%w: record %d does not follow record %d", ErrBroken, n+1, n)
		case rec.Hash != hashOf(rec):
			return last, n, fmt.Errorf("%w: record %d was modified", ErrBroken, n+1)
		}
		prev, last, n = rec.Hash, rec, n+1
	}
	if err := sc.Err(); err != nil {
		return last, n, err
	}
	return last, n, nil
}
