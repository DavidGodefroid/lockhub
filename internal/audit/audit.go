// Package audit is the hub's append-only, hash-chained audit log
// (tickets.jsonl): one JSON line per ticket event, each line carrying the
// hash of the previous one, so that a removed, reordered or edited line is
// detected by Verify. Each record's hash is also signed with the hub key,
// so that whoever can write the file cannot rebuild a consistent chain
// (VerifySigned).
package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	// Outbox is the id of the outbox row the record came from (records
	// from before the outbox have none): ids only grow along the log, so
	// a row logged already, or replayed, is told apart exactly.
	Outbox int64  `json:"outbox,omitempty"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
	// Sig is the hub key's signature over Hash (SignContext).
	Sig string `json:"sig,omitempty"`
}

// SignContext separates audit signatures from every other signature of
// the hub key.
const SignContext = "lockhub/audit/v1\x00"

func signedMsg(hash string) []byte { return []byte(SignContext + hash) }

// OutboxContext separates the hub key's signatures of outboxed records
// (records committed, not yet in the log) from its other signatures.
const OutboxContext = "lockhub/audit-outbox/v1\x00"

// SignOutbox signs an outboxed record (its JSON) with the hub key, so
// that whoever can write the database cannot have the hub chain and sign
// a record it never made.
// The signature covers the row's id, so a row cannot be moved to
// another id.
func SignOutbox(key ed25519.PrivateKey, id int64, record []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, outboxMsg(id, record)))
}

// VerifyOutbox checks SignOutbox's signature.
func VerifyOutbox(key ed25519.PublicKey, id int64, record []byte, sig string) bool {
	b, err := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && ed25519.Verify(key, outboxMsg(id, record), b)
}

func outboxMsg(id int64, record []byte) []byte {
	m := binary.BigEndian.AppendUint64([]byte(OutboxContext), uint64(id))
	return append(m, record...)
}

// hashOf hashes r without its Hash and Sig fields. Field order is fixed by the
// struct, so the JSON is stable.
func hashOf(r Record) string {
	r.Hash, r.Sig = "", ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Log appends to one file. Safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	f    file
	size int64 // bytes of whole records in f
	// broken is set when a failed append could not be undone: the file
	// may end with bytes the chain does not account for, so nothing more
	// is appended until the log is reopened (and verified).
	broken error
	seq    int64
	prev   string
	now    func() time.Time
	key    ed25519.PrivateKey
	last   Record
}

// file is what Log needs of its *os.File (a seam for tests).
type file interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Close() error
}

// SetKey makes Append sign every record with key (the hub key).
func (l *Log) SetKey(key ed25519.PrivateKey) { l.key = key }

// Open opens (or creates, 0600) the log at path, verifies it and resumes
// its chain. A broken chain refuses to open: the hub does not start on a
// log it cannot extend honestly.
func Open(path string) (*Log, error) { return open(path, nil) }

// OpenSigned is Open that also requires every existing record to be
// signed by key, and signs new records with priv (key's private half).
func OpenSigned(path string, priv ed25519.PrivateKey) (*Log, error) {
	l, err := open(path, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	l.key = priv
	return l, nil
}

func open(path string, key ed25519.PublicKey) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := cutTornTail(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit %s: %w", path, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	last, n, err := verify(f, key)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit %s: %w", path, err)
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, err
	}
	l := &Log{f: f, size: size, seq: n, prev: Genesis, now: time.Now}
	if n > 0 {
		l.prev, l.last = last.Hash, last
	}
	return l, nil
}

// cutTornTail removes a last line without its newline: an append the
// process did not finish (power loss before its sync), which Append
// always ends with a newline in the same write. Its change is still in
// the hub's outbox, and is logged again from there.
func cutTornTail(f *os.File) error {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil || size == 0 {
		return err
	}
	// Look back for the last newline, up to one record's length.
	n := min(size, MaxLine+1)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil {
		return err
	}
	if buf[n-1] == '\n' {
		return nil
	}
	cut := int64(0)
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		cut = size - n + int64(i) + 1
	} else if size > n {
		return fmt.Errorf("%w: last record over %d bytes", ErrBroken, MaxLine)
	}
	if err := f.Truncate(cut); err != nil {
		return err
	}
	return f.Sync()
}

// Append chains r (Seq, Prev and Hash are set here, and At unless r
// has one), writes it and syncs. An error means the record is not in the
// log.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Seq = l.seq + 1
	if r.At == "" {
		r.At = l.now().UTC().Format(time.RFC3339Nano)
	}
	r.Prev = l.prev
	r.Hash = hashOf(r)
	if l.key != nil {
		r.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(l.key, signedMsg(r.Hash)))
	}
	b, err := json.Marshal(r)
	if err != nil {
		return Record{}, err
	}
	if len(b) >= MaxLine {
		return Record{}, fmt.Errorf("audit record of %d bytes over the %d-byte limit", len(b), MaxLine)
	}
	if l.broken != nil {
		return Record{}, l.broken
	}
	line := append(b, '\n')
	_, err = l.f.Write(line)
	if err == nil {
		err = l.f.Sync()
	}
	if err != nil {
		// A torn line, or a whole one not known to be durable: cut the
		// file back to its last whole record, so that a retry appends
		// this record once, chained. If that fails too, refuse to go on.
		if terr := l.f.Truncate(l.size); terr != nil {
			l.broken = fmt.Errorf("audit log needs a restart: an append failed (%v) and could not be undone (%v)", err, terr)
		} else if serr := l.f.Sync(); serr != nil {
			l.broken = fmt.Errorf("audit log needs a restart: an append failed (%v) and its undo is not durable (%v)", err, serr)
		}
		return Record{}, err
	}
	l.size += int64(len(line))
	l.seq, l.prev, l.last = r.Seq, r.Hash, r
	return r, nil
}

// LastOutbox is the outbox id of the log's last record (0: none).
func (l *Log) LastOutbox() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last.Outbox
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }

// ErrBroken is a chain that does not verify.
var ErrBroken = errors.New("audit chain broken")

// Verify reads a whole log and checks every link. It returns the number
// of records.
func Verify(r io.Reader) (int64, error) {
	_, n, err := verify(r, nil)
	return n, err
}

// VerifySigned is Verify that also requires every record to be signed by
// key.
func VerifySigned(r io.Reader, key ed25519.PublicKey) (int64, error) {
	_, n, err := verify(r, key)
	return n, err
}

func verify(r io.Reader, key ed25519.PublicKey) (Record, int64, error) {
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
		if key != nil {
			sig, err := base64.RawURLEncoding.DecodeString(rec.Sig)
			if err != nil || !ed25519.Verify(key, signedMsg(rec.Hash), sig) {
				return last, n, fmt.Errorf("%w: record %d is not signed by the hub key", ErrBroken, n+1)
			}
		}
		prev, last, n = rec.Hash, rec, n+1
	}
	if err := sc.Err(); err != nil {
		return last, n, err
	}
	return last, n, nil
}
