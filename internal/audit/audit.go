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
	"slices"
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
	// Device is the approval device of a mobile decision or of a device
	// event (pair, revoke), Fingerprint its record's fingerprint.
	Device      string `json:"device,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Outbox is the id of the outbox row the record came from (records
	// from before the outbox have none): ids only grow along the log, so
	// a row logged already, or replayed, is told apart exactly.
	Outbox int64 `json:"outbox,omitempty"`
	// NewKey is the public key (base64 std) a key_rotated record hands
	// the log over to; NewSig is that key's signature over Hash.
	NewKey string `json:"new_key,omitempty"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
	// Sig is the hub key's signature over Hash (SignContext).
	Sig    string `json:"sig,omitempty"`
	NewSig string `json:"new_sig,omitempty"`
}

// EventKeyRotated is the record of a hub key rotation: signed by the key
// it retires (Sig) and by the key that signs every later record (NewKey,
// NewSig), so that the log stays verifiable from its first record with
// every key it was signed with, and a log cut back to before the
// rotation no longer ends on the current key.
const EventKeyRotated = "key_rotated"

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

// hashOf hashes r without its Hash, Sig and NewSig fields. Field order is
// fixed by the struct, so the JSON is stable.
func hashOf(r Record) string {
	r.Hash, r.Sig, r.NewSig = "", "", ""
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
	// lastOut is the last record that came from the outbox.
	lastOut Record
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
// signed by priv's public half, and signs new records with priv. retired
// are the hub keys used before it, oldest first: a log whose key was
// rotated (key_rotated records) is signed by each in turn, and must end
// on priv's.
func OpenSigned(path string, priv ed25519.PrivateKey, retired ...ed25519.PublicKey) (*Log, error) {
	l, err := open(path, append(slices.Clip(retired), priv.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	l.key = priv
	return l, nil
}

func open(path string, keys []ed25519.PublicKey) (*Log, error) {
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
	c, err := verify(f, keys, nil)
	if err == nil && keys != nil && c.key != len(keys)-1 {
		err = fmt.Errorf("%w: the log is not handed over to the current hub key (a key_rotated record is missing)", ErrBroken)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit %s: %w", path, err)
	}
	last, n := c.last, c.n
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, err
	}
	l := &Log{f: f, size: size, seq: n, prev: Genesis, now: time.Now}
	if n > 0 {
		l.prev, l.last, l.lastOut = last.Hash, last, c.lastOut
	}
	return l, nil
}

// cutTornTail removes a last line without its newline that is no whole
// record: an append the process did not finish (power loss before its
// sync), which Append always ends with a newline in the same write. Its
// change is still in the hub's outbox (rows are dropped only after the
// sync), and is logged again from there.
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
	// A whole record without its newline is no torn append (the newline
	// goes in the same write): someone edited the log. Refuse.
	var rec Record
	if json.Unmarshal(buf[cut-(size-n):], &rec) == nil {
		return fmt.Errorf("%w: the last record lacks its newline", ErrBroken)
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
	if r.Event == EventKeyRotated || r.NewKey != "" || r.NewSig != "" {
		return Record{}, errors.New("audit: a key rotation is appended by Rotate")
	}
	return l.append(r, nil)
}

// Rotate appends the key_rotated record that hands the log over to next,
// signed by the current key and by next, and signs every later record
// with next. The log must be signed (OpenSigned).
func (l *Log) Rotate(next ed25519.PrivateKey) (Record, error) {
	if l.key == nil {
		return Record{}, errors.New("audit: rotating the key of an unsigned log")
	}
	r := Record{Event: EventKeyRotated, NewKey: base64.StdEncoding.EncodeToString(next.Public().(ed25519.PublicKey))}
	return l.append(r, next)
}

func (l *Log) append(r Record, next ed25519.PrivateKey) (Record, error) {
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
	if next != nil {
		r.NewSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(next, signedMsg(r.Hash)))
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
	if r.Outbox != 0 {
		l.lastOut = r
	}
	if next != nil {
		l.key = next
	}
	return r, nil
}

// IsLastOutbox reports whether the log's last record from the outbox has
// r's content: every field but Seq, Prev, Hash, Sig and Outbox.
func (l *Log) IsLastOutbox(r Record) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.lastOut
	a.Seq, a.Prev, a.Hash, a.Sig, a.Outbox = 0, "", "", "", 0
	r.Seq, r.Prev, r.Hash, r.Sig, r.Outbox = 0, "", "", "", 0
	return l.lastOut.Seq > 0 && a == r
}

// LastOutbox is the outbox id of the log's last record from the outbox
// (0: none). A key_rotated record comes from no outbox.
func (l *Log) LastOutbox() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastOut.Outbox
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }

// ErrBroken is a chain that does not verify.
var ErrBroken = errors.New("audit chain broken")

// Verify reads a whole log and checks every link. It returns the number
// of records.
func Verify(r io.Reader) (int64, error) {
	c, err := verify(r, nil, nil)
	return c.n, err
}

// VerifySigned is Verify that also requires every record to be signed by
// key.
func VerifySigned(r io.Reader, key ed25519.PublicKey) (int64, error) {
	n, _, err := VerifyKeys(r, []ed25519.PublicKey{key}, nil)
	return n, err
}

// VerifyKeys is VerifySigned for a log whose hub key may have been
// rotated: keys are the hub keys, oldest first. The records up to the
// first key_rotated record must be signed by keys[0], that record by
// keys[0] and keys[1] (its new_key), and so on. It returns the number of
// records and the index in keys of the key the log ends on: a log that
// is complete for keys ends on the last one, which the caller checks
// (lox audit verify refuses less; a rotation in progress expects one
// key more). each, when not nil, sees every record with that index.
func VerifyKeys(r io.Reader, keys []ed25519.PublicKey, each func(rec Record, key int)) (int64, int, error) {
	if len(keys) == 0 {
		return 0, 0, errors.New("audit: no hub key to verify with")
	}
	c, err := verify(r, keys, each)
	return c.n, c.key, err
}

// chain is what one pass over a log found.
type chain struct {
	last, lastOut Record
	n             int64
	key           int // the index in keys of the key signing the end
}

func sigOK(key ed25519.PublicKey, hash, sig string) bool {
	b, err := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && ed25519.Verify(key, signedMsg(hash), b)
}

func verify(r io.Reader, keys []ed25519.PublicKey, each func(Record, int)) (chain, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), MaxLine+1)
	prev := Genesis
	var c chain
	for sc.Scan() {
		n := c.n
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return c, fmt.Errorf("%w: empty line after record %d", ErrBroken, n)
		}
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return c, fmt.Errorf("%w: record %d: %v", ErrBroken, n+1, err)
		}
		switch {
		case rec.Seq != n+1:
			return c, fmt.Errorf("%w: record %d has seq %d", ErrBroken, n+1, rec.Seq)
		case rec.Prev != prev:
			return c, fmt.Errorf("%w: record %d does not follow record %d", ErrBroken, n+1, n)
		case rec.Hash != hashOf(rec):
			return c, fmt.Errorf("%w: record %d was modified", ErrBroken, n+1)
		case (rec.Event == EventKeyRotated) != (rec.NewKey != "") || (rec.NewSig != "" && rec.NewKey == ""):
			return c, fmt.Errorf("%w: record %d: a new key outside a key rotation, or a rotation without one", ErrBroken, n+1)
		}
		if keys != nil {
			if !sigOK(keys[c.key], rec.Hash, rec.Sig) {
				return c, fmt.Errorf("%w: record %d is not signed by the hub key", ErrBroken, n+1)
			}
			if rec.Event == EventKeyRotated {
				if c.key+1 >= len(keys) || rec.NewKey != base64.StdEncoding.EncodeToString(keys[c.key+1]) {
					return c, fmt.Errorf("%w: record %d hands the log over to a key not among the hub keys given (or not the next of them)", ErrBroken, n+1)
				}
				if !sigOK(keys[c.key+1], rec.Hash, rec.NewSig) {
					return c, fmt.Errorf("%w: record %d is not signed by the key it hands the log over to", ErrBroken, n+1)
				}
			}
		}
		if each != nil {
			each(rec, c.key)
		}
		if keys != nil && rec.Event == EventKeyRotated {
			c.key++
		}
		prev, c.last, c.n = rec.Hash, rec, n+1
		if rec.Outbox != 0 {
			c.lastOut = rec
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	return c, nil
}
