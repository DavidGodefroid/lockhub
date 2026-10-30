// Package verify is `lock audit verify`: it checks the hub's audit chain,
// every decision's signature, and that the database and the audit log
// tell the same story (so that a cut tail of the log is seen too).
package verify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Report is what Hub found. Problems is empty when everything holds.
type Report struct {
	Records   int64
	Decisions int
	// Outboxed counts audit records of committed changes not yet in the
	// log: the hub appends them at its next change or start.
	Outboxed int
	Problems []string
}

// OK reports whether nothing is wrong.
func (r Report) OK() bool { return len(r.Problems) == 0 }

func (r *Report) bad(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// Hub verifies the hub data directory dir against the hub's public key.
// It may run against a running hub: the database is read as of one
// instant first, then the log, which by then holds every record
// committed before that instant (or the outbox does).
func Hub(ctx context.Context, dir string, hubKey ed25519.PublicKey) (Report, error) {
	var r Report
	st, err := store.OpenReadOnly(filepath.Join(dir, "hub.db"))
	if err != nil {
		return r, err
	}
	defer st.Close()
	outbox, decisions, err := st.AuditSnapshot(ctx)
	if err != nil {
		return r, err
	}
	// Read the log once: what is verified is what is then compared.
	logBytes, err := os.ReadFile(filepath.Join(dir, "tickets.jsonl"))
	if err != nil {
		return r, err
	}
	// A last line without its newline is an append in progress (the hub
	// writes a record and its newline at once): not read yet.
	if i := bytes.LastIndexByte(logBytes, '\n'); i < len(logBytes)-1 {
		logBytes = logBytes[:i+1]
	}
	n, err := audit.VerifySigned(bytes.NewReader(logBytes), hubKey)
	r.Records = n
	if err != nil {
		r.bad("audit chain: %v", err)
		return r, nil
	}
	// Decisions the audit log vouches for.
	inLog := map[string]audit.Record{} // instance/ticket → its decision record
	var lastOutbox int64               // outbox ids only grow along the log
	logged := map[int64]audit.Record{} // outbox id → its logged record
	sc := bufio.NewScanner(bytes.NewReader(logBytes))
	sc.Buffer(make([]byte, 64<<10), audit.MaxLine+1)
	for sc.Scan() {
		var rec audit.Record
		json.Unmarshal(sc.Bytes(), &rec)
		if rec.Decision != "" {
			inLog[rec.Instance+"/"+rec.Ticket] = rec
		}
		if rec.Outbox != 0 {
			if rec.Outbox <= lastOutbox {
				r.bad("audit record %d: outbox record %d logged after outbox record %d (replayed)", rec.Seq, rec.Outbox, lastOutbox)
			}
			lastOutbox = rec.Outbox
			logged[rec.Outbox] = rec
		}
	}
	// Committed changes whose records are still in the outbox (the hub
	// stopped between its commit and the log, or the log is down): signed
	// by the hub key for their row, they vouch for their decisions too,
	// and are reported, not refused.
	for _, o := range outbox {
		var rec audit.Record
		if !audit.VerifyOutbox(hubKey, o.ID, o.Record, o.Sig) {
			r.bad("audit outbox record %d: not signed by the hub key", o.ID)
			continue
		}
		if err := json.Unmarshal(o.Record, &rec); err != nil {
			r.bad("audit outbox record %d: %v", o.ID, err)
			continue
		}
		if o.ID <= lastOutbox {
			// Logged since the snapshot, or before a crash that left the
			// row: the hub drops it at its next flush. A row the log does
			// not have under its id is a replay.
			rec.Outbox = o.ID
			if l, ok := logged[o.ID]; !ok || content(rec) != content(l) {
				r.bad("audit outbox record %d: not the record logged for it (replayed; the log is at outbox record %d)", o.ID, lastOutbox)
			}
			continue
		}
		r.Outboxed++
		if rec.Decision != "" {
			inLog[rec.Instance+"/"+rec.Ticket] = rec
		}
	}
	for _, d := range decisions {
		r.check(hubKey, d, inLog)
	}
	// What the log records beyond the snapshot was committed after it.
	if len(inLog) > 0 {
		var since int64
		if len(decisions) > 0 {
			since = decisions[len(decisions)-1].Seq
		}
		for {
			ds, err := st.AllDecisions(ctx, since, 500)
			if err != nil {
				return r, err
			}
			if len(ds) == 0 {
				break
			}
			for _, d := range ds {
				since = d.Seq
				if _, ok := inLog[d.Instance+"/"+d.Ticket]; ok {
					r.check(hubKey, d, inLog)
				}
			}
		}
	}
	for key := range inLog {
		r.bad("audit log records a decision on %s that the database does not have", key)
	}
	return r, nil
}

// content is a record without its place in the chain.
func content(r audit.Record) audit.Record {
	r.Seq, r.Prev, r.Hash, r.Sig = 0, "", "", ""
	return r
}

// check verifies one stored decision against the record vouching for it,
// which it takes out of inLog.
func (r *Report) check(hubKey ed25519.PublicKey, d store.Decision, inLog map[string]audit.Record) {
	r.Decisions++
	key := d.Instance + "/" + d.Ticket
	dec, err := ticket.VerifyDecision(hubKey, d.Raw)
	switch {
	case err != nil:
		r.bad("decision %s: signature: %v", key, err)
		return
	case dec.Ticket != d.Ticket || dec.Instance != d.Instance:
		r.bad("decision %s: names %s/%s", key, dec.Instance, dec.Ticket)
	}
	sum := sha256.Sum256(d.Raw)
	h := "sha256:" + hex.EncodeToString(sum[:])
	want := "denied"
	if dec.Decision == ticket.Approved {
		want = "approved"
	}
	switch rec, ok := inLog[key]; {
	case !ok:
		r.bad("decision %s: not in the audit log (log cut or edited)", key)
	case rec.Decision != h:
		r.bad("decision %s: differs from the one the audit log recorded", key)
	case rec.State != want || rec.Approver != dec.Approver.ID || rec.Facade != dec.Facade:
		r.bad("decision %s: the audit record (%s by %s on %s) does not match the signed decision", key, rec.State, rec.Approver, rec.Facade)
	}
	delete(inLog, key)
}
