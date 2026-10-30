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
func Hub(ctx context.Context, dir string, hubKey ed25519.PublicKey) (Report, error) {
	var r Report
	// Read the log once: what is verified is what is then compared.
	logBytes, err := os.ReadFile(filepath.Join(dir, "tickets.jsonl"))
	if err != nil {
		return r, err
	}
	n, err := audit.VerifySigned(bytes.NewReader(logBytes), hubKey)
	r.Records = n
	if err != nil {
		r.bad("audit chain: %v", err)
		return r, nil
	}
	// Decisions the audit log vouches for.
	inLog := map[string]audit.Record{} // instance/ticket → its decision record
	sc := bufio.NewScanner(bytes.NewReader(logBytes))
	sc.Buffer(make([]byte, 64<<10), audit.MaxLine+1)
	for sc.Scan() {
		var rec audit.Record
		json.Unmarshal(sc.Bytes(), &rec)
		if rec.Decision != "" {
			inLog[rec.Instance+"/"+rec.Ticket] = rec
		}
	}
	st, err := store.OpenReadOnly(filepath.Join(dir, "hub.db"))
	if err != nil {
		return r, err
	}
	defer st.Close()
	// Committed changes whose records are still in the outbox (the hub
	// stopped between its commit and the log): they vouch for their
	// decisions too, and are reported, not refused.
	out, err := st.AuditOutbox(ctx)
	if err != nil {
		return r, err
	}
	for _, o := range out {
		var rec audit.Record
		if err := json.Unmarshal(o.Record, &rec); err != nil {
			r.bad("audit outbox record %d: %v", o.ID, err)
			continue
		}
		r.Outboxed++
		if rec.Decision != "" {
			inLog[rec.Instance+"/"+rec.Ticket] = rec
		}
	}
	var since int64
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
			r.Decisions++
			key := d.Instance + "/" + d.Ticket
			dec, err := ticket.VerifyDecision(hubKey, d.Raw)
			switch {
			case err != nil:
				r.bad("decision %s: signature: %v", key, err)
				continue
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
	}
	for key := range inLog {
		r.bad("audit log records a decision on %s that the database does not have", key)
	}
	return r, nil
}
