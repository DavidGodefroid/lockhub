package verify

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
	"strings"

	lkaudit "github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/store"
)

// LockLog is one lock instance's audit log (lockkit's audit.log, or the
// directory holding it).
type LockLog struct{ Instance, Path string }

// LockReport is what Locks found in one lock's log.
type LockReport struct {
	Instance string
	// Records and Legacy are lockkit's Summary (Legacy: lines from before
	// the chain); HubDecisions the records of a hub decision, Unsigned
	// those of them without the hub's signature (locksql does not record
	// it yet: checked on ticket, outcome, approver and facade only);
	// Unrecorded the hub's decisions for the instance the log has no
	// record of (decided, not yet acted on, or cut from the log).
	Records, Legacy, HubDecisions, Unsigned, Unrecorded int
	// Anchored is whether the log was checked against a kept anchor;
	// Anchor is its anchor now (empty: no chained line yet).
	Anchored bool
	Anchor   lkaudit.Anchor
	Problems []string
}

// OK reports whether nothing is wrong.
func (r LockReport) OK() bool { return len(r.Problems) == 0 }

func (r *LockReport) bad(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// lockRecord is what Locks reads of a lockkit audit record.
type lockRecord struct {
	Event    string           `json:"event"`
	Decision string           `json:"decision"`
	Approval string           `json:"approval"`
	Ticket   string           `json:"ticket"`
	Approver *ticket.Approver `json:"approver"`
	Facade   string           `json:"facade"`
	HubSig   string           `json:"hub_sig"`
}

// hubFields are the fields that make a record about a hub decision.
var hubFields = []string{"approval", "ticket", "approver", "facade", "hub_sig"}

// Locks verifies lock-side audit logs: each one's chain (lockkit
// audit.Verify; VerifyAnchored when anchors holds the anchor kept for the
// instance, so that a cut tail or a stripped chain is seen too), and
// that every record naming a hub decision (hub_sig) matches a decision
// the hub's database holds and signed: same signature, approver and
// facade. dir is the hub's data directory.
func Locks(ctx context.Context, dir string, hubKey ed25519.PublicKey, logs []LockLog, anchors map[string]lkaudit.Anchor) ([]LockReport, error) {
	st, err := store.OpenReadOnly(filepath.Join(dir, "hub.db"))
	if err != nil {
		return nil, err
	}
	defer st.Close()
	type signed struct {
		sig, approver, facade, outcome string
	}
	byTicket := map[string]signed{} // instance/ticket → the hub's decision
	var since int64
	for {
		ds, err := st.AllDecisions(ctx, since, 500)
		if err != nil {
			return nil, err
		}
		if len(ds) == 0 {
			break
		}
		for _, d := range ds {
			since = d.Seq
			dec, err := ticket.VerifyDecision(hubKey, d.Raw)
			if err != nil {
				continue // Hub reports it
			}
			// Keyed on what the hub signed, not on the database's columns.
			byTicket[dec.Instance+"/"+dec.Ticket] = signed{dec.Sig, dec.Approver.ID, dec.Facade, string(dec.Decision)}
		}
	}
	var out []LockReport
	for _, l := range logs {
		r := LockReport{Instance: l.Instance}
		b, err := readLockLog(l.Path)
		if err != nil {
			return nil, fmt.Errorf("audit log of %s: %w", l.Instance, err)
		}
		var sum lkaudit.Summary
		if a, ok := anchors[l.Instance]; ok && a.Line > 0 {
			r.Anchored = true
			sum, err = lkaudit.VerifyAnchored(bytes.NewReader(b), a)
		} else {
			sum, err = lkaudit.Verify(bytes.NewReader(b))
		}
		r.Records, r.Legacy, r.Anchor = sum.Records, sum.Legacy, sum.Anchor()
		if err != nil {
			r.bad("audit chain: %v", err)
			out = append(out, r)
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		line := 0
		recorded := map[string]bool{}
		for sc.Scan() {
			line++
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
				r.bad("line %d: %v", line, err)
				continue
			}
			var rec lockRecord
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				for _, f := range hubFields {
					if _, ok := raw[f]; ok {
						r.bad("line %d: a hub field that does not read: %v", line, err)
						break
					}
				}
				continue
			}
			// A hub decision: what the consoles write when the hub decided
			// (approval "hub", approved or denied), or anything carrying
			// the hub's signature.
			isDecision := rec.Event == lkaudit.EventApproved || rec.Event == lkaudit.EventDenied
			if !(rec.HubSig != "" || rec.Approval == "hub" && isDecision) {
				continue
			}
			r.HubDecisions++
			key := l.Instance + "/" + rec.Ticket
			d, ok := byTicket[key]
			approver := ""
			if rec.Approver != nil {
				approver = rec.Approver.ID
			}
			want := lkaudit.EventDenied
			if d.outcome == string(ticket.Approved) {
				want = lkaudit.EventApproved
			}
			if rec.HubSig == "" {
				r.Unsigned++
			}
			switch {
			case !ok:
				r.bad("line %d (%s): a hub decision on %s the hub has not signed", line, rec.Event, key)
			case rec.HubSig != "" && d.sig != rec.HubSig:
				r.bad("line %d (%s): the hub signature differs from the hub's decision on %s", line, rec.Event, key)
			case isDecision && rec.Event != want, rec.Decision != "" && rec.Decision != d.outcome:
				r.bad("line %d (%s, decision %q): the hub's decision on %s is %s", line, rec.Event, rec.Decision, key, d.outcome)
			case d.approver != approver || d.facade != rec.Facade:
				r.bad("line %d (%s): approver %s on %s, the hub's decision on %s says %s on %s", line, rec.Event, approver, rec.Facade, key, d.approver, d.facade)
			}
			recorded[key] = true
		}
		for key := range byTicket {
			if strings.HasPrefix(key, l.Instance+"/") && !recorded[key] {
				r.Unrecorded++
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("audit log of %s: %w", l.Instance, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// readLockLog reads path, or path/audit.log when path is a directory.
func readLockLog(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		path = filepath.Join(path, "audit.log")
	}
	return os.ReadFile(path)
}

// anchor is an anchor in the anchors file.
type anchor struct {
	Line int    `json:"line"`
	Hash string `json:"hash"`
}

// LoadAnchors reads the anchors file (instance → the anchor of its log
// when last verified); missing: none.
func LoadAnchors(path string) (map[string]lkaudit.Anchor, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]lkaudit.Anchor{}, nil
	} else if err != nil {
		return nil, err
	}
	var f map[string]anchor
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	a := map[string]lkaudit.Anchor{}
	for k, v := range f {
		if v.Line < 1 || v.Hash == "" {
			return nil, fmt.Errorf("%s: empty anchor for %s", path, k)
		}
		a[k] = lkaudit.Anchor{Line: v.Line, Hash: v.Hash}
	}
	return a, nil
}

// SaveAnchors replaces the anchors file (0600).
func SaveAnchors(path string, a map[string]lkaudit.Anchor) error {
	f := map[string]anchor{}
	for k, v := range a {
		if v.Line > 0 {
			f[k] = anchor{v.Line, v.Hash}
		}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	t, err := os.CreateTemp(filepath.Dir(path), ".anchors-*")
	if err != nil {
		return err
	}
	tmp := t.Name()
	_, err = t.Write(append(b, '\n'))
	if cerr := t.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
