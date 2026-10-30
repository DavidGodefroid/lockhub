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
	// the chain); HubDecisions the records that name a hub decision.
	Records, Legacy, HubDecisions int
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
	Ticket   string           `json:"ticket"`
	Approver *ticket.Approver `json:"approver"`
	Facade   string           `json:"facade"`
	HubSig   string           `json:"hub_sig"`
}

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
		sig, approver, facade string
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
			byTicket[d.Instance+"/"+d.Ticket] = signed{dec.Sig, dec.Approver.ID, dec.Facade}
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
		for sc.Scan() {
			line++
			var rec lockRecord
			if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.HubSig == "" {
				continue
			}
			r.HubDecisions++
			key := l.Instance + "/" + rec.Ticket
			d, ok := byTicket[key]
			approver := ""
			if rec.Approver != nil {
				approver = rec.Approver.ID
			}
			switch {
			case !ok:
				r.bad("line %d (%s): a hub decision on %s the hub has not signed", line, rec.Event, key)
			case d.sig != rec.HubSig:
				r.bad("line %d (%s): the hub signature differs from the hub's decision on %s", line, rec.Event, key)
			case d.approver != approver || d.facade != rec.Facade:
				r.bad("line %d (%s): approver %s on %s, the hub's decision on %s says %s on %s", line, rec.Event, approver, rec.Facade, key, d.approver, d.facade)
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
