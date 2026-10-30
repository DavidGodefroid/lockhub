package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// flaky is a file whose next Write writes half and fails, or whose next
// Sync fails after a whole write, or whose Truncate fails.
type flaky struct {
	*os.File
	halfWrite, failSync, failTruncate bool
}

func (f *flaky) Write(b []byte) (int, error) {
	if f.halfWrite {
		f.halfWrite = false
		n, _ := f.File.Write(b[:len(b)/2])
		return n, errors.New("no space left")
	}
	return f.File.Write(b)
}

func (f *flaky) Sync() error {
	if f.failSync {
		f.failSync = false
		return errors.New("sync failed")
	}
	return f.File.Sync()
}

func (f *flaky) Truncate(n int64) error {
	if f.failTruncate {
		return errors.New("truncate failed")
	}
	return f.File.Truncate(n)
}

// A failed append leaves no bytes behind: retrying it chains it once.
func TestFailedAppendUndone(t *testing.T) {
	for name, fl := range map[string]flaky{"torn write": {halfWrite: true}, "sync": {failSync: true}} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "tickets.jsonl")
			write(t, p, 2)
			l, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			fl.File = l.f.(*os.File)
			l.f = &fl
			r := Record{Event: "approve", Ticket: "T", Instance: "i", State: "approved"}
			if _, err := l.Append(r); err == nil {
				t.Fatal("append succeeded")
			}
			if _, err := l.Append(r); err != nil {
				t.Fatalf("retry: %v", err)
			}
			l.Close()
			f, _ := os.Open(p)
			defer f.Close()
			if n, err := Verify(f); err != nil || n != 3 {
				t.Fatalf("%d records, %v", n, err)
			}
		})
	}
}

// An append that cannot be undone stops the log until it is reopened.
func TestUndoFailureStopsLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tickets.jsonl")
	write(t, p, 1)
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.f = &flaky{File: l.f.(*os.File), halfWrite: true, failTruncate: true}
	r := Record{Event: "approve", Ticket: "T", Instance: "i", State: "approved"}
	if _, err := l.Append(r); err == nil {
		t.Fatal("append succeeded")
	}
	if _, err := l.Append(r); err == nil {
		t.Fatal("appended after a torn line it could not cut")
	}
}
