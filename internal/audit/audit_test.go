package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < n; i++ {
		if _, err := l.Append(Record{Event: "push", Ticket: "T", Instance: "i", State: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainAndResume(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tickets.jsonl")
	write(t, p, 3)
	write(t, p, 2) // reopen resumes the chain
	f, _ := os.Open(p)
	defer f.Close()
	n, err := Verify(f)
	if err != nil || n != 5 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
}

func TestTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tickets.jsonl")
	write(t, p, 3)
	orig, _ := os.ReadFile(p)
	lines := strings.SplitAfter(strings.TrimSuffix(string(orig), "\n"), "\n")
	cases := map[string]string{
		"edited":         strings.Replace(string(orig), `"state":"pending"`, `"state":"approved"`, 1),
		"removed":        lines[0] + lines[2] + "\n",
		"reordered":      lines[1] + lines[0] + lines[2] + "\n",
		"truncated head": lines[1] + lines[2] + "\n",
	}
	for name, content := range cases {
		_, err := Verify(bytes.NewReader([]byte(content)))
		if !errors.Is(err, ErrBroken) {
			t.Errorf("%s: Verify err = %v, want ErrBroken", name, err)
		}
		bad := filepath.Join(t.TempDir(), "bad.jsonl")
		os.WriteFile(bad, []byte(content), 0o600)
		if _, err := Open(bad); err == nil {
			t.Errorf("%s: Open accepted a broken log", name)
		}
	}
	// A truncated tail (last line dropped) still verifies: the chain
	// alone cannot see it; the store's sequence does (hub tests).
	if n, err := Verify(bytes.NewReader([]byte(lines[0] + lines[1]))); err != nil || n != 2 {
		t.Errorf("prefix: %d, %v", n, err)
	}
}

func TestSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "tickets.jsonl")
	l, _ := Open(p)
	l.SetKey(priv)
	for i := 0; i < 3; i++ {
		l.Append(Record{Event: "push", Ticket: "T", Instance: "i", State: "pending"})
	}
	l.Close()
	b, _ := os.ReadFile(p)
	if n, err := VerifySigned(bytes.NewReader(b), pub); err != nil || n != 3 {
		t.Fatalf("VerifySigned = %d, %v", n, err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifySigned(bytes.NewReader(b), other); !errors.Is(err, ErrBroken) {
		t.Errorf("other key: %v", err)
	}
	// A chain rebuilt without the hub key (consistent hashes, no valid
	// signature) is refused.
	p2 := filepath.Join(t.TempDir(), "rebuilt.jsonl")
	l2, _ := Open(p2)
	l2.Append(Record{Event: "push", Ticket: "T", Instance: "i", State: "pending"})
	l2.Close()
	b2, _ := os.ReadFile(p2)
	if _, err := VerifySigned(bytes.NewReader(b2), pub); !errors.Is(err, ErrBroken) {
		t.Errorf("unsigned rebuilt chain: %v", err)
	}
}

func TestOpenSignedRefusesForeignRecords(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "tickets.jsonl")
	write(t, p, 1) // unsigned record
	if _, err := OpenSigned(p, priv); !errors.Is(err, ErrBroken) {
		t.Errorf("unsigned history accepted: %v", err)
	}
	p2 := filepath.Join(t.TempDir(), "t2.jsonl")
	l, err := OpenSigned(p2, priv)
	if err != nil {
		t.Fatal(err)
	}
	l.Append(Record{Event: "push", Ticket: "T", Instance: "i", State: "pending"})
	l.Close()
	if l, err := OpenSigned(p2, priv); err != nil {
		t.Errorf("own signed history refused: %v", err)
	} else {
		l.Close()
	}
}
