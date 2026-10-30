package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func TestRotate(t *testing.T) {
	pub0, k0, _ := ed25519.GenerateKey(rand.Reader)
	pub1, k1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, k2, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "tickets.jsonl")
	l, _ := OpenSigned(p, k0)
	l.Append(Record{Event: "push", Ticket: "T", Instance: "i", State: "pending", Outbox: 7})
	if _, err := l.Append(Record{Event: EventKeyRotated, NewKey: "x"}); err == nil {
		t.Error("rotation through Append")
	}
	if _, err := l.Rotate(k1); err != nil {
		t.Fatal(err)
	}
	if l.LastOutbox() != 7 {
		t.Errorf("LastOutbox after a rotation = %d", l.LastOutbox())
	}
	l.Append(Record{Event: "push", Ticket: "U", Instance: "i", State: "pending", Outbox: 8})
	l.Close()
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(b), "\n")
	keyOf := map[string]int{}
	n, end, err := VerifyKeys(bytes.NewReader(b), []ed25519.PublicKey{pub0, pub1}, func(r Record, k int) { keyOf[r.Ticket+r.Event] = k })
	if err != nil || n != 3 || end != 1 || keyOf["Tpush"] != 0 || keyOf["Upush"] != 1 {
		t.Fatalf("VerifyKeys = %d %d %v %v", n, end, err, keyOf)
	}
	for name, ks := range map[string][]ed25519.PublicKey{"new key only": {pub1}, "old key only": {pub0}, "other next key": {pub0, pub2}} {
		if _, _, err := VerifyKeys(bytes.NewReader(b), ks, nil); !errors.Is(err, ErrBroken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Reopened: signed by both, extended with the new key; never with
	// the old one alone, nor on a log cut back to before the rotation.
	if l, err := OpenSigned(p, k1, pub0); err != nil {
		t.Errorf("reopen: %v", err)
	} else {
		l.Close()
	}
	if _, err := OpenSigned(p, k0); !errors.Is(err, ErrBroken) {
		t.Errorf("old key: %v", err)
	}
	cut := filepath.Join(t.TempDir(), "cut.jsonl")
	os.WriteFile(cut, []byte(lines[0]), 0o600)
	if _, end, err := VerifyKeys(bytes.NewReader([]byte(lines[0])), []ed25519.PublicKey{pub0, pub1}, nil); err != nil || end != 0 {
		t.Errorf("cut: %d %v", end, err)
	}
	if _, err := OpenSigned(cut, k1, pub0); err == nil || !strings.Contains(err.Error(), "not handed over") {
		t.Errorf("cut log opened: %v", err)
	}
	// A rotation the next key did not sign (whoever holds the old key
	// names the current key, signing for it with a key of theirs) is
	// refused.
	var first Record
	json.Unmarshal([]byte(lines[0]), &first)
	r := Record{Seq: 2, At: first.At, Event: EventKeyRotated, NewKey: base64.StdEncoding.EncodeToString(pub1), Prev: first.Hash}
	r.Hash = hashOf(r)
	r.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k0, signedMsg(r.Hash)))
	r.NewSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k2, signedMsg(r.Hash)))
	fb, _ := json.Marshal(r)
	if _, _, err := VerifyKeys(bytes.NewReader([]byte(lines[0]+string(fb)+"\n")), []ed25519.PublicKey{pub0, pub1}, nil); !errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), "not signed by the key it hands") {
		t.Errorf("rotation not signed by its new key: %v", err)
	}
	r.NewSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k1, signedMsg(r.Hash)))
	fb, _ = json.Marshal(r)
	if _, end, err := VerifyKeys(bytes.NewReader([]byte(lines[0]+string(fb)+"\n")), []ed25519.PublicKey{pub0, pub1}, nil); err != nil || end != 1 {
		t.Errorf("rotation signed by both: %d %v", end, err)
	}
	// A new key outside a rotation record is refused.
	bad := strings.Replace(lines[0], `"prev"`, `"new_key":"x","prev"`, 1)
	if _, err := Verify(bytes.NewReader([]byte(bad))); !errors.Is(err, ErrBroken) {
		t.Errorf("new_key on a push: %v", err)
	}
	// Unsigned logs cannot rotate.
	ul, _ := Open(filepath.Join(t.TempDir(), "u.jsonl"))
	if _, err := ul.Rotate(k1); err == nil {
		t.Error("unsigned log rotated")
	}
	ul.Close()
}
