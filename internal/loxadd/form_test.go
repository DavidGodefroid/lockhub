package loxadd

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden screens")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (go test -run %s -update writes it)", err, t.Name())
	}
	if got != string(want) {
		t.Errorf("%s differs (go test -update rewrites it):\n--- got\n%s\n--- want\n%s", p, got, want)
	}
}

// typist feeds one typed line per Read and writes it to out when the form
// asks for it, as a terminal echoes: the golden reads as a session.
type typist struct {
	lines   []string
	out     io.Writer
	pending []byte
}

func (r *typist) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		if len(r.lines) == 0 {
			return 0, io.EOF
		}
		r.pending = []byte(r.lines[0] + "\n")
		r.lines = r.lines[1:]
		r.out.Write(r.pending)
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func session(t *testing.T, lock string, d Defaults, given Answers, typed ...string) (string, Answers) {
	t.Helper()
	var out bytes.Buffer
	f := &Form{In: bufio.NewReaderSize(&typist{lines: typed, out: &out}, 16), Out: &out}
	a, err := f.Run(lock, fieldsOf(t, lock, d), given)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	return out.String(), a
}

func TestFormGolden(t *testing.T) {
	for _, c := range []struct {
		name, lock string
		d          Defaults
		typed      []string
		want       Answers
	}{
		{"add-locksql-ask", "locksql", Defaults{}, []string{"", "", "", "", "", "", "", "", ""},
			Answers{"engine": "postgres", "host": "host.docker.internal", "port": "5432", "tls": "disable", "credentials": "ask", "name": "db"}},
		{"add-locksql-vault-first", "locksql", Defaults{}, []string{"mariadb", "db.example.com", "", "shop", "orders", "y", "", "vault", "", "https://vault.example.com:8200", "", "", "orders"},
			Answers{"engine": "mariadb", "port": "3306", "production": "y", "tls": "verify-full", "credentials": "vault", "vault-address": "https://vault.example.com:8200", "name": "orders"}},
		{"add-locksql-vault-second", "locksql", Defaults{VaultSet: true, Declared: []string{"db"}}, []string{"", "", "", "", "", "", "", "vault", "", ""},
			Answers{"credentials": "vault", "vault-path": "database/creds/db-2", "name": "db-2"}},
		{"add-locksql-reask", "locksql", Defaults{}, []string{"oracle", "", "db.example.com:5432", "host.docker.internal", "0", "70000", "5432", "", "", "maybe", "n", "", "", ""},
			Answers{"engine": "postgres", "port": "5432", "production": "n"}},
		{"add-lockmq", "lockmq", Defaults{Source: &shopMQ}, []string{"", "", "-", "", "", "", ""},
			Answers{"url": "http://host.docker.internal:55672", "user": "orders", "vhost": "", "credentials": "ask", "name": "mq"}},
		{"add-lockfile-s3", "lockfile", Defaults{}, []string{"", "shop-invoices", "", "eu-west-1", "", "", "", ""},
			Answers{"source": "s3", "bucket": "shop-invoices", "region": "eu-west-1", "credentials": "ask", "name": "files"}},
		{"add-lockhttp", "lockhttp", Defaults{}, []string{""}, Answers{"name": "web"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, a := session(t, c.lock, c.d, nil, c.typed...)
			golden(t, c.name, out)
			for k, v := range c.want {
				if a[k] != v {
					t.Errorf("answer %s = %q, want %q", k, a[k], v)
				}
			}
			if strings.Contains(out, "sekret") {
				t.Error("leak")
			}
		})
	}
}

func TestFormNonInteractiveMissing(t *testing.T) {
	f := &Form{Out: io.Discard, NonInteractive: true}
	_, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), Answers{"engine": "sqlite"})
	want := "usage: --path is required (lox add locksql --non-interactive)"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %s", err, want)
	}
	a, err := f.Run("lockhttp", fieldsOf(t, "lockhttp", Defaults{}), Answers{})
	if err != nil || a["name"] != "web" {
		t.Fatalf("defaults: %v %v", a, err)
	}
}

func TestFormFlagsChecked(t *testing.T) {
	var out bytes.Buffer
	f := &Form{Out: &out, NonInteractive: true}
	_, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), Answers{"port": "0"})
	if err == nil || err.Error() != "--port: want a number from 1 to 65535" {
		t.Fatalf("got %v", err)
	}
	_, err = f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), Answers{"host": "user:sekret@db.example.com"})
	if err == nil || !strings.HasPrefix(err.Error(), "--host: ") || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("non-interactive printed %q", out.String())
	}
}

func TestFormEOF(t *testing.T) {
	var out bytes.Buffer
	f := &Form{In: bufio.NewReader(strings.NewReader("postgres\n")), Out: &out}
	_, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), nil)
	if err == nil || err.Error() != "no answer (end of input)" {
		t.Fatalf("got %v", err)
	}
}
