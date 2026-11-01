package loxadd

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
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

func TestFormRefusesAPasswordInATextField(t *testing.T) {
	const reason = "user: it embeds a password: type the target without it (the console asks for the password at its start)"
	for _, typed := range []string{"shop:sekret", "shop:sekret@db.example.com"} {
		var out bytes.Buffer
		f := &Form{In: bufio.NewReader(strings.NewReader("\n\n\n" + typed + "\n\n\n\n\n\n\n\n\n")), Out: &out}
		a, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), nil)
		if err != nil {
			t.Fatalf("%s: %v", typed, err)
		}
		if !strings.Contains(out.String(), "  "+reason+"\n") {
			t.Errorf("%s: no re-ask with the reason:\n%s", typed, out.String())
		}
		for _, l := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(l, "  ") && strings.Contains(l, "sekret") {
				t.Errorf("reason line leaks: %q", l)
			}
		}
		for k, v := range a {
			if strings.Contains(v, "sekret") {
				t.Errorf("answer %s keeps the secret", k)
			}
		}
		_, err = (&Form{Out: io.Discard, NonInteractive: true}).Run("locksql", fieldsOf(t, "locksql", Defaults{}), Answers{"user": typed})
		if err == nil || strings.Contains(err.Error(), "sekret") || !strings.HasPrefix(err.Error(), "--user: it embeds a password") {
			t.Errorf("flag %s: %v", typed, err)
		}
	}
	for _, key := range []string{"database", "vhost", "region"} {
		lock := map[string]string{"database": "locksql", "vhost": "lockmq", "region": "lockfile"}[key]
		g := Answers{key: "a:sekret@b"}
		if key == "region" {
			g["source"], g["bucket"], g["endpoint"] = "s3", "shop-invoices", "-"
		}
		_, err := (&Form{Out: io.Discard, NonInteractive: true}).Run(lock, fieldsOf(t, lock, Defaults{}), g)
		if err == nil || strings.Contains(err.Error(), "sekret") || !strings.Contains(err.Error(), "--"+key+": it embeds a password") {
			t.Errorf("%s: %v", key, err)
		}
	}
}

func TestFormFlagNotAQuestion(t *testing.T) {
	f := &Form{Out: io.Discard, NonInteractive: true}
	_, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), Answers{"engine": "sqlite", "path": "/tmp/shop.db", "port": "5432"})
	want := "--port: not a question of lox add locksql with these answers"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %s", err, want)
	}
}

// A refused flag, a missing one or one that is no question is a usage
// error (ErrUsage), its message unchanged; an end of input is not.
func TestFormUsageErrorsAreTyped(t *testing.T) {
	f := &Form{Out: io.Discard, NonInteractive: true}
	for _, g := range []Answers{{"port": "0"}, {"engine": "sqlite"}, {"engine": "sqlite", "path": "/tmp/shop.db", "port": "5432"}} {
		_, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), g)
		if !errors.Is(err, ErrUsage) || strings.Contains(err.Error(), "usage error") {
			t.Errorf("%v: err = %v, want ErrUsage with the form's own message", g, err)
		}
	}
	// A flag refused at a terminal is a usage error too.
	_, err := (&Form{In: bufio.NewReader(strings.NewReader("")), Out: io.Discard}).Run("locksql", fieldsOf(t, "locksql", Defaults{}), Answers{"engine": "postgres", "host": "db.example.com", "port": "0"})
	if !errors.Is(err, ErrUsage) {
		t.Errorf("interactive flag: err = %v", err)
	}
	_, err = (&Form{In: bufio.NewReader(strings.NewReader("")), Out: io.Discard}).Run("locksql", fieldsOf(t, "locksql", Defaults{}), nil)
	if err == nil || errors.Is(err, ErrUsage) {
		t.Errorf("end of input: err = %v, want no ErrUsage", err)
	}
}

func TestFormEOFPartial(t *testing.T) {
	// A last line without a newline is an answer.
	var out bytes.Buffer
	f := &Form{In: bufio.NewReader(strings.NewReader("sqlite\n/tmp/shop.db")), Out: &out}
	_, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), nil)
	if err == nil || err.Error() != "no answer (end of input)" || !strings.Contains(out.String(), "Production?") {
		t.Fatalf("partial: %v\n%s", err, out.String())
	}
	// End of input while re-asking.
	out.Reset()
	f = &Form{In: bufio.NewReader(strings.NewReader("oracle\n")), Out: &out}
	_, err = f.Run("locksql", fieldsOf(t, "locksql", Defaults{}), nil)
	if err == nil || err.Error() != "no answer (end of input)" || strings.Count(out.String(), "Engine:") != 2 {
		t.Fatalf("re-ask: %v\n%s", err, out.String())
	}
}

func TestFormHintsGolden(t *testing.T) {
	var out bytes.Buffer
	f := &Form{In: bufio.NewReaderSize(&typist{lines: []string{"", "", "", "", "", "", "", "", ""}, out: &out}, 16), Out: &out, Hints: []loxinit.Source{shopDB}}
	if _, err := f.Run("locksql", fieldsOf(t, "locksql", Defaults{Source: &shopDB}), nil); err != nil {
		t.Fatal(err)
	}
	golden(t, "add-locksql-hints", out.String())
}
