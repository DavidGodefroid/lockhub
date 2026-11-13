package vaulttoken

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cliToken = "hvs.cli-token-0123456789"

// fakeVault puts a vault binary on PATH: `vault print token` prints the
// token and records the environment it ran in; script replaces its body.
func fakeVault(t *testing.T, script string) (envFile string) {
	t.Helper()
	dir := t.TempDir()
	envFile = filepath.Join(dir, "env")
	if script == "" {
		script = `[ "$1 $2" = "print token" ] || exit 3
printf '%s\n' "` + cliToken + `"`
	}
	body := "#!/bin/sh\nprintf '%s|%s|%s' \"$VAULT_ADDR\" \"$VAULT_NAMESPACE\" \"${VAULT_TOKEN-unset}\" >" + envFile + "\n" + script + "\n"
	if err := os.WriteFile(filepath.Join(dir, "vault"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return envFile
}

func TestReadRunsTheCLIWithTheReviewedVault(t *testing.T) {
	env := fakeVault(t, "")
	t.Setenv("VAULT_TOKEN", "hvs.from-lox-env")
	t.Setenv("VAULT_ADDR", "https://elsewhere.example.com")
	s := &Source{Address: "https://vault.example.com:8200", Namespace: "shop", Home: func() (string, error) { return t.TempDir(), nil }}
	tok, err := s.Read(context.Background())
	if err != nil || string(tok) != cliToken {
		t.Fatalf("read %q, %v", tok, err)
	}
	b, _ := os.ReadFile(env)
	if string(b) != "https://vault.example.com:8200|shop|unset" {
		t.Errorf("the CLI ran with VAULT_ADDR|VAULT_NAMESPACE|VAULT_TOKEN = %s", b)
	}
}

func TestReadCLIFailures(t *testing.T) {
	for name, c := range map[string]struct {
		script, want string
		timeout      time.Duration
	}{
		"fails":   {"echo hvs.leaked-in-stderr >&2; echo hvs.leaked-in-stdout; exit 2", "the Vault CLI found no token", 0},
		"empty":   {"exit 0", "the Vault CLI's token is empty", 0},
		"spaces":  {"echo 'hvs.a hvs.b'", "the Vault CLI's token is not a token", 0},
		"too big": {"head -c 5000 /dev/zero | tr '\\0' a", "longer than 4 KiB", 0},
		"slow":    {"sleep 5; echo hvs.late", "the Vault CLI did not answer within 200ms", 200 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			fakeVault(t, c.script)
			t.Setenv("PATH", os.Getenv("PATH")+":/usr/bin:/bin")
			s := &Source{Address: "https://vault.example.com", Timeout: c.timeout}
			tok, err := s.Read(context.Background())
			if err == nil || tok != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, %v; want %q", tok, err, c.want)
			}
			if strings.Contains(err.Error(), "hvs.") {
				t.Errorf("the error quotes the CLI: %v", err)
			}
		})
	}
}

// Without a vault binary: ~/.vault-token, only a regular 0600 file of
// the user's; VAULT_TOKEN of the environment is never a fallback.
func TestReadTokenFile(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("VAULT_TOKEN", "hvs.from-lox-env")
	home := t.TempDir()
	s := &Source{Address: "https://vault.example.com", Home: func() (string, error) { return home, nil }}
	file := filepath.Join(home, ".vault-token")
	if _, err := s.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "no ~/.vault-token") {
		t.Fatalf("no file: %v", err)
	}
	os.WriteFile(file, []byte(cliToken+"\n"), 0o600)
	if tok, err := s.Read(context.Background()); err != nil || string(tok) != cliToken {
		t.Fatalf("0600 file: %q %v", tok, err)
	}
	os.Chmod(file, 0o400)
	if tok, err := s.Read(context.Background()); err != nil || string(tok) != cliToken {
		t.Fatalf("0400 file: %q %v", tok, err)
	}
	os.Chmod(file, 0o644)
	if tok, err := s.Read(context.Background()); err == nil || tok != nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("0644 file: %q %v", tok, err)
	}
	os.Chmod(file, 0o600)
	os.Rename(file, file+".real")
	os.Symlink(file+".real", file)
	if tok, err := s.Read(context.Background()); err == nil || tok != nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink: %q %v", tok, err)
	}
	os.Remove(file)
	os.Mkdir(file, 0o700)
	if _, err := s.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	os.Remove(file)
	os.WriteFile(file, []byte(strings.Repeat("a", MaxToken+1)), 0o600)
	if _, err := s.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than 4 KiB") {
		t.Errorf("big file: %v", err)
	}
}

// vaultServer is a Vault answering lookup-self and capabilities-self for
// cliToken in namespace shop.
type vaultServer struct {
	ttl   int64
	caps  map[string][]string
	code  int // lookup-self's status (0: 200)
	delay time.Duration
	seen  []string
}

func (v *vaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.seen = append(v.seen, r.Method+" "+r.URL.Path)
	time.Sleep(v.delay)
	if r.Header.Get("X-Vault-Token") != cliToken || r.Header.Get("X-Vault-Namespace") != "shop" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	switch r.URL.Path {
	case "/v1/auth/token/lookup-self":
		if v.code != 0 {
			w.WriteHeader(v.code)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": v.ttl, "id": cliToken}})
	case "/v1/sys/capabilities-self":
		var req struct{ Paths []string }
		json.NewDecoder(r.Body).Decode(&req)
		out := map[string]any{}
		data := map[string]any{}
		for _, p := range req.Paths {
			out[p], data[p] = v.caps[p], v.caps[p]
		}
		out["data"] = data
		json.NewEncoder(w).Encode(out)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestCheck(t *testing.T) {
	const path = "secret/data/shop/inventory"
	for name, c := range map[string]struct {
		v    vaultServer
		tok  string
		want string // "" accepted
	}{
		"valid":          {vaultServer{ttl: 3600, caps: map[string][]string{path: {"read", "list"}}}, cliToken, ""},
		"root no expiry": {vaultServer{ttl: 0, caps: map[string][]string{path: {"root"}}}, cliToken, ""},
		"short ttl":      {vaultServer{ttl: 30, caps: map[string][]string{path: {"read"}}}, cliToken, "expires in under a minute"},
		"expired":        {vaultServer{ttl: -1, caps: map[string][]string{path: {"read"}}}, cliToken, "is expired"},
		"no read":        {vaultServer{ttl: 3600, caps: map[string][]string{path: {"list"}}}, cliToken, "lacks read on " + path},
		"deny":           {vaultServer{ttl: 3600, caps: map[string][]string{path: {"deny", "read"}}}, cliToken, "lacks read on " + path},
		"403":            {vaultServer{}, "hvs.revoked-token", "expired or revoked"},
		"500":            {vaultServer{code: 500}, cliToken, "Vault answered HTTP 500 to auth/token/lookup-self"},
		"timeout":        {vaultServer{delay: 500 * time.Millisecond}, cliToken, "Vault did not answer within 100ms"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(&c.v)
			defer srv.Close()
			s := &Source{Address: srv.URL, Namespace: "shop", Timeout: 100 * time.Millisecond}
			if name != "timeout" {
				s.Timeout = 5 * time.Second
			}
			err := s.Check(context.Background(), []byte(c.tok), []string{path})
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if err != nil && (strings.Contains(err.Error(), c.tok) || strings.Contains(err.Error(), "hvs.")) {
				t.Errorf("the reason names the token: %v", err)
			}
		})
	}
}

// host.docker.internal, the consoles' name for this machine, is the
// loopback from lox run; no proxy carries the token.
func TestCheckHostGatewayNoProxy(t *testing.T) {
	v := &vaultServer{ttl: 0, caps: map[string][]string{"secret/x": {"read"}}}
	srv := httptest.NewServer(v)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	s := &Source{Address: "http://host.docker.internal:" + port, Namespace: "shop"}
	if err := s.Check(context.Background(), []byte(cliToken), []string{"secret/x"}); err != nil {
		t.Fatal(err)
	}
	if len(v.seen) != 2 {
		t.Errorf("calls %v", v.seen)
	}
	if err := s.Check(context.Background(), []byte(cliToken), nil); err == nil || !strings.Contains(err.Error(), "names no vault_path") {
		t.Errorf("no path: %v", err)
	}
}

func TestCheckReviewedCA(t *testing.T) {
	v := &vaultServer{ttl: 0, caps: map[string][]string{"secret/x": {"read"}}}
	srv := httptest.NewTLSServer(v)
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := &Source{Address: srv.URL, Namespace: "shop", CA: ca}
	if err := s.Check(context.Background(), []byte(cliToken), []string{"secret/x"}); err != nil {
		t.Fatalf("reviewed CA: %v", err)
	}
	s.CA = nil
	if err := s.Check(context.Background(), []byte(cliToken), []string{"secret/x"}); err == nil || !strings.Contains(err.Error(), "cannot be reached") {
		t.Errorf("system CAs took the test certificate: %v", err)
	}
	s.CA = []byte("not a pem")
	if err := s.Check(context.Background(), []byte(cliToken), []string{"secret/x"}); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Errorf("bad CA: %v", err)
	}
}

func TestTokenReadsThenChecks(t *testing.T) {
	fakeVault(t, "")
	v := &vaultServer{ttl: 30, caps: map[string][]string{"secret/x": {"read"}}}
	srv := httptest.NewServer(v)
	defer srv.Close()
	s := &Source{Address: srv.URL, Namespace: "shop"}
	if tok, err := s.Token(context.Background(), []string{"secret/x"}); tok != nil || err == nil {
		t.Fatalf("short ttl used: %q %v", tok, err)
	}
	v.ttl = 7200
	if tok, err := s.Token(context.Background(), []string{"secret/x"}); err != nil || string(tok) != cliToken {
		t.Fatalf("token %q %v", tok, err)
	}
}
