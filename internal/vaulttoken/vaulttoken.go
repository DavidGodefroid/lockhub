// Package vaulttoken reads the host's Vault CLI token for lox run, and
// checks it at the workspace's Vault before a lock gets it (lockhub#124).
//
// The token is never logged, printed or written: the CLI's output and
// errors are not shown, an error names what is wrong and never the
// token, and the caller wipes the token it gets.
package vaulttoken

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// MaxToken is the longest token read (the CLI's output, ~/.vault-token).
const MaxToken = 4096

// MinTTL is the shortest time a token must still live to be used.
const MinTTL = 60 * time.Second

// DefaultTimeout bounds the CLI and each call to Vault.
const DefaultTimeout = 5 * time.Second

// Source is where the host's token is read, and the Vault it is checked
// at: the workspace's reviewed vault: block.
type Source struct {
	Address, Namespace string
	// CA is the reviewed CA's PEM (nil: the system's CAs).
	CA []byte
	// Timeout bounds the CLI and each call to Vault (0: DefaultTimeout).
	Timeout time.Duration
	// LookPath, Environ and Home stand for exec.LookPath, os.Environ and
	// os.UserHomeDir (tests).
	LookPath func(file string) (string, error)
	Environ  func() []string
	Home     func() (string, error)
}

// Token reads the host's token and checks it may read every one of
// paths: the token (the caller wipes it), or an error saying why it is
// unusable, in words a card shows ("the Vault CLI's token …").
func (s *Source) Token(ctx context.Context, paths []string) ([]byte, error) {
	tok, err := s.Read(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Check(ctx, tok, paths); err != nil {
		clear(tok)
		return nil, err
	}
	return tok, nil
}

func (s *Source) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultTimeout
}

// Read reads the host's token: `vault print token`, run with VAULT_ADDR
// and VAULT_NAMESPACE of the reviewed block (it honours the user's
// token helper); without a vault binary, ~/.vault-token, if it is a
// regular file of the user's, 0600 or stricter, at most MaxToken bytes.
// VAULT_TOKEN of lox's own environment is never used: too easy to
// inherit by accident.
func (s *Source) Read(ctx context.Context) ([]byte, error) {
	look := s.LookPath
	if look == nil {
		look = exec.LookPath
	}
	bin, err := look("vault")
	if err == nil {
		return s.readCLI(ctx, bin)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		return nil, errors.New("the Vault CLI cannot be run (vault on PATH)")
	}
	return s.readFile()
}

func (s *Source) readCLI(ctx context.Context, bin string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "print", "token")
	cmd.Env = s.env()
	// A token helper it started may hold the pipe past the timeout.
	cmd.WaitDelay = time.Second
	cmd.Stdin, cmd.Stderr = nil, nil // its errors could quote anything: not shown
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.New("the Vault CLI cannot be run")
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.New("the Vault CLI cannot be run")
	}
	buf := make([]byte, MaxToken+2)
	defer clear(buf)
	var n int
	var rerr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, rerr = io.ReadFull(out, buf)
		if rerr == nil {
			// More than a token: read to the end, so the CLI is not stuck.
			_, _ = io.Copy(io.Discard, out)
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// A child of the CLI may hold the pipe open: not waited for.
		out.Close()
		<-done
	}
	werr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("the Vault CLI did not answer within %s", s.timeout())
	case werr != nil:
		return nil, errors.New("the Vault CLI found no token (vault print token failed: vault login first)")
	case rerr == nil:
		return nil, errors.New("the Vault CLI's token is longer than 4 KiB")
	}
	return token(buf[:n], "the Vault CLI's token")
}

// env is the CLI's environment: lox's own, without VAULT_TOKEN (which
// `vault print token` would print), with the reviewed address and
// namespace.
func (s *Source) env() []string {
	environ := s.Environ
	if environ == nil {
		environ = os.Environ
	}
	var env []string
	for _, kv := range environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "VAULT_TOKEN", "VAULT_ADDR", "VAULT_NAMESPACE":
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "VAULT_ADDR="+s.Address)
	if s.Namespace != "" {
		env = append(env, "VAULT_NAMESPACE="+s.Namespace)
	}
	return env
}

func (s *Source) readFile() ([]byte, error) {
	home := s.Home
	if home == nil {
		home = os.UserHomeDir
	}
	h, err := home()
	if err != nil || !filepath.IsAbs(h) {
		return nil, errors.New("no Vault CLI on PATH, and no home directory for ~/.vault-token")
	}
	f, err := os.OpenFile(filepath.Join(h, ".vault-token"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no Vault CLI on PATH, and no ~/.vault-token (vault login first)")
	}
	if err != nil {
		return nil, errors.New("~/.vault-token cannot be opened (a symbolic link is refused)")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("~/.vault-token is not a regular file")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return nil, errors.New("~/.vault-token is not yours")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("~/.vault-token is readable by others: chmod 600 it")
	}
	if fi.Size() > MaxToken {
		return nil, errors.New("~/.vault-token is larger than 4 KiB")
	}
	buf := make([]byte, MaxToken+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if err == nil {
		return nil, errors.New("~/.vault-token is larger than 4 KiB")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, errors.New("~/.vault-token cannot be read")
	}
	return token(buf[:n], "~/.vault-token")
}

// token is b without its surrounding white space, a copy, if it reads as
// a token: printable ASCII, no space.
func token(b []byte, what string) ([]byte, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, errors.New(what + " is empty (vault login first)")
	}
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return nil, errors.New(what + " is not a token")
		}
	}
	return bytes.Clone(b), nil
}

// Check asks the Vault whether tok may be used: its lookup-self says it
// lives at least MinTTL (or never expires), and its capabilities-self
// give read (or root) on every one of paths.
func (s *Source) Check(ctx context.Context, tok []byte, paths []string) error {
	if len(paths) == 0 {
		return errors.New("the lock's reviewed profile names no vault_path to check the Vault CLI's token on")
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	var look struct {
		Data struct {
			TTL *int64 `json:"ttl"`
		} `json:"data"`
	}
	if err := s.call(ctx, c, http.MethodGet, "/v1/auth/token/lookup-self", nil, tok, &look); err != nil {
		return err
	}
	switch ttl := look.Data.TTL; {
	case ttl == nil:
		return errors.New("Vault's token lookup names no ttl")
	case *ttl < 0:
		return errors.New("the Vault CLI's token is expired (vault login again)")
	case *ttl != 0 && time.Duration(*ttl)*time.Second < MinTTL:
		return errors.New("the Vault CLI's token expires in under a minute (vault login again)")
	}
	body, _ := json.Marshal(map[string][]string{"paths": paths})
	var caps map[string]json.RawMessage
	if err := s.call(ctx, c, http.MethodPost, "/v1/sys/capabilities-self", body, tok, &caps); err != nil {
		return err
	}
	if d, ok := caps["data"]; ok {
		var data map[string]json.RawMessage
		if json.Unmarshal(d, &data) == nil && len(data) > 0 {
			caps = data
		}
	}
	for _, p := range paths {
		raw, ok := caps[p]
		if !ok && len(paths) == 1 {
			raw, ok = caps["capabilities"]
		}
		var cs []string
		if !ok || json.Unmarshal(raw, &cs) != nil || !canRead(cs) {
			return fmt.Errorf("the Vault CLI's token lacks read on %s", p)
		}
	}
	return nil
}

func canRead(cs []string) bool {
	for _, c := range cs {
		if c == "deny" {
			return false
		}
	}
	for _, c := range cs {
		if c == "read" || c == "root" {
			return true
		}
	}
	return false
}

// client reaches the reviewed address only: no proxy (the token would
// cross it), the reviewed CA or the system's, and host.docker.internal
// (the consoles' name for this machine) dialled as the loopback.
func (s *Source) client() (*http.Client, error) {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	if s.CA != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(s.CA) {
			return nil, errors.New("vault.ca_file holds no PEM certificate")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	d := &net.Dialer{Timeout: s.timeout()}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, p, err := net.SplitHostPort(addr); err == nil && strings.EqualFold(h, "host.docker.internal") {
			addr = net.JoinHostPort("127.0.0.1", p)
		}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr, Timeout: s.timeout(),
		// A redirect could take the token elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// maxBody bounds what is read of Vault's answer.
const maxBody = 1 << 20

func (s *Source) call(ctx context.Context, c *http.Client, method, path string, body, tok []byte, out any) error {
	u, err := url.Parse(strings.TrimRight(s.Address, "/") + path)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("vault.address is not an http(s) URL")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return errors.New("vault.address is not an http(s) URL")
	}
	req.Header.Set("X-Vault-Token", string(tok))
	req.Header.Set("X-Vault-Request", "true")
	if s.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() || ctx.Err() != nil {
			return fmt.Errorf("Vault did not answer within %s", s.timeout())
		}
		return errors.New("Vault cannot be reached at " + s.Address)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return errors.New("Vault's answer cannot be read")
	}
	switch {
	case resp.StatusCode == http.StatusForbidden && path == "/v1/auth/token/lookup-self":
		return errors.New("the Vault CLI's token is expired or revoked (vault login again)")
	case resp.StatusCode == http.StatusForbidden:
		return errors.New("the Vault CLI's token may not ask its capabilities (sys/capabilities-self)")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("Vault answered HTTP %d to %s", resp.StatusCode, strings.TrimPrefix(path, "/v1/"))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return errors.New("Vault's answer is not JSON")
	}
	return nil
}
