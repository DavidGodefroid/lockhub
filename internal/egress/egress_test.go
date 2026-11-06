package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseForward(t *testing.T) {
	for in, want := range map[string]Forward{
		"5432=db.example.com:5432":                 {Listen: 5432, Host: "db.example.com", Port: 5432},
		"443=gwout-db:20001,sni=Vault.Example.com": {Listen: 443, Host: "gwout-db", Port: 20001, SNI: "vault.example.com"},
		"8200=[::1]:8200":                          {Listen: 8200, Host: "::1", Port: 8200},
	} {
		got, err := ParseForward(in)
		if err != nil || got != want {
			t.Errorf("ParseForward(%q) = %+v, %v; want %+v", in, got, err, want)
		}
		if again, err := ParseForward(got.String()); err != nil || again != got {
			t.Errorf("round trip of %q: %+v, %v", in, again, err)
		}
	}
	for _, bad := range []string{"", "5432", "x=db:5432", "0=db:5432", "5432=db", "5432=:5432", "5432=db:70000", "443=h:443,sni=", "443=h:443,sni=a,b"} {
		if _, err := ParseForward(bad); err == nil {
			t.Errorf("ParseForward(%q) accepted", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	if err := Check(nil); err == nil {
		t.Error("no forward accepted")
	}
	ok := []Forward{{Listen: 443, Host: "b", Port: 1, SNI: "a.example"}, {Listen: 443, Host: "b", Port: 2, SNI: "b.example"}, {Listen: 5432, Host: "db", Port: 5432}}
	if err := Check(ok); err != nil {
		t.Errorf("Check: %v", err)
	}
	for name, fs := range map[string][]Forward{
		"shared without sni": {{Listen: 443, Host: "a", Port: 1}, {Listen: 443, Host: "b", Port: 2, SNI: "b"}},
		"same sni twice":     {{Listen: 443, Host: "a", Port: 1, SNI: "x"}, {Listen: 443, Host: "b", Port: 2, SNI: "x"}},
	} {
		if err := Check(fs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// echo is a target that answers each line with name + line.
func echo(t *testing.T, name string) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				s := bufio.NewScanner(c)
				for s.Scan() {
					io.WriteString(c, name+":"+s.Text()+"\n")
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

// serve runs g on loopback ports; addr maps a forward's listen port to
// where it listens.
func serve(t *testing.T, g *Gateway) map[int]string {
	t.Helper()
	addrs := map[int]string{}
	var mu sync.Mutex
	g.Listen = func(p int) (net.Listener, error) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			mu.Lock()
			addrs[p] = l.Addr().String()
			mu.Unlock()
		}
		return l, err
	}
	ready := make(chan struct{})
	g.Ready = func() { close(ready) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Serve: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("gateway not ready")
	}
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return addrs
}

func TestForwardsPlainTCP(t *testing.T) {
	p, stop := echo(t, "db")
	defer stop()
	var log syncBuf
	g := &Gateway{Forwards: []Forward{{Listen: 5432, Host: "127.0.0.1", Port: p}}, Log: &log}
	addrs := serve(t, g)
	c, err := net.Dial("tcp", addrs[5432])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "hello\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != "db:hello\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !strings.Contains(log.String(), "forwarding 5432=127.0.0.1:"+strconv.Itoa(p)) {
		t.Errorf("log: %q", log.String())
	}
}

// A shared port routes by the ClientHello's server name, replays it to
// the endpoint, and closes a connection whose name matches none.
func TestSharedPortRoutesBySNI(t *testing.T) {
	seen := map[string]chan string{"a": make(chan string, 1), "b": make(chan string, 1)}
	target := func(name string) int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			rec := &recorder{r: c}
			sni, _, _ := peekSNI(rec)
			seen[name] <- sni
		}()
		return l.Addr().(*net.TCPAddr).Port
	}
	pa, pb := target("a"), target("b")
	var log syncBuf
	g := &Gateway{Log: &log, Forwards: []Forward{
		{Listen: 443, Host: "127.0.0.1", Port: pa, SNI: "a.example"},
		{Listen: 443, Host: "127.0.0.1", Port: pb, SNI: "b.example"},
	}}
	addrs := serve(t, g)
	hello := func(name string) {
		c, err := net.Dial("tcp", addrs[443])
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}
	go hello("B.example")
	select {
	case got := <-seen["b"]:
		if got != "b.example" {
			t.Errorf("b got the ClientHello for %q", got)
		}
	case <-seen["a"]:
		t.Fatal("b.example went to a")
	case <-time.After(5 * time.Second):
		t.Fatal("b.example reached no endpoint")
	}
	hello("evil.example")
	select {
	case <-seen["a"]:
		t.Fatal("an unlisted server name reached an endpoint")
	case <-time.After(300 * time.Millisecond):
	}
	if !strings.Contains(log.String(), `"evil.example" matches no endpoint`) {
		t.Errorf("log: %q", log.String())
	}
	// Not TLS at all: refused too.
	c, err := net.Dial("tcp", addrs[443])
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("a plain request on a shared port got an answer")
	}
	c.Close()
}

func TestUnreachableTargetClosesAndLogs(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	var log syncBuf
	g := &Gateway{Log: &log, Forwards: []Forward{{Listen: 1, Host: "127.0.0.1", Port: p}}}
	addrs := serve(t, g)
	c, err := net.Dial("tcp", addrs[1])
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("read from an unreachable target")
	}
	c.Close()
	for i := 0; i < 50 && !strings.Contains(log.String(), "unreachable"); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(log.String(), "unreachable") {
		t.Errorf("log: %q", log.String())
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
