// Package egress is a lock's egress gateway (lockhub#123): a TCP forwarder
// that lox run puts between a lock and the endpoints of its reviewed
// profile. The lock sits on an internal network (no route out); the
// gateway listens there under the endpoints' own names (network aliases),
// so host names and TLS server names stay the lock's, and forwards each
// listening port to one fixed endpoint, or, when several endpoints share a
// port, to the one the connection's TLS server name (SNI) names. Nothing
// else is forwarded: a connection that matches no endpoint is closed.
//
// lox run runs it twice per lock: the front, on the lock's network, and
// the back, the only one with a route out. The front's aliases would
// otherwise answer its own lookups of the endpoints' names.
package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Forward is one --forward: connections to Listen go to Host:Port; with
// SNI set, only those whose TLS ClientHello names SNI.
type Forward struct {
	Listen int
	Host   string
	Port   int
	SNI    string
}

// String is the flag form: LISTEN=HOST:PORT[,sni=NAME].
func (f Forward) String() string {
	s := strconv.Itoa(f.Listen) + "=" + net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
	if f.SNI != "" {
		s += ",sni=" + f.SNI
	}
	return s
}

// ParseForward reads LISTEN=HOST:PORT[,sni=NAME].
func ParseForward(s string) (Forward, error) {
	var f Forward
	l, rest, ok := strings.Cut(s, "=")
	if !ok {
		return f, fmt.Errorf("forward %q: want LISTEN=HOST:PORT[,sni=NAME]", s)
	}
	target, sni, hasSNI := strings.Cut(rest, ",sni=")
	if hasSNI {
		if sni == "" || strings.ContainsAny(sni, ",= ") {
			return f, fmt.Errorf("forward %q: empty or malformed sni", s)
		}
		f.SNI = strings.ToLower(sni)
	}
	var err error
	if f.Listen, err = port(l); err != nil {
		return f, fmt.Errorf("forward %q: listen port: %w", s, err)
	}
	h, p, err := net.SplitHostPort(target)
	if err != nil || h == "" {
		return f, fmt.Errorf("forward %q: want HOST:PORT after =", s)
	}
	f.Host = h
	if f.Port, err = port(p); err != nil {
		return f, fmt.Errorf("forward %q: target port: %w", s, err)
	}
	return f, nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("want 1 to 65535")
	}
	return n, nil
}

// Check refuses a set of forwards the gateway cannot serve unambiguously:
// on a port shared by several forwards, each must name a distinct SNI.
func Check(fs []Forward) error {
	if len(fs) == 0 {
		return errors.New("no --forward: nothing to serve")
	}
	by := map[int][]Forward{}
	for _, f := range fs {
		by[f.Listen] = append(by[f.Listen], f)
	}
	for p, l := range by {
		if len(l) == 1 {
			continue
		}
		seen := map[string]bool{}
		for _, f := range l {
			if f.SNI == "" {
				return fmt.Errorf("port %d is shared by %d forwards: each needs an sni", p, len(l))
			}
			if seen[f.SNI] {
				return fmt.Errorf("port %d: sni %s twice", p, f.SNI)
			}
			seen[f.SNI] = true
		}
	}
	return nil
}

// Gateway serves a set of forwards.
type Gateway struct {
	Forwards []Forward
	// Log gets one line per refused or failed connection (never data).
	Log io.Writer
	// Dial dials a target (nil: a net.Dialer with a 10s timeout).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Listen listens on a port (nil: net.Listen on ":PORT").
	Listen func(port int) (net.Listener, error)
	// Ready, if set, is called once every port listens.
	Ready func()

	mu sync.Mutex
}

func (g *Gateway) logf(format string, a ...any) {
	if g.Log == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fmt.Fprintf(g.Log, "egress: "+format+"\n", a...)
}

// Serve listens on every forward's port until ctx ends.
func (g *Gateway) Serve(ctx context.Context) error {
	if err := Check(g.Forwards); err != nil {
		return err
	}
	by := map[int][]Forward{}
	var ports []int
	for _, f := range g.Forwards {
		if _, ok := by[f.Listen]; !ok {
			ports = append(ports, f.Listen)
		}
		by[f.Listen] = append(by[f.Listen], f)
	}
	slices.Sort(ports)
	listen := g.Listen
	if listen == nil {
		listen = func(p int) (net.Listener, error) { return net.Listen("tcp", ":"+strconv.Itoa(p)) }
	}
	var ls []net.Listener
	closeAll := func() {
		for _, l := range ls {
			l.Close()
		}
	}
	for _, p := range ports {
		l, err := listen(p)
		if err != nil {
			closeAll()
			return fmt.Errorf("listen on %d: %w", p, err)
		}
		ls = append(ls, l)
	}
	for _, p := range ports {
		for _, f := range by[p] {
			g.logf("forwarding %s", f)
		}
	}
	if g.Ready != nil {
		g.Ready()
	}
	var wg sync.WaitGroup
	errc := make(chan error, len(ls))
	for i, l := range ls {
		wg.Add(1)
		go func(l net.Listener, fs []Forward) {
			defer wg.Done()
			errc <- g.accept(ctx, l, fs)
		}(l, by[ports[i]])
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	closeAll()
	wg.Wait()
	return err
}

func (g *Gateway) accept(ctx context.Context, l net.Listener, fs []Forward) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go g.handle(ctx, c, fs)
	}
}

// handshakeWait bounds how long a shared port waits for a ClientHello.
const handshakeWait = 10 * time.Second

func (g *Gateway) handle(ctx context.Context, c net.Conn, fs []Forward) {
	defer c.Close()
	f := fs[0]
	var head []byte
	if len(fs) > 1 || f.SNI != "" {
		c.SetReadDeadline(time.Now().Add(handshakeWait))
		sni, read, err := peekSNI(c)
		c.SetReadDeadline(time.Time{})
		head = read
		i := slices.IndexFunc(fs, func(f Forward) bool { return f.SNI == sni })
		if err != nil || i < 0 {
			g.logf("refused a connection to port %d from %s: TLS server name %q matches no endpoint", f.Listen, c.RemoteAddr(), sni)
			return
		}
		f = fs[i]
	}
	dial := g.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	addr := net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
	u, err := dial(ctx, "tcp", addr)
	if err != nil {
		g.logf("port %d: %s unreachable: %v", f.Listen, addr, err)
		return
	}
	defer u.Close()
	if len(head) > 0 {
		if _, err := u.Write(head); err != nil {
			return
		}
	}
	pipe(c, u)
}

// pipe copies both ways until both sides are done, half-closing as each
// direction ends.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// errSNI stops the handshake once the ClientHello is read.
var errSNI = errors.New("sni read")

// peekSNI reads the TLS ClientHello from c and returns the server name it
// names (lower case) and the bytes read, to replay to the endpoint.
func peekSNI(c net.Conn) (string, []byte, error) {
	rec := &recorder{r: c}
	sni := ""
	seen := false
	err := tls.Server(rec, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni, seen = strings.ToLower(h.ServerName), true
		return nil, errSNI
	}}).Handshake()
	if !seen {
		if err == nil {
			err = errors.New("no ClientHello")
		}
		return "", rec.buf.Bytes(), err
	}
	return sni, rec.buf.Bytes(), nil
}

// recorder is a read-only net.Conn that keeps what it read; writes (the
// TLS server's alert) are dropped.
type recorder struct {
	r   net.Conn
	buf bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf.Write(p[:n])
	return n, err
}
func (r *recorder) Write(p []byte) (int, error)        { return len(p), nil }
func (r *recorder) Close() error                       { return nil }
func (r *recorder) LocalAddr() net.Addr                { return r.r.LocalAddr() }
func (r *recorder) RemoteAddr() net.Addr               { return r.r.RemoteAddr() }
func (r *recorder) SetDeadline(t time.Time) error      { return r.r.SetDeadline(t) }
func (r *recorder) SetReadDeadline(t time.Time) error  { return r.r.SetReadDeadline(t) }
func (r *recorder) SetWriteDeadline(t time.Time) error { return nil }
