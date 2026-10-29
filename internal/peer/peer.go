// Package peer finds who is at the other end of a unix socket connection.
package peer

import (
	"context"
	"net"
)

type ctxKey struct{}

// Cred is a connection's peer, as the kernel reports it.
type Cred struct {
	UID, PID int
	Known    bool
}

// ConnContext is an http.Server ConnContext that records the peer of a
// unix socket connection.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	cr, err := cred(uc)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, cr)
}

// From returns the peer recorded by ConnContext.
func From(ctx context.Context) Cred {
	c, _ := ctx.Value(ctxKey{}).(Cred)
	return c
}
