// Package ticketcodec is the hub's ticket format: lockkit's ticket
// package. It is the only lockhub package that imports it.
package ticketcodec

import (
	"crypto/ed25519"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
)

// Codec implements hub.Codec with lockkit tickets and decisions.
type Codec struct{}

var _ hub.Codec = Codec{}

// KeyID names a lock key as tickets do.
func (Codec) KeyID(k ed25519.PublicKey) string { return ticket.KeyID(k) }

// VerifyRequest checks a Lock-Sig header value.
func (Codec) VerifyRequest(k ed25519.PublicKey, method, pathQuery, instance string, at time.Time, nonce string, body []byte, sig string) bool {
	msg := ticket.RequestMessage(method, pathQuery, instance, at, nonce, body)
	return ticket.VerifyBytes(k, ticket.ContextRequest, msg, sig) == nil
}

// VerifyTicket verifies a signed ticket and maps it to hub.Info. The TTL
// is the ticket's own, clamped to its risk class: a lock may shorten the
// wait, never lengthen it, and a write without an expiry gets its class's.
func (Codec) VerifyTicket(k ed25519.PublicKey, raw []byte) (hub.Info, error) {
	t, err := ticket.VerifyTicket(k, raw)
	if err != nil {
		return hub.Info{}, err
	}
	var ttl time.Duration
	if t.Expires != nil {
		ttl = t.Expires.Sub(t.Created)
	}
	return hub.Info{
		ID: t.ID, Instance: t.Source.Instance, KeyID: t.Source.KeyID,
		Risk: string(t.Risk), PlanHash: t.PlanHash, Created: t.Created,
		TTL:        ticket.ClampTTL(t.Risk, ttl),
		Production: t.Flags.Production, Retype: t.Flags.Retype,
	}, nil
}

// SignDecision builds and signs the decision on t.
func (Codec) SignDecision(k ed25519.PrivateKey, t hub.Info, v hub.Verdict, at time.Time) ([]byte, error) {
	out := ticket.Denied
	if v.Approved {
		out = ticket.Approved
	}
	d := &ticket.Decision{
		V: ticket.Version, Ticket: t.ID, Instance: t.Instance, KeyID: t.KeyID, PlanHash: t.PlanHash,
		Decision: out, Reason: v.Reason,
		Approver: ticket.Approver{ID: v.ApproverID, Display: v.ApproverDisplay},
		Facade:   v.Facade, At: at.UTC().Truncate(time.Millisecond), Nonce: ticket.NewNonce(),
	}
	if err := d.Sign(k); err != nil {
		return nil, err
	}
	return d.Marshal()
}
