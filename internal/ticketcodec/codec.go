// Package ticketcodec is the hub's ticket format: lockkit's ticket
// package. It is the only lockhub package that imports it.
package ticketcodec

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
)

// Codec implements hub.Codec with lockkit tickets and decisions.
type Codec struct{}

var _ hub.Codec = Codec{}

// KeyID names a lock key as tickets do.
func (Codec) KeyID(k ed25519.PublicKey) string { return ticket.KeyID(k) }

// TicketVersions are the schema versions lockkit's ticket package
// verifies (it refuses any other): version 1, and the tickets that name
// their kind (ticket.VersionKinds).
func (Codec) TicketVersions() []int { return []int{ticket.Version, ticket.VersionKinds} }

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
	info := hub.Info{
		ID: t.ID, Instance: t.Source.Instance, KeyID: t.Source.KeyID,
		Risk: string(t.Risk), PlanHash: t.PlanHash, Created: t.Created,
		TTL:        ticket.ClampTTL(t.Risk, ttl),
		Production: t.Flags.Production, Retype: t.Flags.Retype, NeverAuto: t.Flags.NeverAuto,
	}
	fl, err := ticket.Canonical(&t.Flags)
	if err != nil {
		return hub.Info{}, err
	}
	info.Flags = string(fl)
	info.V, info.Kind = t.V, string(t.Kind)
	info.AskSecret = t.Kind == ticket.KindConnect && t.Subject != nil && t.Subject.SecretTo != ""
	if t.AsksInputs() {
		info.AskInputs, info.Inputs = true, slices.Clone(t.Subject.Inputs)
		info.AskSecret = t.Subject.SecretTo != ""
	}
	if t.Renews != nil {
		info.Renews = &hub.Renewal{Of: t.Renews.Of, Unchanged: t.Renews.Unchanged()}
	}
	return info, nil
}

// NewID makes a hub request id (a ULID, like ticket ids).
func (Codec) NewID(now time.Time) string { return ticket.NewID(now) }

// SignRequest builds and signs a lockkit ticket.HubRequest. A reveal's
// key must be a valid ticket.RevealKey for q's ticket, lock key and
// facade (the lock checks the facade's signature on it, not the hub).
func (Codec) SignRequest(k ed25519.PrivateKey, q hub.Request) ([]byte, error) {
	r := &ticket.HubRequest{V: ticket.Version, ID: q.ID, Kind: ticket.RequestKind(q.Kind), Ticket: q.Ticket,
		Instance: q.Instance, KeyID: q.KeyID, Approver: ticket.Approver{ID: q.ApproverID, Display: q.ApproverDisplay},
		Facade: q.Facade, At: q.At.UTC().Truncate(time.Millisecond)}
	if q.Kind == hub.KindReveal {
		var rk ticket.RevealKey
		dec := json.NewDecoder(bytes.NewReader(q.RevealKey))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rk); err != nil {
			return nil, fmt.Errorf("reveal key: %v", err)
		}
		if rk.Ticket != q.Ticket || rk.Instance != q.Instance || rk.KeyID != q.KeyID || rk.Facade != q.Facade {
			return nil, hub.ErrForeignKey
		}
		if age := q.At.Sub(rk.At); age >= ticket.RevealTTL || age < -time.Minute {
			return nil, fmt.Errorf("reveal key: made %s ago", age.Round(time.Second))
		}
		r.Reveal = &rk
	} else if len(q.RevealKey) > 0 {
		return nil, fmt.Errorf("a %s request carries no reveal key", q.Kind)
	}
	if err := r.Sign(k); err != nil {
		return nil, err
	}
	return r.Marshal()
}

// SignDecision builds and signs the decision on t. A device's decision
// (v.Device) is signed only once its assertion verifies, as a lock will
// check it: over the decision and the lock's signed ticket t.Raw.
func (Codec) SignDecision(k ed25519.PrivateKey, t hub.Info, v hub.Verdict, at time.Time) ([]byte, error) {
	out := ticket.Denied
	if v.Approved {
		out = ticket.Approved
	}
	nonce := v.Nonce
	if nonce == "" {
		nonce = ticket.NewNonce()
	}
	d := &ticket.Decision{
		V: ticket.Version, Ticket: t.ID, Instance: t.Instance, KeyID: t.KeyID, PlanHash: t.PlanHash,
		Decision: out, Reason: v.Reason,
		Approver: ticket.Approver{ID: v.ApproverID, Display: v.ApproverDisplay},
		Facade:   v.Facade, At: at.UTC().Truncate(time.Millisecond), Nonce: nonce,
		HubKeyID: ticket.KeyID(k.Public().(ed25519.PublicKey)),
	}
	switch {
	case t.V == ticket.VersionKinds:
		// A ticket that names its kind is answered with the deciding
		// rule: lox run's auto rule, or the human on the facade.
		d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleHuman}
		if v.Rule != "" {
			d.Rule = &ticket.Rule{By: ticket.RuleAuto, ID: v.Rule}
		}
	case v.Rule != "" || len(v.Secret) > 0:
		return nil, fmt.Errorf("a version %d decision names no rule and carries no secret", t.V)
	}
	if len(v.Secret) > 0 {
		var box ticket.Sealed
		if err := strictJSON(v.Secret, &box); err != nil {
			return nil, fmt.Errorf("secret: %v", err)
		}
		d.Secret = &box
	}
	if len(v.Device) > 0 {
		var a ticket.DeviceAssertion
		if err := strictJSON(v.Device, &a); err != nil {
			return nil, err
		}
		devs, err := ticket.ParseDevices(append(append([]byte(`{"devices":[`), v.DeviceRecord...), []byte(`],"v":1}`)...))
		if err != nil {
			return nil, err
		}
		d.Device = &a
		if err := ticket.VerifyDevice(&devs[0], d, t.Raw); err != nil {
			return nil, err
		}
	}
	if err := d.Sign(k); err != nil {
		return nil, err
	}
	return d.Marshal()
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
