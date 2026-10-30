// Package mobiletest is a phone for tests: a virtual WebAuthn
// authenticator (lockkit devicetest) driving the mobile facade's API as
// the web app does, with the same checks before it signs.
package mobiletest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"

	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
)

var b64 = base64.RawURLEncoding

// Phone is one device talking to a mobile facade at Base (an
// httptest TLS server: the session cookie is Secure).
type Phone struct {
	Auth   *devicetest.Authenticator
	Base   string
	Origin string
	HTTP   *http.Client
	// Seen records every answer body the phone received (PII capture).
	Seen [][]byte
}

// New is a phone for the facade at base (client: the TLS server's), for
// origin (the configured one).
func New(base, origin, rpID, name string, client *http.Client) *Phone {
	jar, _ := cookiejar.New(nil)
	c := *client
	c.Jar = jar
	return &Phone{Auth: devicetest.New(rpID, origin, name), Base: base, Origin: origin, HTTP: &c}
}

// Error is an error answer of the facade.
type Error struct {
	Status int
	Kind   string
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Kind, e.Msg) }

// Do sends a request as the web app does and decodes the answer.
func (p *Phone) Do(method, path string, in, out any) error {
	var body io.Reader
	if method == http.MethodPost {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, p.Base+path, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", p.Origin)
		req.Header.Set(mobile.CSRFHeader, "1")
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	p.Seen = append(p.Seen, b)
	if resp.StatusCode/100 != 2 {
		var e struct{ Error, Message string }
		json.Unmarshal(b, &e)
		return &Error{resp.StatusCode, e.Error, e.Message}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// --- minimal CBOR, for the attestation object --------------------------

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
}

func cborInt(i int64) []byte {
	if i >= 0 {
		return cborHead(0, uint64(i))
	}
	return cborHead(1, uint64(-1-i))
}
func cborBytes(b []byte) []byte  { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte   { return append(cborHead(3, uint64(len(s))), s...) }
func cborMap(n int) []byte       { return cborHead(5, uint64(n)) }
func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// coseKey is the credential's ES256 key as COSE.
func (p *Phone) coseKey() []byte {
	pt := p.Auth.PublicKey()
	return cat(cborMap(5), cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1),
		cborInt(-2), cborBytes(pt[1:33]), cborInt(-3), cborBytes(pt[33:]))
}

// Registration builds the browser's answer to options, as a
// navigator.credentials.create() serialized by the web app.
func (p *Phone) Registration(o map[string]any, flags byte, origin string) json.RawMessage {
	ch, _ := o["challenge"].(string)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": ch, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(p.Auth.RPID))
	ad := cat(rp[:], []byte{flags}, []byte{0, 0, 0, 0}, make([]byte, 16),
		binary.BigEndian.AppendUint16(nil, uint16(len(p.Auth.Cred))), p.Auth.Cred, p.coseKey())
	att := cat(cborMap(3), cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(0), cborText("authData"), cborBytes(ad))
	id := b64.EncodeToString(p.Auth.Cred)
	b, _ := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key",
		"response":               map[string]string{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att)},
		"clientExtensionResults": map[string]any{}})
	return b
}

// Pair registers the phone with code and returns the fingerprint it
// computed itself (it must match the hub's).
func (p *Phone) Pair(code string) (string, error) {
	var begin struct {
		Pairing string         `json:"pairing"`
		Name    string         `json:"name"`
		Options map[string]any `json:"options"`
	}
	if err := p.Do(http.MethodPost, "/m/v1/pair/begin", mobile.PairBegin{Code: code}, &begin); err != nil {
		return "", err
	}
	p.Auth.Name = begin.Name
	cred := p.Registration(begin.Options, 0x45, p.Origin)
	var fin mobile.PairFinishResult
	x := b64.EncodeToString(p.Auth.Seal.PublicKey().Bytes())
	if err := p.Do(http.MethodPost, "/m/v1/pair/finish", mobile.PairFinish{Pairing: begin.Pairing, Credential: cred, X25519: x}, &fin); err != nil {
		return "", err
	}
	dev := p.Auth.Device()
	fp, _ := dev.Fingerprint()
	if fp != fin.Fingerprint {
		return "", errors.New("the hub registered another device record")
	}
	return fp, nil
}

// Login signs in.
func (p *Phone) Login() error {
	var b mobile.LoginBeginResult
	if err := p.Do(http.MethodPost, "/m/v1/login/begin", struct{}{}, &b); err != nil {
		return err
	}
	nonce, err := b64.DecodeString(b.Nonce)
	if err != nil {
		return err
	}
	// The phone computes the challenge itself (never one the hub chose).
	a := p.Auth.Assert(mobile.LoginChallenge(nonce))
	return p.Do(http.MethodPost, "/m/v1/login/finish", mobile.LoginFinish{ID: b.ID,
		Assertion: mobile.Assertion{Device: a.Device, AuthData: a.AuthData, ClientData: a.ClientData, Sig: a.Sig}}, nil)
}

// Queue reads the queue once.
func (p *Phone) Queue() (mobile.QueueResult, error) {
	var q mobile.QueueResult
	err := p.Do(http.MethodGet, "/m/v1/queue?since=0", nil, &q)
	return q, err
}

// Clear opens the clear screen of it sealed to this phone.
func (p *Phone) Clear(it mobile.Item) (ticket.Screen, error) {
	var t ticket.Ticket
	if err := json.Unmarshal([]byte(it.Ticket), &t); err != nil {
		return ticket.Screen{}, err
	}
	id := ticket.DeviceID(p.Auth.Cred)
	for i := range t.PII.SealedFor {
		if t.PII.SealedFor[i].Device == id {
			return ticket.OpenClearScreen(p.Auth.Seal, t.ID, id, &t.PII.SealedFor[i])
		}
	}
	return ticket.Screen{}, errors.New("nothing sealed to this phone")
}

// Prepared is a statement the hub asks the phone to sign.
type Prepared struct {
	Draft     string
	Statement ticket.DeviceStatement
	Challenge []byte
}

// Prepare asks the hub for the statement of an answer.
func (p *Phone) Prepare(it mobile.Item, approve bool, reason string) (Prepared, error) {
	var r mobile.PrepareResult
	path := "/m/v1/tickets/" + url.PathEscape(it.Instance) + "/" + url.PathEscape(it.ID) + "/prepare"
	if err := p.Do(http.MethodPost, path, mobile.Prepare{Approve: approve, Reason: reason}, &r); err != nil {
		return Prepared{}, err
	}
	ch, _ := b64.DecodeString(r.Challenge)
	return Prepared{r.Draft, r.Statement, ch}, nil
}

// Check is the web app's check before it signs: the statement is the
// human's answer on the ticket shown; the challenge is computed here.
func (p *Phone) Check(it mobile.Item, st ticket.DeviceStatement, approve bool, reason string) ([]byte, error) {
	var t ticket.Ticket
	if err := json.Unmarshal([]byte(it.Ticket), &t); err != nil {
		return nil, err
	}
	out := ticket.Denied
	if approve {
		out = ticket.Approved
	}
	id := ticket.DeviceID(p.Auth.Cred)
	want := ticket.DeviceStatement{V: 1, Ticket: t.ID, Instance: t.Source.Instance, KeyID: t.Source.KeyID, PlanHash: t.PlanHash,
		Decision: out, Reason: reason, Approver: id, Display: p.Auth.Name, Facade: ticket.FacadeMobile, At: st.At,
		Nonce: st.Nonce, HubKeyID: st.HubKeyID, Device: id, TicketHash: ticket.TicketHash([]byte(it.Ticket))}
	if st != want {
		return nil, fmt.Errorf("the hub asked to sign %+v, not %+v", st, want)
	}
	if d := time.Since(st.At); d > 2*time.Minute || d < -2*time.Minute {
		return nil, errors.New("the hub's time is off")
	}
	return st.Challenge()
}

// Decide signs challenge and sends the decision.
func (p *Phone) Decide(it mobile.Item, draft string, challenge []byte, retype string) error {
	a := p.Auth.Assert(challenge)
	path := "/m/v1/tickets/" + url.PathEscape(it.Instance) + "/" + url.PathEscape(it.ID) + "/decide"
	return p.Do(http.MethodPost, path, mobile.Decide{Draft: draft, Retype: retype,
		Assertion: mobile.Assertion{Device: a.Device, AuthData: a.AuthData, ClientData: a.ClientData, Sig: a.Sig}}, nil)
}

// Answer is Prepare, Check and Decide.
func (p *Phone) Answer(it mobile.Item, approve bool, reason, retype string) error {
	pr, err := p.Prepare(it, approve, reason)
	if err != nil {
		return err
	}
	ch, err := p.Check(it, pr.Statement, approve, reason)
	if err != nil {
		return err
	}
	if !bytes.Equal(ch, pr.Challenge) {
		return errors.New("the hub's challenge differs")
	}
	return p.Decide(it, pr.Draft, ch, retype)
}
