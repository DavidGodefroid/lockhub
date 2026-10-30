// Package mobile is the mobile facade: an installable web app (PWA) the
// human opens on their phone, served by the hub on a listener of its own
// behind the human's TLS reverse proxy or tunnel.
//
// A phone becomes an approval device by pairing: `lock mobile pair` on the
// host asks for a one-time code, the phone enters it and registers a
// WebAuthn credential and an X25519 sealing key, and the human confirms at
// the host's terminal that both screens show the same fingerprint. Each
// decision taken on the phone is a WebAuthn assertion, with user
// verification, over the decision and the hash of the lock's signed
// ticket (lockkit ticket.DeviceStatement): the hub checks it before
// signing its own decision, and locks check it again against the device
// they pin. The phone opens the clear screen sealed to it by the lock; the
// hub only relays ciphertext.
//
// The listener serves the web app and /m/v1 only: never the lock API, never
// the facade API. Pairing and revocation happen on the facade socket.
package mobile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

//go:embed static
var static embed.FS

var b64 = base64.RawURLEncoding

// Limits and lifetimes.
const (
	PairingTTL      = 5 * time.Minute
	PairingAttempts = 5 // wrong codes before every open pairing is cancelled
	maxPairings     = 4
	ChallengeTTL    = 2 * time.Minute
	maxChallenges   = 32
	SessionTTL      = 12 * time.Hour
	maxSessions     = 32
	DraftTTL        = 2 * time.Minute
	maxDrafts       = 64
	MaxWait         = 30 * time.Second
	maxBody         = 64 << 10
	// CookieName is the session cookie (__Host-: Secure, Path=/, no Domain).
	CookieName = "__Host-lockhub"
	// CSRFHeader must be on every POST (with the configured Origin).
	CSRFHeader = "X-Lockhub"
)

// Config configures the facade.
type Config struct {
	Hub *hub.Hub
	// Origin is the https origin the phone reaches the hub at, through
	// the human's reverse proxy or tunnel ("https://hub.example.net"). Its
	// host is the WebAuthn relying party id.
	Origin string
	// HubKeyID is the KeyID of the hub's signing key (part of what a
	// device signs).
	HubKeyID string
	Now      func() time.Time
	Log      io.Writer
}

// Service is the mobile facade. Safe for concurrent use.
type Service struct {
	c    Config
	rpID string
	wa   *webauthn.WebAuthn

	mu         sync.Mutex
	pairings   map[string]*pairing // by id
	failed     int                 // wrong pairing codes since the last success
	challenges map[string]challenge
	sessions   map[[32]byte]session
	drafts     map[string]*draft
}

type pairingState string

const (
	waiting    pairingState = "waiting"    // code shown, phone not yet registered
	registered pairingState = "registered" // phone registered, the host human must confirm
	confirmed  pairingState = "confirmed"
	refused    pairingState = "refused"
	expired    pairingState = "expired"
)

type pairing struct {
	id, code, name string
	expires        time.Time
	state          pairingState
	session        *webauthn.SessionData
	user           *user
	device         *ticket.Device
	record         []byte
	fingerprint    string
	signCount      uint32
	changed        chan struct{} // closed and replaced on every change
}

type challenge struct {
	raw     []byte
	expires time.Time
}

type session struct {
	device  string
	expires time.Time
}

type draft struct {
	device    string
	ref       store.Ref
	statement ticket.DeviceStatement
	challenge []byte
	approve   bool
	expires   time.Time
}

// user is the one WebAuthn user of a hub: the human of this host.
type user struct {
	id   []byte
	name string
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return u.name }
func (u *user) WebAuthnDisplayName() string                { return u.name }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return nil }

// New checks c and returns the facade.
func New(c Config) (*Service, error) {
	if c.Hub == nil {
		return nil, errors.New("mobile: no hub")
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.String() != c.Origin || strings.ToLower(c.Origin) != c.Origin ||
		u.Path != "" || u.RawQuery != "" || u.User != nil || u.Port() == "443" {
		return nil, fmt.Errorf("mobile: origin %q: want an https origin as a browser writes it (https://host[:port], lowercase, no path)", c.Origin)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	rpID := u.Hostname()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: rpID, RPDisplayName: "lockhub", RPOrigins: []string{c.Origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mobile: %w", err)
	}
	return &Service{c: c, rpID: rpID, wa: wa, pairings: map[string]*pairing{}, challenges: map[string]challenge{},
		sessions: map[[32]byte]session{}, drafts: map[string]*draft{}}, nil
}

// RPID is the relying party id (the origin's host).
func (s *Service) RPID() string { return s.rpID }

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b)
}

// codeAlphabet has no 0/O, 1/I/L: a code is read off a terminal and typed.
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func newCode() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = codeAlphabet[int(c)%len(codeAlphabet)]
	}
	return string(out)
}

// sweep drops what expired. Locked.
func (s *Service) sweep(now time.Time) {
	for id, p := range s.pairings {
		if now.After(p.expires) && p.state != confirmed {
			p.state = expired
			s.changed(p)
			delete(s.pairings, id)
		}
	}
	for id, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, id)
		}
	}
	for k, se := range s.sessions {
		if now.After(se.expires) {
			delete(s.sessions, k)
		}
	}
	for id, d := range s.drafts {
		if now.After(d.expires) {
			delete(s.drafts, id)
		}
	}
}

// changed wakes whoever waits on p. Locked.
func (s *Service) changed(p *pairing) {
	close(p.changed)
	p.changed = make(chan struct{})
}

// --- HTTP helpers -----------------------------------------------------

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, apiError{Error: kind, Message: msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// securityHeaders apply to every answer of the mobile listener.
func securityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "+
		"manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

// --- the mobile listener ----------------------------------------------

// Handler serves the web app and the /m/v1 API on the mobile listener.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	files := http.FileServerFS(sub)
	for _, f := range []string{"/", "/app.js", "/style.css", "/sw.js", "/manifest.webmanifest", "/icon.svg"} {
		mux.Handle("GET "+f, files)
	}
	mux.HandleFunc("POST /m/v1/pair/begin", s.post(s.pairBegin))
	mux.HandleFunc("POST /m/v1/pair/finish", s.post(s.pairFinish))
	mux.HandleFunc("POST /m/v1/login/begin", s.post(s.loginBegin))
	mux.HandleFunc("POST /m/v1/login/finish", s.post(s.loginFinish))
	mux.HandleFunc("POST /m/v1/logout", s.post(s.authed(s.logout)))
	mux.HandleFunc("GET /m/v1/queue", s.authed(s.queue))
	mux.HandleFunc("POST /m/v1/tickets/{instance}/{id}/prepare", s.post(s.authed(s.prepare)))
	mux.HandleFunc("POST /m/v1/tickets/{instance}/{id}/decide", s.post(s.authed(s.decide)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w.Header())
		mux.ServeHTTP(w, r)
	})
}

// post refuses a POST that did not come from the web app itself: the
// configured Origin and the custom header (no form or cross-site fetch
// can send both), a JSON body.
func (s *Service) post(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != s.c.Origin || r.Header.Get(CSRFHeader) != "1" ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeErr(w, http.StatusForbidden, "origin", "requests come from the lockhub web app only")
			return
		}
		next(w, r)
	}
}

type ctxKey struct{}

// authed requires a session; the device id is in the context.
func (s *Service) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "login", "sign in with your device")
			return
		}
		k := sha256.Sum256([]byte(c.Value))
		now := s.c.Now()
		s.mu.Lock()
		s.sweep(now)
		se, ok := s.sessions[k]
		s.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusUnauthorized, "login", "sign in with your device")
			return
		}
		d, err := s.c.Hub.Device(r.Context(), se.device)
		if err != nil || d.State != store.DeviceActive {
			s.mu.Lock()
			delete(s.sessions, k)
			s.mu.Unlock()
			writeErr(w, http.StatusUnauthorized, "login", "this device is no longer active")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, se.device)))
	}
}

func deviceOf(r *http.Request) string { v, _ := r.Context().Value(ctxKey{}).(string); return v }

// --- pairing, phone side ----------------------------------------------

// PairBegin is POST /m/v1/pair/begin.
type PairBegin struct {
	Code string `json:"code"`
}

// PairBeginResult carries the WebAuthn creation options.
type PairBeginResult struct {
	Pairing string                                      `json:"pairing"`
	Name    string                                      `json:"name"`
	Options protocol.PublicKeyCredentialCreationOptions `json:"options"`
}

func (s *Service) pairBegin(w http.ResponseWriter, r *http.Request) {
	var req PairBegin
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a pairing request")
		return
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(req.Code), " ", ""))
	now := s.c.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	var p *pairing
	for _, q := range s.pairings {
		if q.state == waiting && q.session == nil && subtle.ConstantTimeCompare([]byte(q.code), []byte(code)) == 1 {
			p = q
		}
	}
	if p == nil {
		s.failed++
		if s.failed >= PairingAttempts {
			// Too many wrong codes: every open pairing ends; the human
			// starts again at the terminal.
			for id, q := range s.pairings {
				if q.state != confirmed {
					q.state = refused
					s.changed(q)
					delete(s.pairings, id)
				}
			}
			s.failed = 0
		}
		writeErr(w, http.StatusForbidden, "code", "wrong or expired pairing code")
		return
	}
	s.failed = 0
	u := &user{id: []byte(randomID(16)), name: "lockhub " + p.name}
	creation, sd, err := s.wa.BeginRegistration(u,
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "cannot start the registration")
		return
	}
	p.session, p.user = sd, u
	writeJSON(w, http.StatusOK, PairBeginResult{Pairing: p.id, Name: p.name, Options: creation.Response})
}

// PairFinish is POST /m/v1/pair/finish: the browser's registration
// response and the device's X25519 public key.
type PairFinish struct {
	Pairing    string          `json:"pairing"`
	Credential json.RawMessage `json:"credential"`
	X25519     string          `json:"x25519"`
}

// PairFinishResult is the device record and its fingerprint, which the
// human compares with the terminal's.
type PairFinishResult struct {
	Device      ticket.Device `json:"device"`
	Fingerprint string        `json:"fingerprint"`
}

func (s *Service) pairFinish(w http.ResponseWriter, r *http.Request) {
	var req PairFinish
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a registration")
		return
	}
	now := s.c.Now()
	s.mu.Lock()
	s.sweep(now)
	p := s.pairings[req.Pairing]
	if p == nil || p.state != waiting || p.session == nil {
		s.mu.Unlock()
		writeErr(w, http.StatusForbidden, "pairing", "no such pairing waiting")
		return
	}
	sd, u := *p.session, p.user
	p.session = nil // one registration per code
	s.mu.Unlock()

	fail := func(msg string) {
		s.mu.Lock()
		if p.state == waiting {
			p.state = refused
			s.changed(p)
			delete(s.pairings, p.id)
		}
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, "registration", msg)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		fail("the registration does not parse")
		return
	}
	cred, err := s.wa.CreateCredential(u, sd, parsed)
	if err != nil {
		fail("the registration does not verify")
		return
	}
	if !cred.Flags.UserPresent || !cred.Flags.UserVerified {
		fail("the authenticator did not verify the user")
		return
	}
	pub, err := es256Point(cred.PublicKey)
	if err != nil {
		fail(err.Error())
		return
	}
	dev := ticket.Device{V: ticket.Version, ID: ticket.DeviceID(cred.ID), Credential: b64.EncodeToString(cred.ID), Name: p.name,
		RPID: s.rpID, Origin: s.c.Origin, ES256: b64.EncodeToString(pub), X25519: req.X25519}
	if err := dev.Validate(); err != nil {
		fail("the device record is not valid")
		return
	}
	rec, err := ticket.Canonical(&dev)
	if err != nil {
		fail("the device record is not valid")
		return
	}
	fp, _ := dev.Fingerprint()
	s.mu.Lock()
	if p.state != waiting {
		s.mu.Unlock()
		writeErr(w, http.StatusForbidden, "pairing", "the pairing ended")
		return
	}
	p.state, p.device, p.record, p.fingerprint, p.signCount = registered, &dev, rec, fp, cred.Authenticator.SignCount
	s.changed(p)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, PairFinishResult{Device: dev, Fingerprint: fp})
}

// es256Point is the uncompressed P-256 point of a COSE ES256 key.
func es256Point(cose []byte) ([]byte, error) {
	k, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return nil, errors.New("the credential key does not parse")
	}
	ec, ok := k.(webauthncose.EC2PublicKeyData)
	if !ok || ec.Algorithm != int64(webauthncose.AlgES256) || ec.Curve != int64(webauthncose.P256) || len(ec.XCoord) > 32 || len(ec.YCoord) > 32 {
		return nil, errors.New("the credential is not an ES256 P-256 key")
	}
	out := make([]byte, 65)
	out[0] = 4
	copy(out[33-len(ec.XCoord):33], ec.XCoord)
	copy(out[65-len(ec.YCoord):], ec.YCoord)
	return out, nil
}

// --- login --------------------------------------------------------------

// LoginBeginResult is a challenge for a login assertion.
type LoginBeginResult struct {
	ID        string   `json:"id"`
	Challenge string   `json:"challenge"`
	RPID      string   `json:"rp_id"`
	Allow     []string `json:"allow"` // credential ids of active devices
}

// loginContext separates login challenges from decision challenges.
const loginContext = "lockhub/mobile-login/v1\x00"

func (s *Service) loginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is {}")
		return
	}
	devs, err := s.c.Hub.Store().Devices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "cannot list devices")
		return
	}
	res := LoginBeginResult{ID: randomID(16), RPID: s.rpID, Allow: []string{}}
	for _, d := range devs {
		if d.State != store.DeviceActive {
			continue
		}
		var dev ticket.Device
		if json.Unmarshal(d.Record, &dev) == nil {
			res.Allow = append(res.Allow, dev.Credential)
		}
	}
	if len(res.Allow) == 0 {
		writeErr(w, http.StatusForbidden, "no_device", "no device is paired: run lock mobile pair on the host")
		return
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ch := sha256.Sum256(append([]byte(loginContext), nonce...))
	now := s.c.Now()
	s.mu.Lock()
	s.sweep(now)
	if len(s.challenges) >= maxChallenges {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "busy", "too many sign-ins in progress")
		return
	}
	s.challenges[res.ID] = challenge{raw: ch[:], expires: now.Add(ChallengeTTL)}
	s.mu.Unlock()
	res.Challenge = b64.EncodeToString(ch[:])
	writeJSON(w, http.StatusOK, res)
}

// Assertion is a WebAuthn assertion as the web app sends it.
type Assertion struct {
	Device     string `json:"device"`
	AuthData   string `json:"auth_data"`
	ClientData string `json:"client_data"`
	Sig        string `json:"sig"`
}

func (a Assertion) lockkit() *ticket.DeviceAssertion {
	return &ticket.DeviceAssertion{Device: a.Device, AuthData: a.AuthData, ClientData: a.ClientData, Sig: a.Sig}
}

// LoginFinish is POST /m/v1/login/finish.
type LoginFinish struct {
	ID        string    `json:"id"`
	Assertion Assertion `json:"assertion"`
}

// activeDevice is the record of an active device.
func (s *Service) activeDevice(ctx context.Context, id string) (*ticket.Device, []byte, error) {
	d, err := s.c.Hub.Device(ctx, id)
	if err != nil || d.State != store.DeviceActive {
		return nil, nil, errors.New("no such active device")
	}
	devs, err := ticket.ParseDevices([]byte(`{"devices":[` + string(d.Record) + `],"v":1}`))
	if err != nil {
		return nil, nil, err
	}
	return &devs[0], d.Record, nil
}

// verify checks an assertion of an active device over challenge and
// records its counter.
func (s *Service) verify(ctx context.Context, ch []byte, a Assertion) (*ticket.Device, []byte, error) {
	dev, rec, err := s.activeDevice(ctx, a.Device)
	if err != nil {
		return nil, nil, err
	}
	n, err := ticket.VerifyAssertion(dev, ch, a.lockkit())
	if err != nil {
		return nil, nil, err
	}
	if err := s.c.Hub.UseCounter(ctx, dev.ID, n); err != nil {
		return nil, nil, err
	}
	return dev, rec, nil
}

func (s *Service) loginFinish(w http.ResponseWriter, r *http.Request) {
	var req LoginFinish
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a sign-in")
		return
	}
	now := s.c.Now()
	s.mu.Lock()
	s.sweep(now)
	c, ok := s.challenges[req.ID]
	delete(s.challenges, req.ID) // single use
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusForbidden, "challenge", "no such sign-in in progress")
		return
	}
	dev, _, err := s.verify(r.Context(), c.raw, req.Assertion)
	if err != nil {
		writeErr(w, http.StatusForbidden, "assertion", "the sign-in does not verify")
		return
	}
	tok := randomID(32)
	k := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	if len(s.sessions) >= maxSessions {
		// Drop the oldest: a new sign-in always works.
		var oldest [32]byte
		var at time.Time
		for kk, se := range s.sessions {
			if at.IsZero() || se.expires.Before(at) {
				oldest, at = kk, se.expires
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[k] = session{device: dev.ID, expires: now.Add(SessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: tok, Path: "/", MaxAge: int(SessionTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{"device": dev.ID, "name": dev.Name})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		k := sha256.Sum256([]byte(c.Value))
		s.mu.Lock()
		delete(s.sessions, k)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- queue and decisions ----------------------------------------------

// Item is a pending ticket as the phone sees it. Ticket is the lock's
// signed ticket, byte for byte as the lock sent it (the device hashes it
// into what it signs): its screen is masked, its clear screen sealed.
type Item struct {
	ID         string     `json:"id"`
	Instance   string     `json:"instance"`
	Risk       string     `json:"risk"`
	Created    time.Time  `json:"created"`
	Expires    *time.Time `json:"expires,omitempty"`
	Answerable bool       `json:"answerable"`
	Why        string     `json:"why,omitempty"`
	Retype     bool       `json:"retype"`
	Ticket     string     `json:"ticket"`
}

// QueueResult answers GET /m/v1/queue.
type QueueResult struct {
	Tickets []Item `json:"tickets"`
	Version uint64 `json:"version"`
}

// visible reports whether the mobile facade shows an instance's tickets
// at all (routing narrowed it away: not shown).
func visible(rules route.Rules, inst string) bool {
	if len(rules.Enabled) > 0 && !contains(rules.Enabled, route.Mobile) {
		return false
	}
	if only, ok := rules.Only[inst]; ok && !contains(only, route.Mobile) {
		return false
	}
	return true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (s *Service) queue(w http.ResponseWriter, r *http.Request) {
	var since uint64
	var wait time.Duration
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "since is a queue version")
			return
		}
		since = n
	}
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "bad_request", "wait is a number of seconds")
			return
		}
		wait = min(time.Duration(n)*time.Second, MaxWait)
	}
	tks, ver, err := s.c.Hub.Queue(r.Context(), since, wait)
	if err != nil {
		if r.Context().Err() == nil {
			writeErr(w, http.StatusInternalServerError, "internal", "queue unavailable")
		}
		return
	}
	rules := s.c.Hub.Routes()
	res := QueueResult{Tickets: []Item{}, Version: ver}
	for _, t := range tks {
		if !visible(rules, t.Instance) {
			continue
		}
		it := Item{ID: t.ID, Instance: t.Instance, Risk: t.Risk, Created: t.Created, Ticket: string(t.Raw)}
		if !t.Expires.IsZero() {
			e := t.Expires
			it.Expires = &e
		}
		var tk ticket.Ticket
		if err := json.Unmarshal(t.Raw, &tk); err == nil {
			it.Retype = tk.Flags.Production && tk.Flags.Retype != ""
		}
		if err := rules.Allowed(t.Instance, route.Mobile, t.Risk); err != nil {
			it.Why = err.Error()
		} else {
			it.Answerable = true
		}
		res.Tickets = append(res.Tickets, it)
	}
	writeJSON(w, http.StatusOK, res)
}

// Prepare is POST /m/v1/tickets/{instance}/{id}/prepare: the human's
// answer, before the device signs it.
type Prepare struct {
	Approve bool   `json:"approve"`
	Reason  string `json:"reason"`
}

// PrepareResult is the statement the device signs (lockkit
// ticket.DeviceStatement): the web app checks it against the ticket it
// shows and computes the challenge itself.
type PrepareResult struct {
	Draft     string                 `json:"draft"`
	Statement ticket.DeviceStatement `json:"statement"`
	Challenge string                 `json:"challenge"`
}

func (s *Service) prepare(w http.ResponseWriter, r *http.Request) {
	var req Prepare
	if err := readJSON(r, &req); err != nil || len(req.Reason) > hub.MaxReason {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not an answer")
		return
	}
	ref := store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")}
	devID := deviceOf(r)
	dev, _, err := s.activeDevice(r.Context(), devID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "login", "this device is no longer active")
		return
	}
	var tk store.Ticket
	err = s.c.Hub.Store().Tx(r.Context(), func(tx *store.Tx) error {
		var err error
		tk, err = tx.Ticket(ref)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no such ticket")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal", "ticket unavailable")
		return
	case tk.State != state.Pending:
		writeErr(w, http.StatusConflict, "decided", "this ticket is no longer pending")
		return
	case !visible(s.c.Hub.Routes(), tk.Instance) || s.c.Hub.Routes().Allowed(tk.Instance, route.Mobile, tk.Risk) != nil:
		writeErr(w, http.StatusForbidden, "not_routed", "this ticket is not answered on mobile")
		return
	}
	var t ticket.Ticket
	if err := json.Unmarshal(tk.Raw, &t); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "ticket unreadable")
		return
	}
	out := ticket.Denied
	if req.Approve {
		out = ticket.Approved
	}
	st := ticket.DeviceStatement{V: ticket.Version, Ticket: t.ID, Instance: t.Source.Instance, KeyID: t.Source.KeyID,
		PlanHash: t.PlanHash, Decision: out, Reason: req.Reason, Approver: dev.ID, Display: dev.Name,
		Facade: ticket.FacadeMobile, At: s.c.Now().UTC().Truncate(time.Millisecond), Nonce: ticket.NewNonce(),
		HubKeyID: s.c.HubKeyID, Device: dev.ID, TicketHash: ticket.TicketHash(tk.Raw)}
	ch, err := st.Challenge()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "cannot build the statement")
		return
	}
	id := randomID(16)
	now := s.c.Now()
	s.mu.Lock()
	s.sweep(now)
	if len(s.drafts) >= maxDrafts {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "busy", "too many answers in progress")
		return
	}
	s.drafts[id] = &draft{device: dev.ID, ref: ref, statement: st, challenge: ch, approve: req.Approve, expires: now.Add(DraftTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, PrepareResult{Draft: id, Statement: st, Challenge: b64.EncodeToString(ch)})
}

// Decide is POST /m/v1/tickets/{instance}/{id}/decide: the device's
// assertion over a prepared statement.
type Decide struct {
	Draft     string    `json:"draft"`
	Retype    string    `json:"retype,omitempty"`
	Assertion Assertion `json:"assertion"`
}

func (s *Service) decide(w http.ResponseWriter, r *http.Request) {
	var req Decide
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a decision")
		return
	}
	ref := store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")}
	devID := deviceOf(r)
	now := s.c.Now()
	s.mu.Lock()
	s.sweep(now)
	d := s.drafts[req.Draft]
	delete(s.drafts, req.Draft) // single use, whatever happens next
	s.mu.Unlock()
	if d == nil || d.device != devID || d.ref != ref || req.Assertion.Device != devID {
		writeErr(w, http.StatusForbidden, "draft", "no such answer in progress for this device and ticket")
		return
	}
	dev, rec, err := s.verify(r.Context(), d.challenge, req.Assertion)
	if err != nil {
		writeErr(w, http.StatusForbidden, "assertion", "the device's signature does not verify")
		return
	}
	a, _ := json.Marshal(req.Assertion.lockkit())
	st := d.statement
	_, err = s.c.Hub.Decide(r.Context(), ref, hub.Verdict{
		Approved: d.approve, Reason: st.Reason, Retype: req.Retype,
		ApproverID: dev.ID, ApproverDisplay: dev.Name, Facade: route.Mobile,
		Nonce: st.Nonce, At: st.At, Device: a, DeviceID: dev.ID, DeviceRecord: rec,
	})
	switch {
	case errors.Is(err, hub.ErrRetype):
		writeErr(w, http.StatusUnprocessableEntity, "retype", err.Error())
	case errors.Is(err, hub.ErrNotRouted):
		writeErr(w, http.StatusForbidden, "not_routed", err.Error())
	case errors.Is(err, hub.ErrDevice):
		writeErr(w, http.StatusForbidden, "device", "the hub refused the device's decision")
	case errors.Is(err, hub.ErrExpired):
		writeErr(w, http.StatusGone, "expired", "the ticket expired")
	case err != nil:
		writeErr(w, http.StatusConflict, "decided", "the decision was not recorded (already decided?)")
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// --- pairing and devices, host side (facade socket) -------------------

// FacadeRoutes adds the host-side routes to the facade socket's mux:
// pairing (lock mobile pair), listing and revoking devices.
func (s *Service) FacadeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/mobile/pairings", s.host(s.pairStart))
	mux.HandleFunc("GET /v1/mobile/pairings/{id}", s.host(s.pairState))
	mux.HandleFunc("POST /v1/mobile/pairings/{id}/confirm", s.host(s.pairConfirm))
	mux.HandleFunc("GET /v1/mobile/devices", s.host(s.devices))
	mux.HandleFunc("POST /v1/mobile/devices/{id}/revoke", s.host(s.revoke))
}

// host requires a facade-socket peer the kernel identified.
func (s *Service) host(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := peer.From(r.Context())
		if !p.Known {
			writeErr(w, http.StatusForbidden, "unknown_peer", "the facade socket cannot identify this connection's user")
			return
		}
		next(w, r, fmt.Sprintf("host:uid:%d", p.UID))
	}
}

// PairStart is POST /v1/mobile/pairings.
type PairStart struct {
	Name string `json:"name"`
}

// PairStartResult is what the terminal shows.
type PairStartResult struct {
	ID      string    `json:"id"`
	Code    string    `json:"code"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

func validName(n string) bool {
	if n == "" || len(n) > 32 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (s *Service) pairStart(w http.ResponseWriter, r *http.Request, _ string) {
	var req PairStart
	if err := readJSON(r, &req); err != nil || !validName(req.Name) {
		writeErr(w, http.StatusBadRequest, "bad_request", "name: 1 to 32 of a-z, 0-9, -")
		return
	}
	now := s.c.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	open := 0
	for _, p := range s.pairings {
		if p.state == waiting || p.state == registered {
			open++
		}
	}
	if open >= maxPairings {
		writeErr(w, http.StatusTooManyRequests, "busy", "too many pairings open")
		return
	}
	p := &pairing{id: randomID(16), code: newCode(), name: req.Name, expires: now.Add(PairingTTL), state: waiting, changed: make(chan struct{})}
	s.pairings[p.id] = p
	writeJSON(w, http.StatusOK, PairStartResult{ID: p.id, Code: p.code, URL: s.c.Origin + "/#pair", Expires: p.expires})
}

// PairStateResult is a pairing's state, with the registered device.
type PairStateResult struct {
	State       string         `json:"state"`
	Device      *ticket.Device `json:"device,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
}

func (s *Service) pairState(w http.ResponseWriter, r *http.Request, _ string) {
	wait := time.Duration(0)
	if v := r.URL.Query().Get("wait"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			wait = min(time.Duration(n)*time.Second, MaxWait)
		}
	}
	id := r.PathValue("id")
	s.mu.Lock()
	s.sweep(s.c.Now())
	p := s.pairings[id]
	if p == nil {
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, PairStateResult{State: string(expired)})
		return
	}
	if p.state == waiting && wait > 0 {
		ch := p.changed
		s.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ch:
		case <-t.C:
		case <-r.Context().Done():
		}
		t.Stop()
		s.mu.Lock()
	}
	res := PairStateResult{State: string(p.state)}
	if p.state == registered {
		res.Device, res.Fingerprint = p.device, p.fingerprint
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, res)
}

// PairConfirm is the human's answer at the terminal: the fingerprint the
// terminal showed (it must be the one registered), confirmed or not.
type PairConfirm struct {
	Confirm     bool   `json:"confirm"`
	Fingerprint string `json:"fingerprint"`
}

// PairConfirmResult is the confirmed device's record (canonical JSON).
type PairConfirmResult struct {
	Record json.RawMessage `json:"record"`
}

func (s *Service) pairConfirm(w http.ResponseWriter, r *http.Request, approver string) {
	var req PairConfirm
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a confirmation")
		return
	}
	s.mu.Lock()
	s.sweep(s.c.Now())
	p := s.pairings[r.PathValue("id")]
	if p == nil || p.state != registered {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "pairing", "no registered device waits for this pairing")
		return
	}
	if !req.Confirm || req.Fingerprint != p.fingerprint {
		p.state = refused
		s.changed(p)
		delete(s.pairings, p.id)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, PairStateResult{State: string(refused)})
		return
	}
	dev, rec, fp, n := p.device, p.record, p.fingerprint, p.signCount
	p.state = confirmed
	s.changed(p)
	delete(s.pairings, p.id)
	s.mu.Unlock()
	if err := s.c.Hub.AddDevice(r.Context(), dev.ID, rec, fp, approver, n); err != nil {
		writeErr(w, http.StatusConflict, "device", "the device could not be recorded: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, PairConfirmResult{Record: rec})
}

// DeviceInfo lists a device on the facade socket.
type DeviceInfo struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	State       string          `json:"state"`
	Fingerprint string          `json:"fingerprint"`
	Created     time.Time       `json:"created"`
	Record      json.RawMessage `json:"record"`
}

func (s *Service) devices(w http.ResponseWriter, r *http.Request, _ string) {
	ds, err := s.c.Hub.Store().Devices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "cannot list devices")
		return
	}
	out := []DeviceInfo{}
	for _, d := range ds {
		var dev ticket.Device
		json.Unmarshal(d.Record, &dev)
		fp, _ := dev.Fingerprint()
		out = append(out, DeviceInfo{ID: d.ID, Name: dev.Name, State: d.State, Fingerprint: fp, Created: d.Created, Record: d.Record})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request, approver string) {
	id := r.PathValue("id")
	if err := s.c.Hub.RevokeDevice(r.Context(), id, approver); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such device")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "cannot revoke")
		return
	}
	s.mu.Lock()
	for k, se := range s.sessions {
		if se.device == id {
			delete(s.sessions, k)
		}
	}
	for k, d := range s.drafts {
		if d.device == id {
			delete(s.drafts, k)
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Fingerprint of a canonical record, for callers holding bytes.
func Fingerprint(record []byte) (string, error) {
	devs, err := ticket.ParseDevices([]byte(`{"devices":[` + string(record) + `],"v":1}`))
	if err != nil {
		return "", err
	}
	return devs[0].Fingerprint()
}
