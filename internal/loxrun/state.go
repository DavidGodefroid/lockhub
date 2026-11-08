package loxrun

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Prompt kinds of a card.
const (
	promptRetype = "retype"
	promptSecret = "secret"
)

// answer is how the human is answering a ticket (embedded in tracked).
type answer struct {
	promptKind string
	retyped    string
	lastReq    *api.DecideRequest // a decision to send again (the hub was unreachable)
	inFeed     bool
	// A connect ticket's approval waits for its result: only a consumed
	// ticket (the lock opened the connection) proves the secret typed
	// for it (secret, kept until then) and the human's approval of the
	// connection (human), which the session then reuses.
	secret []byte
	human  bool
	cached bool // approved with the session's secret for the profile
}

func clean(s string) string { return sanitize.Terminal(s, false) }

// maxAsked bounds the reason a decision carries to the hub's audit (the
// hub refuses more than its MaxReason).
const maxAsked = 512

// askedText is why, as the hub's audit keeps it: at most maxAsked bytes,
// cut on a rune.
func askedText(why string) string {
	if len(why) <= maxAsked {
		return why
	}
	cut := maxAsked
	for cut > 0 && !utf8.RuneStart(why[cut]) {
		cut--
	}
	return why[:cut]
}

// parseTicket reads a queue item's ticket: verified under the pinned
// lock key when there is one (verified true), only decoded otherwise.
// A ticket that does not verify under its pinned key is an error.
func parseTicket(it api.QueueItem, keys map[string]ed25519.PublicKey) (*ticket.Ticket, bool, error) {
	if k, ok := keys[it.Instance]; ok {
		tk, err := ticket.VerifyTicket(k, it.Ticket)
		if err != nil {
			return nil, false, fmt.Errorf("does not verify under the pinned lock key: %w", err)
		}
		if tk.Source.Instance != it.Instance || tk.ID != it.ID {
			return nil, false, errors.New("the hub lists it under another instance or id")
		}
		return tk, true, nil
	}
	var tk ticket.Ticket
	if err := json.Unmarshal(it.Ticket, &tk); err != nil {
		return nil, false, err
	}
	return &tk, false, nil
}

func local(facades []string) bool { return slices.Contains(facades, route.TTY) }

// summary is a ticket's request on one line, as the lock masked it.
func summary(tk *ticket.Ticket) string {
	if tk.Kind == ticket.KindConnect && tk.Subject != nil {
		return "connect " + clean(tk.Subject.Endpoint) + " (credentials: " + clean(tk.Subject.Credential) + ")"
	}
	if tk.Kind == ticket.KindEndpoint && tk.Subject != nil {
		return strings.TrimSpace(clean(tk.Subject.Verb) + " " + clean(tk.Subject.Endpoint) + clean(tk.Subject.Target))
	}
	for _, b := range tk.Screen.Body {
		if s := strings.TrimSpace(clean(b)); s != "" {
			return s
		}
	}
	return clean(tk.Screen.Header)
}

func (st *state) logf(format string, args ...any) {
	if st.s.Size == nil {
		fmt.Fprintf(st.s.Out, format+"\n", args...)
	}
}

func (st *state) printEntry(e *Entry) {
	if st.s.Size == nil {
		fmt.Fprintln(st.s.Out, FeedLine(*e, st.view(), 100, st.s.Style))
	}
}

func (st *state) wipe() {
	for k, b := range st.secrets {
		clear(b)
		delete(st.secrets, k)
	}
	for _, t := range st.cards {
		if t.card != nil && t.card.Prompt != nil {
			clear(t.card.Prompt.Typed)
		}
	}
	for _, t := range st.seen {
		clear(t.secret)
		t.secret = nil
	}
	for k, a := range st.consoleAnswers {
		clear(a.value)
		delete(st.consoleAnswers, k)
	}
}

func (st *state) view() View {
	v := View{Workspace: st.s.Workspace, Mode: st.eng.Mode, HubOK: st.hubOK, HubErr: st.hubErr, Locks: st.s.Locks,
		Overlay: st.overlay, Flash: st.flash, Now: st.s.now(), Quitting: st.quitting, Consoles: st.lockConsoles()}
	if st.s.Sound != nil {
		v.Sound = SoundOn
		if st.muted {
			v.Sound = SoundOff
		}
	}
	if st.overlay == overlayWithdraw {
		v.Withdraw = st.withdrawView()
	}
	if st.overlay == "audit" && st.s.Audit != nil {
		a := st.audit
		v.Audit = &a
	}
	for _, e := range st.feed {
		v.Feed = append(v.Feed, *e)
	}
	for _, t := range st.cards {
		v.Cards = append(v.Cards, *t.card)
	}
	for k, p := range st.conns {
		c := *p
		c.ReadsAsked = st.readsAsked[k]
		v.Profiles = append(v.Profiles, c)
	}
	slices.SortFunc(v.Profiles, func(a, b ProfileConn) int { return a.Since.Compare(b.Since) })
	return v
}

// draw redraws the terminal (or, without one, rings the bell only: the
// lines were printed as they came).
func (st *state) draw() {
	if !st.dirty && !st.bell {
		return
	}
	var b strings.Builder
	if st.s.Size != nil && st.dirty {
		w, h := st.s.Size()
		lines := Frame(st.view(), w, h, st.s.Style)
		if st.drawn == 0 {
			b.WriteString("\x1b[2J")
		}
		b.WriteString("\x1b[H")
		for i, l := range lines {
			b.WriteString(l)
			b.WriteString("\x1b[K")
			if i < len(lines)-1 {
				b.WriteString("\r\n")
			}
		}
		b.WriteString("\x1b[J")
		st.drawn++
	}
	if st.bell {
		// The bell rings only for a question, never for auto traffic,
		// when no sound file could be played for it.
		b.WriteString("\a")
	}
	io.WriteString(st.s.Out, b.String())
	st.dirty, st.bell = false, false
}

func (st *state) setFlash(msg string) {
	st.flash, st.flashTo = msg, st.s.now().Add(4*time.Second)
	st.logf("lox run: %s", msg)
}

func (st *state) onQueue(res api.QueueResult, err error) {
	st.dirty = true
	if err != nil {
		if st.hubOK || st.hubErr == "" {
			st.observeHub(err)
		}
		st.hubOK, st.hubErr = false, shortErr(err)
		return
	}
	if !st.hubOK {
		st.hubOK, st.hubErr = true, ""
		st.observeHub(nil)
	}
	st.withdraw.queue = res.Tickets
	inQueue := map[string]bool{}
	for _, it := range res.Tickets {
		k := key(it.Instance, it.ID)
		inQueue[k] = true
		if t, ok := st.seen[k]; ok {
			if t.lastReq != nil && !t.sending && !t.decided {
				// The hub was unreachable when lox run decided: again.
				st.pending = append(st.pending, effect{t, *t.lastReq})
				t.lastReq = nil
			}
			continue
		}
		st.add(it)
	}
	for k, t := range st.seen {
		if inQueue[k] || t.sending || t.decided {
			continue
		}
		// It left the queue without lox run's decision: another facade
		// decided it, its lock withdrew it, or it expired.
		st.removeCard(t)
		if t.entry.Status == Waiting {
			t.entry.Status = Elsewhere
			st.printEntry(t.entry)
		}
		t.decided = true
		st.results[k] = t
	}
}

func (st *state) observeHub(err error) {
	st.s.observe(Event{Kind: EvHub, Err: err})
	if err != nil {
		st.logf("lox run: hub unreachable: %s", shortErr(err))
	} else {
		st.logf("lox run: hub up")
	}
}

func shortErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "no such file"):
		return "no facade socket: is the hub running?"
	}
	return approve.Explain(err)
}

// add takes a new pending ticket into the feed and decides it, or asks.
func (st *state) add(it api.QueueItem) {
	now := st.s.now()
	k := key(it.Instance, it.ID)
	t := &tracked{instance: it.Instance, id: it.ID, item: it}
	st.seen[k] = t
	tk, verified, err := parseTicket(it, st.s.LockKeys)
	if err != nil {
		answerable := local(it.Facades)
		note := err.Error()
		if answerable {
			note = "refused: " + note
		}
		// Equal failures fold into one line with a counter.
		t.entry = &Entry{ID: it.ID, At: now, Instance: clean(it.Instance), Status: Failed, Summary: unreadableSummary,
			Note: shortNote(note)}
		st.pushEntry(t, true)
		st.s.observe(Event{Kind: EvTicket, Instance: it.Instance, ID: it.ID, Err: err})
		if !answerable {
			t.decided = true // left to another facade
			return
		}
		// Refused with the reason, so its lock ends the plan and frees
		// its slot instead of waiting for an answer no facade gives.
		t.unreadable = true
		st.pending = append(st.pending, effect{t, api.DecideRequest{Facade: route.TTY, Display: st.s.Display,
			Reason: rejectReason(err)}})
		return
	}
	t.tk = tk
	t.req = Request{Instance: it.Instance, Lock: tk.Source.Lock, V: tk.V, Kind: tk.EffectiveKind(), Risk: tk.Risk,
		Subject: tk.Subject, NeverAuto: tk.Flags.NeverAuto, Production: tk.Flags.Production, Retype: it.Retype != "",
		Verified: verified}
	if tk.V < ticket.VersionKinds {
		// A version-1 ticket's kind is only implied by its risk.
		t.req.Subject = nil
	}
	t.profileKey = it.Instance + "/" + t.req.Profile()
	st.active[t.profileKey] = now
	t.gen = st.gen[t.profileKey]
	dropped := false
	if ran, ok := st.ran[t.profileKey]; ok {
		delete(st.ran, t.profileKey)
		if tk.Kind == ticket.KindConnect && st.s.ReconnectAsk > 0 && now.Sub(ran.at) < st.s.ReconnectAsk &&
			ran.endpoint == endpointOf(tk) {
			// It connected and asks again before anything ran on it: the
			// connection did not work. The same credentials are not
			// sent again on their own. A connect to another endpoint is
			// the profile's next leg (its database behind a bastion).
			st.forget(it.Instance, t.req.Profile())
			t.gen = st.gen[t.profileKey]
			dropped = true
		}
	}
	target := ""
	if tk.Subject != nil {
		target = clean(tk.Subject.Target)
	}
	t.entry = &Entry{ID: it.ID, At: now, Agent: clean(tk.Requester.Agent), Instance: clean(it.Instance), Lock: clean(tk.Source.Lock),
		Profile: clean(t.req.Profile()), Kind: t.req.Kind, Production: tk.Flags.Production, Summary: summary(tk), Target: target}
	st.s.observe(Event{Kind: EvTicket, Instance: it.Instance, ID: it.ID})
	if !local(it.Facades) {
		t.entry.Status, t.entry.Note = Elsewhere, "(not answerable here)"
		st.pushEntry(t, false)
		t.decided = true
		st.results[k] = t
		return
	}
	v := st.eng.Decide(t.req)
	if dropped && v.Outcome == Question {
		v.Why = "asked to connect again right after connecting: the session's password is dropped"
	}
	st.apply(t, v)
}

// forget drops the session's connection approval, endpoints and secret
// for a profile (x, or a reconnect right after connecting): its next
// ticket is asked again, and a connect still on its way does not put
// them back.
func (st *state) forget(instance, profile string) {
	pk := instance + "/" + profile
	for k, s := range st.secrets {
		if k.profile == pk {
			clear(s)
			delete(st.secrets, k)
		}
	}
	st.eng.Forget(instance, profile)
	delete(st.conns, pk)
	delete(st.ran, pk)
	st.gen[pk]++
}

// forgetAll is forget on every profile of the session.
func (st *state) forgetAll() {
	for pk, s := range st.secrets {
		clear(s)
		delete(st.secrets, pk)
	}
	st.eng.ForgetAll()
	pks := map[string]bool{}
	for pk := range st.conns {
		pks[pk] = true
	}
	for _, t := range st.seen {
		pks[t.profileKey] = true
	}
	for pk := range pks {
		st.gen[pk]++
	}
	clear(st.conns)
	clear(st.ran)
}

// unreadableSummary is the feed's summary of a ticket that does not
// verify: lox run cannot show what it asks.
const unreadableSummary = "unreadable ticket"

// rejectReason is the reason of lox run's refusal of a ticket that does
// not verify, as its lock returns it to the agent.
func rejectReason(err error) string {
	r := "ticket rejected by lox run: " + clean(err.Error())
	if len(r) > 512 {
		r = r[:512]
	}
	return r
}

func shortNote(s string) string {
	s = clean(s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func needsSecret(t *tracked) bool {
	return t.tk != nil && t.tk.Kind == ticket.KindConnect && t.tk.Subject != nil && t.tk.Subject.SecretTo != ""
}

// secretKey keys a session secret: the profile and the endpoint the lock
// connected to with it.
type secretKey struct{ profile, endpoint string }

// ranAt is when, and to which endpoint, the lock last connected on a
// profile.
type ranAt struct {
	at       time.Time
	endpoint string
}

func endpointOf(tk *ticket.Ticket) string {
	if tk == nil || tk.Subject == nil {
		return ""
	}
	return tk.Subject.Endpoint
}

func (t *tracked) secretKey() secretKey {
	return secretKey{t.profileKey, endpointOf(t.tk)}
}

// cachedSecret is the secret typed earlier in this session for an "ask"
// profile's endpoint that the lock connected with (a copy: the caller
// wipes it), nil otherwise. A Vault token is
// asked each time the lock asks: it asks only once its own expired.
func (st *state) cachedSecret(t *tracked) []byte {
	if t.tk.Subject.Credential != ticket.CredentialAsk {
		return nil
	}
	if s, ok := st.secrets[t.secretKey()]; ok {
		return slices.Clone(s)
	}
	return nil
}

// apply carries out the engine's verdict on t.
func (st *state) apply(t *tracked, v Verdict) {
	switch v.Outcome {
	case Approve:
		var secret []byte
		if needsSecret(t) {
			if secret = st.cachedSecret(t); secret == nil {
				st.ask(t, "the lock asks for the secret: "+v.Why, "ask:secret")
				return
			}
			t.cached = true
		}
		t.entry.Status, t.entry.Rule, t.entry.Tag = AutoApproved, v.Rule, v.Tag
		st.pushEntry(t, true)
		st.send(t, true, v.Rule, secret)
		clear(secret)
	case Refuse:
		t.entry.Status, t.entry.Rule, t.entry.Tag = Denied, v.Rule, v.Tag
		st.pushEntry(t, false)
		st.send(t, false, v.Rule, nil)
	default:
		// An unmask (read-pii) is the lock's own question, not a read
		// its profile asks.
		if t.req.NeverAuto && t.req.Action() == ActRead && t.req.Risk == ticket.RiskRead {
			st.readsAsked[t.profileKey] = true
		}
		st.ask(t, v.Why, v.Tag)
	}
}

// ask puts t's question card up and calls the human (a sound, the bell).
func (st *state) ask(t *tracked, why, tag string) {
	tk := t.tk
	c := &Card{ID: t.id, Instance: clean(t.instance), Lock: clean(tk.Source.Lock), Agent: clean(tk.Requester.Agent),
		Profile: clean(t.req.Profile()), Kind: t.req.Kind, Risk: clean(string(tk.Risk)), Production: tk.Flags.Production,
		Workspace: clean(tk.Workspace), Header: clean(tk.Screen.Header), Note: clean(tk.Screen.Note), Why: why,
		Unverified: !t.req.Verified}
	for _, b := range tk.Screen.Body {
		c.Body = append(c.Body, clean(b))
	}
	for _, w := range tk.Screen.Warnings {
		c.Warnings = append(c.Warnings, clean(w))
	}
	for _, p := range tk.PII.Touched {
		c.Touched = append(c.Touched, clean(p))
	}
	if t.item.Expires != nil {
		c.Expires = *t.item.Expires
	}
	t.card = c
	st.detach(t)
	t.entry.Status, t.entry.Rule, t.entry.Asked, t.entry.Tag = Waiting, "", clean(why), tag
	st.pushEntry(t, false)
	st.cards = append(st.cards, t)
	st.call(t)
	st.dirty = true
	if st.s.Size == nil {
		for _, l := range card(st.view(), *c, len(st.cards), 80, st.s.Style) {
			fmt.Fprintln(st.s.Out, finish(l, 80, st.s.Style))
		}
		st.logf("answer: y approve, n deny (the question on top first)")
	}
	st.s.observe(Event{Kind: EvQuestion, Instance: t.instance, ID: t.id})
}

func (st *state) removeCard(t *tracked) {
	if t.card != nil && t.card.Prompt != nil {
		clear(t.card.Prompt.Typed)
	}
	st.cards = slices.DeleteFunc(st.cards, func(x *tracked) bool { return x == t })
	t.card = nil
	st.dirty = true
}

// pushEntry puts t's entry in the feed once; an auto read equal to the
// last line folds into it (× N).
func (st *state) pushEntry(t *tracked, group bool) {
	st.dirty = true
	if t.inFeed {
		st.printEntry(t.entry)
		return
	}
	t.inFeed = true
	e := t.entry
	if group && len(st.feed) > 0 {
		last := st.feed[len(st.feed)-1]
		if g := e.group(); g != "" && g == last.group() && e.At.Sub(last.At) < 10*time.Minute {
			last.Count = max(last.Count, 1) + 1
			last.At, last.Summary, last.ID, last.Result = e.At, e.Summary, e.ID, ResNone
			t.entry = last
			st.printEntry(e)
			return
		}
	}
	st.feed = append(st.feed, e)
	if len(st.feed) > maxFeed {
		st.feed = st.feed[len(st.feed)-maxFeed:]
	}
	st.printEntry(e)
}

// send queues lox run's decision on t: rule "" is the human's. A secret
// is sealed to the lock's one-use key on the ticket, which lox run
// verified under the pinned lock key: neither the hub nor the agent can
// open it.
func (st *state) send(t *tracked, approved bool, rule string, secret []byte) {
	req := api.DecideRequest{Approved: approved, Facade: route.TTY, Display: st.s.Display, Rule: rule, Retype: t.retyped}
	if rule == "" {
		req.Asked = askedText(t.entry.Asked)
	}
	if approved && secret != nil {
		box, err := ticket.SealSecret(t.tk, secret)
		if err == nil {
			req.Secret, err = json.Marshal(box)
		}
		if err != nil {
			st.failed(t, "cannot seal the secret: "+err.Error())
			return
		}
	}
	st.pending = append(st.pending, effect{t, req})
}

// detach gives t a feed line of its own when it was folded into a line
// of equal auto reads (its decision went otherwise).
func (st *state) detach(t *tracked) {
	if t.entry.Count <= 1 {
		return
	}
	t.entry.Count--
	e := *t.entry
	e.Count, e.ID, e.Result = 0, t.id, ResNone
	t.entry, t.inFeed = &e, false
	st.pushEntry(t, false)
}

func (st *state) failed(t *tracked, note string) {
	st.removeCard(t)
	st.detach(t)
	t.entry.Status, t.entry.Note = Failed, shortNote(note)
	t.decided = true
	clear(t.secret)
	t.secret = nil
	st.printEntry(t.entry)
	st.s.observe(Event{Kind: EvFailed, Instance: t.instance, ID: t.id, Err: errors.New(note)})
}

func (st *state) onDecided(t *tracked, req api.DecideRequest, err error) {
	t.sending = false
	st.dirty = true
	if err == nil && t.unreadable {
		t.decided = true
		st.results[key(t.instance, t.id)] = t
		st.s.observe(Event{Kind: EvDecided, Instance: t.instance, ID: t.id})
		return
	}
	if err == nil {
		t.decided = true
		st.removeCard(t)
		switch {
		case req.Rule != "" && req.Approved:
			t.entry.Status = AutoApproved
		case req.Approved:
			t.entry.Status = Approved
			if t.req.Action() == ActConnect {
				t.human = true // the session reuses it once the lock connected
			} else {
				st.eng.Answered(t.req, true)
			}
		default:
			t.entry.Status = Denied
			if req.Rule == "" {
				st.eng.Answered(t.req, false)
			}
		}
		t.entry.Rule = req.Rule
		st.results[key(t.instance, t.id)] = t
		if req.Rule == "" {
			st.printEntry(t.entry)
		}
		st.s.observe(Event{Kind: EvDecided, Instance: t.instance, ID: t.id, Approved: req.Approved, Rule: req.Rule})
		return
	}
	var he *approve.HubError
	switch {
	case errors.As(err, &he) && he.Kind == "needs_human" && req.Rule != "":
		// The hub wants a human for it: asked after all.
		st.ask(t, "the hub wants a human for this ticket", "ask:hub")
	case errors.As(err, &he) && he.Kind == "retype" && t.card != nil:
		t.retyped = ""
		t.promptKind = promptRetype
		t.card.Prompt = &Prompt{Label: retypeLabel(t), Error: "does not match"}
	case errors.As(err, &he):
		st.failed(t, "hub refused: "+approve.Explain(err))
	default:
		// The hub is unreachable: sent again once it lists the ticket.
		t.lastReq = &req
		t.entry.Note = "(hub unreachable: will retry)"
	}
}

func retypeLabel(t *tracked) string {
	return fmt.Sprintf("production: type the instance name %q to approve:", clean(t.item.Retype))
}

func (st *state) onState(t *tracked, res api.TicketState, err error) {
	k := key(t.instance, t.id)
	if err != nil {
		var he *approve.HubError
		if errors.As(err, &he) && he.Status == 404 {
			delete(st.results, k)
			delete(st.seen, k)
			st.settleConnect(t, false)
		}
		return
	}
	var r Result
	switch res.State {
	case "consumed":
		r = ResRan
	case "expired":
		r = ResExpired
	case "withdrawn":
		r = ResWithdrawn
	case "lock_removed":
		r = ResRemoved
	case "denied":
		if t.entry.Status == Elsewhere {
			t.entry.Note = "(denied elsewhere)"
		}
	case "approved":
		if t.entry.Status == Elsewhere {
			t.entry.Note = "(approved elsewhere)"
		}
		if st.s.now().Sub(t.entry.At) < 15*time.Minute {
			return // waiting for its lock to act on it
		}
	case "pending":
		return
	}
	delete(st.results, k)
	delete(st.seen, k)
	st.dirty = true
	st.settleConnect(t, r == ResRan)
	if r == ResNone {
		return
	}
	if t.entry.ID == t.id {
		t.entry.Result = r
	}
	if r == ResRan && t.tk != nil && t.tk.Kind == ticket.KindConnect {
		// The lock opened the connection.
		st.conns[t.profileKey] = &ProfileConn{Name: clean(t.profileKey), Since: st.s.now(), Production: t.tk.Flags.Production}
	}
	if t.entry.Rule == "" {
		st.printEntry(t.entry)
	}
	st.s.observe(Event{Kind: EvResult, Instance: t.instance, ID: t.id, Result: r})
}

// settleConnect ends a connect ticket's wait for its result. Consumed
// (ran): the lock opened the connection, so the secret typed for it
// opens the backend and is kept for the profile, and the human's
// approval of the connection holds for the session. Anything else (it
// expired, was withdrawn, stayed approved and never ran: the lock could
// not connect, a mistyped password) keeps neither, and a session secret
// it carried is dropped: the next connect is asked again.
func (st *state) settleConnect(t *tracked, ran bool) {
	secret := t.secret
	t.secret = nil
	if t.tk == nil || t.tk.Kind != ticket.KindConnect {
		clear(secret)
		return
	}
	if t.gen != st.gen[t.profileKey] {
		clear(secret) // the human dropped the profile since: kept nothing
		return
	}
	if !ran {
		clear(secret)
		if t.cached {
			if s, ok := st.secrets[t.secretKey()]; ok {
				clear(s)
				delete(st.secrets, t.secretKey())
			}
			st.eng.Disconnect(t.instance, t.req.Profile())
		}
		return
	}
	st.ran[t.profileKey] = ranAt{st.s.now(), endpointOf(t.tk)}
	if secret != nil {
		if old, ok := st.secrets[t.secretKey()]; ok {
			clear(old)
		}
		st.secrets[t.secretKey()] = secret
	}
	if t.human {
		st.eng.Answered(t.req, true)
	}
}

func (st *state) onTick() {
	now := st.s.now()
	if st.flash != "" && now.After(st.flashTo) {
		st.flash = ""
	}
	for k, p := range st.conns {
		if last, ok := st.active[k]; ok && last.After(p.Since) {
			if now.Sub(last) > st.s.IdleConn {
				delete(st.conns, k) // the lock closed it as idle
			}
		} else if now.Sub(p.Since) > st.s.IdleConn {
			delete(st.conns, k)
		}
	}
	if st.overlay == "audit" {
		st.loadAudit()
	}
	st.remind()
	st.dirty = st.s.Size != nil
}

// loadAudit reads the hub's audit for the audit view, when it is open.
func (st *state) loadAudit() {
	if st.overlay != "audit" || st.s.Audit == nil {
		return
	}
	xs, runs, err := st.s.Audit()
	if err != nil {
		st.audit.err = shortNote(err.Error())
		return
	}
	st.audit = auditView{xs: xs, runs: runs}
}

// syncTop notes the card on top as the screen is about to show it. When
// it is another card than the one shown last (the top one was decided,
// withdrawn, expired, or Tab), the keys already typed are dropped and y
// and n wait for KeyArm: they were meant for the card that went away.
// When the card went away with its prompt open, the keys typed next are
// still that prompt's (a password half typed): they are dropped until
// Enter or Esc, never read as answers to the next card.
func (st *state) syncTop() {
	var top *tracked
	if len(st.cards) > 0 {
		top = st.cards[0]
	}
	if top != st.shownTop {
		if st.shownPrompt {
			st.discard = true
			st.flash = "the question you were typing into went away: what you type is dropped until Enter or Esc"
			st.flashTo = st.s.now().Add(10 * time.Second)
			st.logf("lox run: %s", st.flash)
		}
		st.shownTop, st.shownAt = top, st.s.now()
		if st.s.KeyArm >= 0 {
			st.flushKeys = true
		}
		st.dirty = true
		if top != nil && st.s.Size == nil && len(st.cards) > 1 {
			// A log shows the cards as they came: say which one y and n answer.
			st.logf("lox run: on top now: %s %s (y approve, n deny)", clean(top.profileKey), top.entry.Summary)
		}
	}
	st.shownPrompt = top != nil && top.card.Prompt != nil
}

// armed: the card on top has been shown long enough to be answered.
func (st *state) armed() bool {
	return st.s.KeyArm <= 0 || st.s.now().Sub(st.shownAt) >= st.s.KeyArm
}

// dropTyped drops the keys already typed (the top card changed under
// them); Enter or Esc among them ends an orphaned prompt's input. True:
// one was Ctrl-C or Ctrl-D (quit).
func (st *state) dropTyped() bool {
	for st.s.Keys != nil {
		select {
		case k, ok := <-st.s.Keys:
			if !ok {
				st.s.Keys = nil
				return false
			}
			switch k.Code {
			case KeyCtrlC, KeyCtrlD:
				return true
			case KeyEnter, KeyEsc:
				st.endDiscard()
			}
		default:
			return false
		}
	}
	return false
}

func (st *state) endDiscard() {
	if st.discard {
		st.discard = false
		st.flash = ""
		st.dirty = true
	}
}

// onKey handles a key; true quits.
func (st *state) onKey(k Key) bool {
	st.dirty = true
	if k.Code == KeyCtrlC || k.Code == KeyCtrlD {
		return true
	}
	st.syncTop()
	if st.discard {
		// Input of a prompt whose card went away: dropped up to its end.
		if k.Code == KeyEnter || k.Code == KeyEsc {
			st.endDiscard()
		}
		return false
	}
	var top *tracked
	if len(st.cards) > 0 {
		top = st.cards[0]
	}
	if top != nil && top.card.Prompt != nil {
		st.promptKey(top, k)
		st.shownPrompt = top.card != nil && top.card.Prompt != nil
		return false
	}
	if st.quitting {
		st.quitting = false
		if k.Code == KeyRune && (k.Rune == 'q' || k.Rune == 'Q') {
			return true
		}
	}
	st.flash = ""
	if st.overlay == overlayWithdraw {
		st.withdrawKey(k)
		return false
	}
	switch k.Code {
	case KeyShiftTab:
		st.eng.Mode = st.eng.Mode.Toggle()
		if st.eng.Mode == Manual {
			st.setFlash("MANUAL mode: every ticket is asked")
		} else {
			st.setFlash("AUTO mode: the rules decide what they allow")
			st.reevaluate()
		}
		st.s.observe(Event{Kind: EvMode, Mode: st.eng.Mode})
		return false
	case KeyTab:
		if len(st.cards) > 1 {
			st.cards = append(st.cards[1:], st.cards[0])
		}
		return false
	case KeyEsc:
		st.overlay = ""
		return false
	case KeyRune:
	default:
		return false
	}
	switch k.Rune {
	case '?':
		st.overlay = toggle(st.overlay, "help")
	case 'a', 'A':
		st.overlay = toggle(st.overlay, "audit")
		st.loadAudit()
	case 'q', 'Q':
		st.quitting = true
	case 'y', 'Y', 'n', 'N':
		if top == nil || top.sending {
			break
		}
		if !st.armed() {
			// Pressed before this card was shown: meant for another.
			st.setFlash("the question on top just changed: read it, then press " + string(k.Rune) + " again")
			break
		}
		yes := k.Rune == 'y' || k.Rune == 'Y'
		switch {
		case top.cq != nil:
			st.consoleKey(top, yes)
		case yes:
			st.approve(top)
		default:
			st.send(top, false, "", nil)
		}
		st.shownPrompt = top.card != nil && top.card.Prompt != nil
	case 'd', 'D':
		if top != nil {
			top.card.Details = !top.card.Details
		}
	case 'w', 'W':
		st.overlay = overlayWithdraw
		st.withdraw.sel, st.withdraw.confirm = 0, nil
	case 'x', 'X':
		st.forgetKey(top)
	case 's', 'S':
		st.toggleSound()
	}
	return false
}

// forgetKey is x: drop the session's connection, endpoints and secret of
// the question's profile, or of every profile when nothing is asked.
func (st *state) forgetKey(top *tracked) {
	if top != nil && top.cq != nil {
		st.forgetConsole(top.instance)
		if top.card.Prompt != nil {
			top.card.Prompt = st.consolePrompt(top)
		}
		st.setFlash("forgot the answers typed to " + clean(top.instance) + "'s console: asked again")
		return
	}
	if top != nil && top.tk != nil {
		st.forget(top.instance, top.req.Profile())
		st.setFlash("forgot " + clean(top.profileKey) + ": its connection, endpoints and password are asked again")
		return
	}
	st.forgetAll()
	for i := range st.consoles {
		st.forgetConsole(i)
	}
	st.setFlash("forgot every profile: connections, endpoints and passwords are asked again")
}

func toggle(cur, v string) string {
	if cur == v {
		return ""
	}
	return v
}

// reevaluate decides, back in auto mode, the questions the rules now
// decide (none being typed into).
func (st *state) reevaluate() {
	for _, t := range slices.Clone(st.cards) {
		if t.sending || t.cq != nil || t.card.Prompt != nil {
			continue
		}
		v := st.eng.Decide(t.req)
		if v.Outcome == Question || (v.Outcome == Approve && needsSecret(t) && st.cachedSecret(t) == nil) {
			continue
		}
		st.removeCard(t)
		st.apply(t, v)
	}
}

// approve is y on t: the instance name first when the hub wants it typed,
// then the secret when the lock asks for one. The human is always shown
// the secret prompt, never handed the session's silently: y is how a
// mistyped one is typed again, and Enter alone keeps the session's.
func (st *state) approve(t *tracked) {
	if t.item.Retype != "" && t.retyped != t.item.Retype {
		t.promptKind = promptRetype
		t.card.Prompt = &Prompt{Label: retypeLabel(t)}
		return
	}
	if needsSecret(t) {
		if !t.req.Verified {
			st.setFlash("this lock's key is not pinned here: no secret can be sealed to it (restart lox run to pin it); n denies")
			return
		}
		t.promptKind = promptSecret
		// The endpoint tells a profile's legs apart (its bastion, its
		// database): each asks its own password.
		of := clean(t.profileKey)
		if ep := clean(t.tk.Subject.Endpoint); ep != "" {
			of += " (" + ep + ")"
		}
		label := "password for " + of + ":"
		if t.tk.Subject.Credential == ticket.CredentialVault {
			label = "Vault token for " + of + " (its token expired):"
		}
		p := &Prompt{Label: label, Secret: true}
		if c := st.cachedSecret(t); c != nil {
			clear(c)
			p.Label = "password for " + of + " (Enter alone: this session's):"
			p.Default = true
		}
		t.card.Prompt = p
		return
	}
	st.send(t, true, "", nil)
}

const maxTyped = 4096

func (st *state) promptKey(t *tracked, k Key) {
	p := t.card.Prompt
	switch k.Code {
	case KeyEsc:
		clear(p.Typed)
		t.card.Prompt = nil
	case KeyBackspace:
		if n := len(p.Typed); n > 0 {
			p.Typed[n-1] = 0
			p.Typed = p.Typed[:n-1]
		}
	case KeyEnter:
		if !st.armed() {
			p.Error = "this question just came on top: read it, then press Enter again"
			return
		}
		// The secret goes from the typed runes to bytes the session
		// wipes, never through a string.
		var secret []byte
		for _, r := range p.Typed {
			secret = utf8.AppendRune(secret, r)
		}
		clear(p.Typed)
		p.Typed = nil
		defer clear(secret)
		if t.cq != nil {
			st.consoleEnter(t, secret)
			return
		}
		switch t.promptKind {
		case promptRetype:
			typed := string(secret)
			if typed != t.item.Retype {
				p.Error = "does not match: not approved"
				return
			}
			t.retyped = typed
			t.card.Prompt = nil
			st.approve(t)
		case promptSecret:
			if len(secret) == 0 {
				c := st.cachedSecret(t)
				if c == nil {
					p.Error = "empty"
					return
				}
				// Enter alone: the session's, dropped if it does not connect.
				defer clear(c)
				t.cached = true
				t.card.Prompt = nil
				st.send(t, true, "", c)
				return
			}
			if t.tk.Subject.Credential == ticket.CredentialAsk {
				// Kept for the profile only once the lock connected with it.
				clear(t.secret)
				t.secret = slices.Clone(secret)
			}
			t.card.Prompt = nil
			st.send(t, true, "", secret)
		}
	case KeyRune:
		if len(p.Typed) < maxTyped {
			p.Typed = append(p.Typed, k.Rune)
			p.Error = ""
		}
	}
}
