package loxrun

import (
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// An unattended session (Session.Unattended) is lox live's: the same
// engine and the same hub as lox run, with no human. It decides what a
// written rule decides and nothing else:
//
//   - a ticket the engine would ask (a write, a DDL, a first connection
//     no rule allows, a grant, a never-auto ticket, a typed name, typed
//     values, a policy loosening, a ticket the hub wants a human for) is
//     left pending at the hub, for a human's facade (the phone, lox
//     approve); nothing here ever answers it;
//   - a console's question is never answered, but the Vault token's of a
//     lock with vault_token: cli (the host's token, read and checked as
//     lox run does). A password, a production profile's name, a policy
//     to review, a host key to trust: the console keeps waiting, and the
//     session says which (ConsoleStatus.Blocked), for lox live's health.

// Why a console waits in an unattended session (ConsoleStatus.Blocked):
// the states lox live's health names.
const (
	// BlockedSecret: it asks a secret lox live does not hold (a password
	// of a credentials: ask profile, a passphrase, a Vault token the
	// host cannot give).
	BlockedSecret = "missing_secret"
	// BlockedEnrolment: it asks a human to review its policy or to type
	// its production profile's name (a first start, a policy loosened
	// since it was approved): answered at a terminal, then enrolled
	// again.
	BlockedEnrolment = "needs_enrolment"
	// BlockedRefused: any other question (an SSH host key to trust): lox
	// live answers none.
	BlockedRefused = "refused"
)

// ConsoleStatus is a lock's console as an Observe hook is told it
// (EvConsole).
type ConsoleStatus struct {
	State ConsoleState
	// Blocked is why it waits for a question nobody here answers (an
	// unattended session): BlockedSecret, BlockedEnrolment or
	// BlockedRefused; "" otherwise. Detail says what it waits for, or
	// why it stopped (never an answer).
	Blocked, Detail string
}

// unattendedT is what an unattended session keeps on a tracked ticket or
// console question.
type unattendedT struct {
	// autoRule and autoTag are the rule that approved a connect whose
	// Vault token is being read (vaultByRule).
	autoRule, autoTag string
	// vaultRetry: a console's Vault token question could not be answered
	// and is tried again at retryAt.
	retryAt    time.Time
	vaultRetry bool
}

// leave leaves t pending at the hub for a human's facade: an unattended
// session asks nobody.
func (st *state) leave(t *tracked, why, tag string) {
	st.removeCard(t)
	st.detach(t)
	t.entry.Status, t.entry.Rule, t.entry.Asked, t.entry.Tag = Elsewhere, "", clean(why), tag
	t.entry.Note = shortNote("(left to a human's facade: " + why + ")")
	st.pushEntry(t, false)
	t.decided = true
	st.results[key(t.instance, t.id)] = t
	st.s.observe(Event{Kind: EvLeft, Instance: t.instance, ID: t.id, Why: why})
}

// policyQuestion: the console asks a human to review its policy (a first
// start, a loosening) or to type its production profile's name.
func policyQuestion(cq *consoleQ) bool {
	if strings.Contains(cq.prompt, "Type the profile name") {
		return true
	}
	for _, l := range cq.context {
		if strings.Contains(l, "review its policy") || strings.Contains(l, "changed since it was approved") {
			return true
		}
	}
	return false
}

// blockedOf is why an unattended session does not answer cq.
func blockedOf(cq *consoleQ) (blocked, detail string) {
	q := strings.TrimSpace(clean(cq.prompt))
	switch {
	case policyQuestion(cq):
		return BlockedEnrolment, "its console asks a human to review its policy or type its profile name (" + q + "): answer at a terminal (lox run), then lox live enrol"
	case cq.kind == cqSecret:
		return BlockedSecret, "its console asks a secret lox live does not hold (" + q + "): lox live takes credentials from Vault only"
	}
	return BlockedRefused, "its console asks a question lox live never answers (" + q + "): answer at a terminal (lox run, lox attach)"
}

// blockConsole leaves t's console question unanswered and says why;
// vaultWhy, when set, is why the host's Vault token did not answer it.
func (st *state) blockConsole(t *tracked, vaultWhy string) {
	blocked, detail := blockedOf(t.cq)
	if st.vaultPrompt(t.instance, t.cq.prompt) {
		// Its own question: tried again later (Vault Agent may write a
		// new token meanwhile).
		// A token the lock refused: later and later (the same token is
		// not typed for ever), until the host's token changes.
		delay := st.s.VaultRetry
		if n := st.vaultRefused[t.instance]; n > 1 {
			delay = min(st.s.VaultRetry<<min(n-1, 16), st.s.VaultRetryMax)
		}
		t.vaultRetry, t.retryAt = true, st.s.now().Add(delay)
		blocked = BlockedSecret
		detail = "the host's Vault token cannot be used for its console"
		if vaultWhy != "" {
			detail += ": " + clean(vaultWhy)
		}
	}
	if t.entry.Status == Waiting {
		t.entry.Status, t.entry.Note = Elsewhere, shortNote("(not answered by lox live: "+blocked+")")
		st.printEntry(t.entry)
	}
	st.s.observe(Event{Kind: EvConsole, Instance: t.instance, Console: &ConsoleStatus{State: ConsoleWaiting, Blocked: blocked, Detail: detail}})
}

// retryVault reads the host's Vault token again for the consoles whose
// Vault token question could not be answered Session.VaultRetry ago.
func (st *state) retryVault() {
	if !st.s.Unattended {
		return
	}
	now := st.s.now()
	changed := false
	if st.s.VaultStamp != nil {
		if s := st.s.VaultStamp(); s != st.vaultStamp || !st.vaultStampSet {
			// Another token on the host: the refusals were the old one's.
			changed = st.vaultStampSet
			st.vaultStamp, st.vaultStampSet = s, true
			if changed {
				clear(st.vaultRefused)
			}
		}
	}
	for _, t := range st.consoleCards {
		if t.vaultRetry && !t.vaultFetching && !t.decided && (changed || !now.Before(t.retryAt)) {
			if changed {
				// Not a refusal of this token: it is typed at once.
				delete(st.vaultCLIAt, answerKey(t.instance, t.cq.prompt))
			}
			t.vaultRetry, t.vaultFetching = false, true
			st.vaultFetches = append(st.vaultFetches, t)
		}
	}
}

// vaultByRule: in an unattended session, a connect a rule approves (v)
// whose lock asks for its Vault token again (it expired) and has
// vault_token: cli gets the host's token, read off the loop, then the
// rule's approval with the token sealed to the lock. false: not such a
// ticket (it is asked, hence left to a human).
func (st *state) vaultByRule(t *tracked, v Verdict) bool {
	if !st.s.Unattended || !t.req.Verified || t.tk.Subject.Credential != ticket.CredentialVault || !st.vaultCLI(t.instance) {
		return false
	}
	t.autoRule, t.autoTag = v.Rule, v.Tag
	t.vaultFetching = true
	st.vaultFetches = append(st.vaultFetches, t)
	return true
}

// vaultRuled takes the host's token read for the connect t a rule
// approved (vaultByRule): sent sealed with the rule's approval, or, when
// the token cannot be used, t is left to a human.
func (st *state) vaultRuled(t *tracked, tok []byte, err error) {
	if t.autoRule == "" || t.sending {
		return
	}
	if err != nil {
		st.leave(t, "the host's Vault token cannot be used: "+err.Error(), "ask:secret")
		return
	}
	t.entry.Status, t.entry.Rule, t.entry.Tag = AutoApproved, t.autoRule, t.autoTag
	t.entry.Summary += " · " + vaultCLISummary
	st.pushEntry(t, false)
	t.vaultHow = VaultFromCLI
	st.send(t, true, t.autoRule, tok)
}
