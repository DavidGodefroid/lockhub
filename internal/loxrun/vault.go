package loxrun

import (
	"context"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// VaultCLI hands the locks with vault_token: cli the host's Vault CLI
// token (lockhub#124): their console's Vault token prompt is answered
// with it, and their expired-token connect ticket is sealed it on y.
// Whenever the token is unusable, the human is asked as before, told why.
type VaultCLI struct {
	// Address is the reviewed vault.address: the console prompt answered
	// is "Vault token for <Address>:".
	Address string
	// Locks are the instances with vault_token: cli.
	Locks map[string]bool
	// Token reads and checks the host's token for instance, off the
	// session's loop: the token (the session wipes it) or why it cannot
	// be used, never with the token in it.
	Token func(ctx context.Context, instance string) ([]byte, error)
}

// How a Vault token reached a lock (Event.VaultToken, the journal).
const (
	VaultFromCLI = "cli"
	VaultTyped   = "typed"
)

// vaultCLIRule is the rule of a console answer given the CLI's token.
const vaultCLIRule = "vault:cli"

// vaultCLISummary is the feed line of a console answered with the CLI's
// token.
const vaultCLISummary = "vault token: from CLI"

func (st *state) vaultCLI(instance string) bool {
	v := st.s.Vault
	return v != nil && v.Token != nil && v.Locks[instance]
}

// vaultPrompt: prompt is the Vault token prompt of a vault_token: cli
// lock's console, naming the reviewed address exactly.
func (st *state) vaultPrompt(instance, prompt string) bool {
	if !st.vaultCLI(instance) {
		return false
	}
	return strings.TrimSpace(clean(prompt)) == "Vault token for "+clean(st.s.Vault.Address)+":"
}

// onVaultToken takes the host's token read for t (tok, which it wipes,
// or why it is unusable).
func (st *state) onVaultToken(t *tracked, tok []byte, err error) {
	defer clear(tok)
	t.vaultFetching = false
	st.dirty = true
	if t.decided {
		return // answered elsewhere, or gone
	}
	if t.cq != nil {
		if st.consoleCards[t.instance] != t {
			return
		}
		if err != nil {
			t.entry.Tag = ""
			st.showConsoleCard(t, err.Error())
			return
		}
		st.vaultCLIAt[answerKey(t.instance, t.cq.prompt)] = st.s.now()
		t.entry.Summary, t.entry.Rule = vaultCLISummary, vaultCLIRule
		st.answerConsole(t, tok, true)
		return
	}
	if t.sending || t.card == nil || !slices.Contains(st.cards, t) {
		return
	}
	if err != nil {
		t.vaultWhy = err.Error()
		st.approve(t)
		return
	}
	t.entry.Summary += " · " + vaultCLISummary
	t.vaultHow = VaultFromCLI
	st.send(t, true, "", tok)
}

// vaultConnect is y on a vault_token: cli lock's expired-token connect:
// the host's token is read again (a new vault login is picked up) and
// sealed in place of the prompt. false: the prompt is shown (the token
// was found unusable for this ticket).
func (st *state) vaultConnect(t *tracked) bool {
	if t.tk.Subject.Credential != ticket.CredentialVault || !st.vaultCLI(t.instance) || t.vaultWhy != "" {
		return false
	}
	if !t.vaultFetching {
		t.vaultFetching = true
		st.vaultFetches = append(st.vaultFetches, t)
	}
	st.setFlash("reading the Vault CLI's token for " + clean(t.instance) + "…")
	return true
}
