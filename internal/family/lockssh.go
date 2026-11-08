package family

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// A lockssh profile's auto rules (lockssh docs/decisions.md, Approvals and
// routing): for each action that becomes a ticket, what lox run's auto
// mode does with it: auto, ask or deny. connect is the first use of an SSH
// session (risk read-pii), run an allow-listed command (read), exec a
// command outside the allow list (write, prod-write on production),
// unmask a command's output in clear (read-pii). lox run reads them with
// `lockssh profile rules --json`, run in the lock's image on the reviewed
// copy (rules-<instance>, as locklog's), shows them in the review and
// applies them in its engine. The console enforces its own side whatever
// lox run does: a deny is refused before any ticket, the ticket of an ask
// is signed never-auto, and unmask is never auto.

// SSHRuleActions are lockssh's auto-rule actions, in the order the review
// shows them (its config.AutoActions).
var SSHRuleActions = []string{"connect", "run", "exec", "unmask"}

// DeriveSSHRules reads the output of `lockssh profile rules --json`: the
// rules of profile, or of every profile it lists when the lock names none
// (the human picks one at the console), by profile. Output it cannot read
// gives one entry, "", whose rules are unknown: lox run asks every ticket
// of the lock (fail closed).
func DeriveSSHRules(out []byte, profile string) map[string]*LogRules {
	if profile != "" {
		return map[string]*LogRules{profile: deriveRules(out, "lockssh", SSHRuleActions, profile)}
	}
	var o struct {
		Lock     string `json:"lock"`
		Profiles []struct {
			Profile string `json:"profile"`
		} `json:"profiles"`
	}
	line := lastJSONLine(out)
	if len(out) > maxRules || line == nil || json.Unmarshal(line, &o) != nil || o.Lock != "lockssh" {
		return map[string]*LogRules{"": deriveRules(out, "lockssh", SSHRuleActions, "")}
	}
	m := map[string]*LogRules{}
	for _, p := range o.Profiles {
		if p.Profile != "" {
			m[p.Profile] = deriveRules(out, "lockssh", SSHRuleActions, p.Profile)
		}
	}
	if len(m) == 0 {
		m[""] = &LogRules{Lock: "lockssh", Unknown: "lockssh profile rules lists no profile"}
	}
	return m
}

// SSHRulesLines are the review's lines of a lockssh instance's rules, by
// profile name.
func SSHRulesLines(n string, rules map[string]*LogRules) []string {
	names := make([]string, 0, len(rules))
	for p := range rules {
		names = append(names, p)
	}
	slices.Sort(names)
	out := make([]string, 0, len(names))
	for _, p := range names {
		out = append(out, rules[p].Line(n))
	}
	return out
}

func sshDir(state, inst string) string { return filepath.Join(state, "lockssh", inst) }

const sshRulesFile = "rules.json"

// writeSSHRules keeps the rules the last confirmed lox run applied to a
// lockssh instance (lox run --no-start reads them), host only.
func writeSSHRules(state, inst string, rules map[string]*LogRules) error {
	for _, d := range []string{filepath.Join(state, "lockssh"), sshDir(state, inst)} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(rules, "", "  ")
	return writeAtomic(filepath.Join(sshDir(state, inst), sshRulesFile), append(b, '\n'), 0o600)
}

// readSSHRules are the rules the last confirmed lox run applied to inst.
func readSSHRules(state, inst string) (map[string]*LogRules, error) {
	if err := checkPrivate(sshDir(state, inst)); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(sshDir(state, inst), sshRulesFile))
	if err != nil {
		return nil, err
	}
	var m map[string]*LogRules
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", sshRulesFile, err)
	}
	for p, r := range m {
		if r == nil || r.lockName() != "lockssh" {
			return nil, fmt.Errorf("%s: profile %q holds no lockssh rules", sshRulesFile, p)
		}
	}
	return m, nil
}

// AppliedSSHRules are the auto rules of each lockssh lock of c, by
// instance then profile, as the last confirmed lox run applied them. A
// lock with none applied has none here: lox run asks its tickets.
func AppliedSSHRules(state string, c *Config) map[string]map[string]*LogRules {
	out := map[string]map[string]*LogRules{}
	for _, n := range c.Instances() {
		k := Kinds[c.Locks[n].Type]
		if !k.Rules || k.Mounts {
			continue
		}
		if m, err := readSSHRules(state, n); err == nil {
			out[n] = m
		}
	}
	return out
}
