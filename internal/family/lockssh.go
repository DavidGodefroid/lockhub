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

// RuleActions are the auto-rule actions of each lock type whose profile
// rules lox run reads (`<type> profile rules --json`), in the order the
// review shows them: locklog's and lockssh's (LogRuleActions,
// SSHRuleActions), locksql's (its config.AutoActions, locksql#185) and
// lockmq's (its config.AutoActions, lockmq#49).
var RuleActions = map[string][]string{
	"locklog": LogRuleActions,
	"lockssh": SSHRuleActions,
	"locksql": {"connect", "read", "write", "ddl", "unmask"},
	"lockmq":  {"connect", "list", "read", "peek", "get", "publish", "purge", "delete"},
}

// asksUnknown reports a lock type whose tickets lox run asks, every one,
// when its rules are unknown (locklog, lockssh: the engine's defaults
// would approve their reads). The others keep the engine's defaults, as
// before lox run read their rules.
func asksUnknown(typ string) bool { return typ == "locklog" || typ == "lockssh" }

// UnknownEffect is what lox run does with the tickets of a lock of type
// typ whose rules it could not read.
func UnknownEffect(typ string) string {
	if asksUnknown(typ) {
		return "lox run asks every ticket of this lock"
	}
	return "lox run keeps its defaults for this lock (the console enforces its own rules)"
}

// DeriveProfileRules reads the output of `<typ> profile rules --json`:
// the rules of profile, or of every profile it lists when the lock names
// none (the human picks one at the console), by profile. Output it cannot
// read gives one entry, "", whose rules are unknown (UnknownEffect; fail
// closed for the types whose reads the defaults would approve).
func DeriveProfileRules(out []byte, typ, profile string) map[string]*LogRules {
	acts := RuleActions[typ]
	if profile != "" {
		return map[string]*LogRules{profile: deriveRules(out, typ, acts, profile)}
	}
	var o struct {
		Lock     string `json:"lock"`
		Profiles []struct {
			Profile string `json:"profile"`
		} `json:"profiles"`
	}
	line := lastJSONLine(out)
	if len(out) > maxRules || line == nil || json.Unmarshal(line, &o) != nil || o.Lock != typ {
		return map[string]*LogRules{"": deriveRules(out, typ, acts, "")}
	}
	m := map[string]*LogRules{}
	for _, p := range o.Profiles {
		if p.Profile != "" {
			m[p.Profile] = deriveRules(out, typ, acts, p.Profile)
		}
	}
	if len(m) == 0 {
		m[""] = &LogRules{Lock: typ, Unknown: typ + " profile rules lists no profile"}
	}
	return m
}

// ProfileRulesLines are the review's lines of an instance's rules, by
// profile name.
func ProfileRulesLines(n string, rules map[string]*LogRules) []string {
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

func rulesDir(state, typ, inst string) string { return filepath.Join(state, typ, inst) }

const profileRulesFile = "rules.json"

// writeProfileRules keeps the rules the last confirmed lox run applied to
// an instance of type typ (lox run --no-start and lox live read them),
// host only.
func writeProfileRules(state, typ, inst string, rules map[string]*LogRules) error {
	for _, d := range []string{filepath.Join(state, typ), rulesDir(state, typ, inst)} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(rules, "", "  ")
	return writeAtomic(filepath.Join(rulesDir(state, typ, inst), profileRulesFile), append(b, '\n'), 0o600)
}

// readProfileRules are the rules the last confirmed lox run applied to
// inst, of type typ.
func readProfileRules(state, typ, inst string) (map[string]*LogRules, error) {
	if err := checkPrivate(rulesDir(state, typ, inst)); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(rulesDir(state, typ, inst), profileRulesFile))
	if err != nil {
		return nil, err
	}
	var m map[string]*LogRules
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", profileRulesFile, err)
	}
	for p, r := range m {
		if r == nil || r.lockName() != typ {
			return nil, fmt.Errorf("%s: profile %q holds no %s rules", profileRulesFile, p, typ)
		}
	}
	return m, nil
}

// AppliedProfileRules are the auto rules of each lock of c whose rules
// lox run reads from its reviewed copy (lockssh, locksql, lockmq;
// locklog's are AppliedLogRules), by instance then profile, as the last
// confirmed lox run applied them. A lock with none applied has none
// here: lox run asks a lockssh lock's tickets, and keeps its defaults for
// the others.
func AppliedProfileRules(state string, c *Config) map[string]map[string]*LogRules {
	out := map[string]map[string]*LogRules{}
	for _, n := range c.Instances() {
		t := c.Locks[n].Type
		k := Kinds[t]
		if !k.Rules || k.Mounts {
			continue
		}
		if m, err := readProfileRules(state, t, n); err == nil {
			out[n] = m
		}
	}
	return out
}
