package family

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A locklog profile's auto rules (locklog#126): for each action that
// becomes a ticket (read: an approved scan, risk read; unmask and lookup:
// risk read-pii), what lox run's auto mode does with it: auto, ask or
// deny. lox run reads them with `locklog profile rules --json`, run in
// the lock's image on the reviewed copy (as `locklog mounts`), shows them
// in the review and applies them in its engine. The console enforces
// its own side whatever lox run does: a deny is refused before any
// ticket, and the ticket of an ask is signed never-auto.

// LogRuleActions are locklog's auto-rule actions, in the order the review
// shows them.
var LogRuleActions = []string{"read", "unmask", "lookup"}

// maxRules bounds the output of locklog profile rules.
const maxRules = 64 << 10

// LogRules are the auto rules lox run applies to a locklog or lockssh
// lock's profile, by action (LogRuleActions, SSHRuleActions): "auto",
// "ask" or "deny". Unknown says why they could not be read: lox run then
// asks every ticket.
type LogRules struct {
	// Lock is the lock type ("": locklog, as lox run wrote them first).
	Lock string `json:"lock,omitempty"`
	// Profile is the profile the console serves (the plan's).
	Profile string            `json:"profile"`
	Rules   map[string]string `json:"rules,omitempty"`
	Unknown string            `json:"unknown,omitempty"`
}

// ruleValue reports a value lox run knows.
func ruleValue(v string) bool { return v == "auto" || v == "ask" || v == "deny" }

// ruleRank orders the values from the strictest.
func ruleRank(v string) int { return slices.Index([]string{"deny", "ask", "auto"}, v) }

// stricter is the stricter of two values.
func stricter(a, b string) string {
	if ruleRank(b) < ruleRank(a) {
		return b
	}
	return a
}

// Get is the value of action a: "ask" when the rules are unknown or do
// not name it (lox run asks; the console's own default is ask too).
func (r *LogRules) Get(a string) string {
	if r == nil || r.Unknown != "" {
		return "ask"
	}
	if v := r.Rules[a]; ruleValue(v) {
		return v
	}
	return "ask"
}

// DeriveLogRules reads the output of `locklog profile rules --json` for
// profile: its effective rules, the stricter of each action's approved
// and file value when the console's approved policy and the reviewed file
// differ (pending review). Any output it cannot read fully gives rules
// that are unknown: every ticket asked (fail closed), never an error that
// keeps the stack from starting.
func DeriveLogRules(out []byte, profile string) *LogRules {
	return deriveRules(out, "locklog", LogRuleActions, profile)
}

// deriveRules reads `<lock> profile rules --json` for profile, its
// actions each auto, ask or deny (DeriveLogRules).
func deriveRules(out []byte, lock string, actions []string, profile string) *LogRules {
	tag := ""
	if lock != "locklog" {
		tag = lock
	}
	unknown := func(why string) *LogRules { return &LogRules{Lock: tag, Profile: profile, Unknown: why} }
	if len(out) > maxRules {
		return unknown(lock + " profile rules: output too long")
	}
	var o struct {
		Lock     string `json:"lock"`
		Profiles []struct {
			Profile       string            `json:"profile"`
			Rules         map[string]string `json:"rules"`
			PendingReview bool              `json:"pending_review"`
			FileRules     map[string]string `json:"file_rules"`
		} `json:"profiles"`
	}
	line := lastJSONLine(out)
	if line == nil || json.Unmarshal(line, &o) != nil || o.Lock != lock {
		return unknown(lock + " profile rules gave no answer lox run reads")
	}
	for _, p := range o.Profiles {
		if p.Profile != profile {
			continue
		}
		r := &LogRules{Lock: tag, Profile: profile, Rules: map[string]string{}}
		for _, a := range actions {
			v := p.Rules[a]
			if !ruleValue(v) {
				return unknown(lock + " profile rules: no auto, ask or deny for " + a)
			}
			if p.PendingReview {
				if fv := p.FileRules[a]; ruleValue(fv) {
					v = stricter(v, fv)
				}
			}
			r.Rules[a] = v
		}
		return r
	}
	return unknown(lock + " profile rules does not list profile " + profile)
}

// lockName is the rules' lock type.
func (r *LogRules) lockName() string {
	if r.Lock == "" {
		return "locklog"
	}
	return r.Lock
}

// actions are the rules' actions, in the review's order.
func (r *LogRules) actions() []string {
	if r.lockName() == "lockssh" {
		return SSHRuleActions
	}
	return LogRuleActions
}

// lastJSONLine is the last line of out that is a JSON object.
func lastJSONLine(out []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "{") && json.Valid([]byte(l)) {
			return []byte(l)
		}
	}
	return nil
}

// Line is the rules' review line for instance n.
func (r *LogRules) Line(n string) string {
	if r == nil {
		return fmt.Sprintf("lock %s auto rules: unknown (none read): lox run asks every ticket", n)
	}
	pre := fmt.Sprintf("lock %s auto rules of profile %s: ", n, r.Profile)
	if r.Unknown != "" {
		return pre + "unknown (" + r.Unknown + "): lox run asks every ticket"
	}
	acts := r.actions()
	parts := make([]string, len(acts))
	for i, a := range acts {
		parts[i] = a + " " + r.Get(a)
	}
	return pre + strings.Join(parts, " · ") + " (" + r.lockName() + " profile rules, on the reviewed copy)"
}

// ErrNoLogRules is a locklog instance with no applied plan, hence no
// rules lox run can apply: it asks every ticket.
var ErrNoLogRules = errors.New("no applied plan with auto rules: run lox run")

// AppliedLogRules are the auto rules of each locklog lock of c, by
// instance, as the last confirmed lox run applied them (lox run
// --no-start reads them). A lock with no applied plan, or one from before
// the rules were read, has unknown rules: lox run asks its tickets.
func AppliedLogRules(state string, c *Config) map[string]*LogRules {
	out := map[string]*LogRules{}
	for _, n := range c.Instances() {
		if !Kinds[c.Locks[n].Type].Mounts {
			continue
		}
		p, err := ReadLogPlan(state, n)
		if err != nil || p.Rules == nil {
			out[n] = &LogRules{Unknown: ErrNoLogRules.Error()}
			continue
		}
		out[n] = p.Rules
	}
	return out
}
