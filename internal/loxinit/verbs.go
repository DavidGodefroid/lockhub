package loxinit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// The JSON the launcher verbs print with --json (lockkit GUIDE.md §14).
// They mirror lockkit/verbs (v0.10.0): lockhub pins an older lockkit, and
// its compatibility build on the release before the pin has no verbs
// package, so the shapes are copied here, field for field.

// The codes of a VerbError.
const (
	CodeUsage  = "usage"
	CodeSecret = "secret"
	CodeExists = "exists"
	CodeFailed = "failed"
)

// VerbError is verbs.Error: a verb that failed.
type VerbError struct {
	Lock  string `json:"lock"`
	Code  string `json:"code"`
	Error string `json:"error"`
}

// VerbProfile is verbs.Profile: profile add wrote the profile.
type VerbProfile struct {
	Lock        string `json:"lock"`
	Profile     string `json:"profile"`
	Config      string `json:"config"`
	Production  bool   `json:"production"`
	Credentials string `json:"credentials,omitempty"`
}

// Check is verbs.Check, one line of a doctor.
type Check struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// VerbDoctor is verbs.Doctor.
type VerbDoctor struct {
	Lock   string   `json:"lock"`
	OK     bool     `json:"ok"`
	Fixed  []string `json:"fixed"`
	Checks []Check  `json:"checks"`
}

// Runner runs a launcher verb in dir, never at a terminal (stdin is
// empty), and returns its stdout, its stderr and its exit status.
type Runner interface {
	Verb(ctx context.Context, dir, name string, args ...string) (stdout, stderr []byte, code int, err error)
}

// ExecRunner runs the real launchers.
type ExecRunner struct{}

// Verb implements Runner.
func (ExecRunner) Verb(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Bytes(), errb.Bytes(), ee.ExitCode(), nil
	}
	if err != nil {
		return out.Bytes(), errb.Bytes(), -1, err
	}
	return out.Bytes(), errb.Bytes(), 0, nil
}

// Outcome is what lox init makes of one verb run.
type Outcome struct {
	// Code: "" on success, else a VerbError code (CodeFailed for a run
	// with no JSON).
	Code string
	// Message is the verb's error, or the end of its stderr when it gave
	// no JSON.
	Message string
	Profile *VerbProfile
	Doctor  *VerbDoctor
}

// OK reports success.
func (o Outcome) OK() bool { return o.Code == "" }

// lastJSON is the last line of out that is a JSON object: the verb's
// answer (human text may come before it, a docker pull on stderr).
func lastJSON(out []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "{") && json.Valid([]byte(l)) {
			return []byte(l)
		}
	}
	return nil
}

// tail is the last n lines of b, trimmed.
func tail(b []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// classify reads a verb run: its JSON answer when there is one (an Error
// has a code, a Doctor has checks, a Profile has a profile), else its exit
// status, a non-zero one with no JSON being CodeFailed with the stderr.
func classify(stdout, stderr []byte, code int, runErr error) Outcome {
	if runErr != nil {
		return Outcome{Code: CodeFailed, Message: runErr.Error()}
	}
	j := lastJSON(stdout)
	if j != nil {
		var keys map[string]json.RawMessage
		_ = json.Unmarshal(j, &keys)
		switch {
		case keys["code"] != nil:
			var e VerbError
			if json.Unmarshal(j, &e) == nil && e.Code != "" {
				return Outcome{Code: e.Code, Message: e.Error}
			}
		case keys["checks"] != nil:
			var d VerbDoctor
			if json.Unmarshal(j, &d) == nil {
				// A doctor's failed checks are its report, not a failed run.
				return Outcome{Doctor: &d}
			}
		case keys["profile"] != nil:
			var p VerbProfile
			if json.Unmarshal(j, &p) == nil && code == 0 {
				return Outcome{Profile: &p}
			}
		}
	}
	if code != 0 {
		msg := tail(stderr, 20)
		if msg == "" {
			msg = "exit status " + strconv.Itoa(code) + ", no output"
		}
		return Outcome{Code: CodeFailed, Message: msg}
	}
	return Outcome{}
}
