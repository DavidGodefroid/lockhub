package loxinit

import (
	"errors"
	"strings"
	"testing"
)

// The JSON shapes are lockkit/verbs' (GUIDE.md §14): a verb prints one
// line of JSON on stdout, after any human text; lox init reads the
// reason from it, not from the exit status.
func TestClassify(t *testing.T) {
	for _, c := range []struct {
		name           string
		stdout, stderr string
		code           int
		err            error
		want           string // Outcome code ("" success)
		profile        bool
		doctor         bool
		msg            string
	}{
		{name: "profile written, human text first", stdout: "Profile shop written (no secret).\n" + `{"lock":"locksql","profile":"shop","config":"/w/.locksql/config.toml","production":false,"credentials":"ask"}` + "\n", profile: true},
		{name: "exists", stdout: `{"lock":"lockmq","code":"exists","error":"--profile: a profile of that name is already in the project's config; nothing written"}`, code: 3, want: CodeExists},
		{name: "usage", stdout: `{"lock":"lockmq","code":"usage","error":"localhost is the console's own container"}`, code: 3, want: CodeUsage, msg: "localhost is the console's own container"},
		{name: "secret", stdout: `{"lock":"locksql","code":"secret","error":"--password: a secret is never given on the command line"}`, code: 64, want: CodeSecret},
		{name: "doctor failing is a report", stdout: `{"lock":"locksql","ok":false,"fixed":[],"checks":[{"check":"client access","status":"fail","detail":"x"}]}`, code: 1, doctor: true},
		{name: "no JSON, non-zero: failed with stderr", stderr: "docker: Error response from daemon: manifest unknown\n", code: 125, want: CodeFailed, msg: "manifest unknown"},
		{name: "no JSON, no output", code: 2, want: CodeFailed, msg: "exit status 2, no output"},
		{name: "not started", err: errors.New(`exec: "locksql": executable file not found in $PATH`), want: CodeFailed, msg: "not found"},
		{name: "init: no JSON, exit 0", stdout: "created .mcp.json\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := Classify([]byte(c.stdout), []byte(c.stderr), c.code, c.err)
			if o.Code != c.want || (o.Profile != nil) != c.profile || (o.Doctor != nil) != c.doctor {
				t.Fatalf("got %+v", o)
			}
			if c.msg != "" && !strings.Contains(o.Message, c.msg) {
				t.Errorf("message %q, want %q in it", o.Message, c.msg)
			}
		})
	}
}
