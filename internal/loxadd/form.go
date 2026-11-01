package loxadd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// Form asks the questions of `lox add`, one per key, on a terminal or from
// flags alone.
type Form struct {
	In  *bufio.Reader
	Out io.Writer
	// NonInteractive asks nothing: a flag or the default answers each field.
	NonInteractive bool
	// Hints are the data sources detected in the project, shown under the
	// header.
	Hints []loxinit.Source
}

// ErrUsage is a refusal of how lox add was called: a flag refused, a
// required one missing (--non-interactive), one that is no question.
// Such errors keep their own message and wrap ErrUsage.
var ErrUsage = errors.New("usage error")

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }
func (e usageError) Unwrap() error { return ErrUsage }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

var lockKinds = map[string]string{
	"locksql":  "database",
	"lockmq":   "broker",
	"lockfile": "file store",
	"lockhttp": "HTTP policy for lea's LockHTTP gate",
}

// Run asks each field in order. For a key, the first field whose When holds
// (given the answers so far) is the one asked. A key in given is a flag: it
// goes through Answer like a typed value and is never asked. The reasons
// name the key or flag, never the value.
func (f *Form) Run(lock string, fields []Field, given Answers) (Answers, error) {
	if !f.NonInteractive {
		fmt.Fprintf(f.Out, "lox add %s: one %s, applied at once (Ctrl-C before the review: nothing is kept)\n", lock, lockKinds[lock])
		loxinit.RenderHints(f.Out, f.Hints)
		fmt.Fprintln(f.Out)
	}
	answers := Answers{}
	done := map[string]bool{}
	var follow []Field // empty answers that took a DefaultFrom
	for _, fd := range fields {
		if done[fd.Key] || (fd.When != nil && !fd.When(answers)) {
			continue
		}
		done[fd.Key] = true
		if fd.DefaultFrom != nil {
			if v := fd.DefaultFrom(known(given, answers)); v != "" {
				fd.Default = v
			}
		}
		if typed, ok := given[fd.Key]; ok {
			v, reason := Answer(fd, typed, answers)
			if reason != "" {
				return nil, usagef("%s", flagReason(fd.Key, reason))
			}
			answers[fd.Key] = v
			if typed == "" && fd.DefaultFrom != nil {
				follow = append(follow, fd)
			}
			continue
		}
		if f.NonInteractive {
			if fd.Empty == "" && fd.Default == "" {
				return nil, usagef("usage: --%s is required (lox add %s --non-interactive)", fd.Key, lock)
			}
			v, reason := Answer(fd, "", answers)
			if reason != "" {
				return nil, usagef("%s", flagReason(fd.Key, reason))
			}
			answers[fd.Key] = v
			if fd.DefaultFrom != nil {
				follow = append(follow, fd)
			}
			continue
		}
		v, defaulted, err := f.ask(fd, answers)
		if err != nil {
			return nil, err
		}
		answers[fd.Key] = v
		if defaulted && fd.DefaultFrom != nil {
			follow = append(follow, fd)
		}
	}
	// A default computed before a later answer follows it now.
	for _, fd := range follow {
		if v := fd.DefaultFrom(answers); v != "" && v != answers[fd.Key] {
			if got, reason := Answer(fd, v, answers); reason == "" {
				answers[fd.Key] = got
			}
		}
	}
	var extra []string
	for k := range given {
		if !done[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		slices.Sort(extra)
		return nil, usagef("--%s: not a question of lox add %s with these answers", extra[0], lock)
	}
	return answers, nil
}

// ask prompts until the answer is accepted; defaulted is true when the
// empty answer took the default.
func (f *Form) ask(fd Field, a Answers) (v string, defaulted bool, err error) {
	for {
		fmt.Fprint(f.Out, Prompt(fd))
		line, err := f.In.ReadString('\n')
		if err != nil && line == "" {
			if errors.Is(err, io.EOF) {
				return "", false, errors.New("no answer (end of input)")
			}
			return "", false, fmt.Errorf("reading the answer: %w", err)
		}
		typed := strings.TrimSpace(line)
		v, reason := Answer(fd, typed, a)
		if reason == "" {
			return v, typed == "", nil
		}
		fmt.Fprintf(f.Out, "  %s\n", reason)
	}
}

// known are the answers so far over the flags given: what a DefaultFrom
// can use before the field a flag answers is reached.
func known(given, answers Answers) Answers {
	m := Answers{}
	for k, v := range given {
		m[k] = v
	}
	for k, v := range answers {
		m[k] = v
	}
	return m
}

// flagReason words a refusal for a flag: "port: ..." becomes "--port: ...".
func flagReason(key, reason string) string {
	if rest, ok := strings.CutPrefix(reason, key+": "); ok {
		reason = rest
	}
	return "--" + key + ": " + reason
}
