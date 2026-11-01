package loxadd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
	for _, fd := range fields {
		if done[fd.Key] || (fd.When != nil && !fd.When(answers)) {
			continue
		}
		done[fd.Key] = true
		if typed, ok := given[fd.Key]; ok {
			v, reason := Answer(fd, typed, answers)
			if reason != "" {
				return nil, errors.New(flagReason(fd.Key, reason))
			}
			answers[fd.Key] = v
			continue
		}
		if f.NonInteractive {
			if fd.Empty == "" && fd.Default == "" {
				return nil, fmt.Errorf("usage: --%s is required (lox add %s --non-interactive)", fd.Key, lock)
			}
			v, reason := Answer(fd, "", answers)
			if reason != "" {
				return nil, errors.New(flagReason(fd.Key, reason))
			}
			answers[fd.Key] = v
			continue
		}
		v, err := f.ask(fd, answers)
		if err != nil {
			return nil, err
		}
		answers[fd.Key] = v
	}
	return answers, nil
}

// ask prompts until the answer is accepted.
func (f *Form) ask(fd Field, a Answers) (string, error) {
	for {
		fmt.Fprint(f.Out, Prompt(fd))
		line, err := f.In.ReadString('\n')
		if err != nil && line == "" {
			if errors.Is(err, io.EOF) {
				return "", errors.New("no answer (end of input)")
			}
			return "", fmt.Errorf("reading the answer: %w", err)
		}
		v, reason := Answer(fd, strings.TrimSpace(line), a)
		if reason == "" {
			return v, nil
		}
		fmt.Fprintf(f.Out, "  %s\n", reason)
	}
}

// flagReason words a refusal for a flag: "port: ..." becomes "--port: ...".
func flagReason(key, reason string) string {
	if rest, ok := strings.CutPrefix(reason, key+": "); ok {
		reason = rest
	}
	return "--" + key + ": " + reason
}
