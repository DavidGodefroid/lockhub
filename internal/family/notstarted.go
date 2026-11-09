package family

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
)

// A lock lox run cannot start (a mount plan it refuses) is left out of
// what it applies, with its reason: the other locks start and are served
// (lockhub#177). The reasons are kept host only, for lox run's header and
// lox doctor.

// NotStartedFile holds the locks the last confirmed lox run did not
// start, by instance, with their reason (in the state directory).
const NotStartedFile = "not-started.json"

// notStartedLine is the summary line of a lock not started: reviewed, so
// that the fixed lock's start is a change the next lox run shows.
func notStartedLine(n, why string) string {
	return fmt.Sprintf("lock %s not started: %s", n, why)
}

var notStartedRe = regexp.MustCompile(`^lock \S+ not started: `)

// without is c without the locks named in skip (c itself unchanged).
func (c *Config) without(skip map[string]string) *Config {
	cc := *c
	cc.Locks = maps.Clone(c.Locks)
	for n := range skip {
		delete(cc.Locks, n)
	}
	return &cc
}

// writeNotStarted keeps the locks not started (none: the file goes).
func writeNotStarted(state string, ns map[string]string) error {
	p := filepath.Join(state, NotStartedFile)
	if len(ns) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, _ := json.MarshalIndent(ns, "", "  ")
	return writeAtomic(p, append(b, '\n'), 0o600)
}

// ReadNotStarted is the locks the last confirmed lox run did not start,
// with their reason (nil: none, or nothing applied).
func ReadNotStarted(state string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(state, NotStartedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ns map[string]string
	if err := json.Unmarshal(b, &ns); err != nil {
		return nil, fmt.Errorf("%s: %w", NotStartedFile, err)
	}
	return ns, nil
}
