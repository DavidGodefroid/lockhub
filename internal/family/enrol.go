package family

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// lox live starts the stack with no human: it never answers a review.
// What it may start is what a human applied with lox run and then
// enrolled (lox live enrol), recorded here: the fingerprint the review
// uses (every line that can change what the hub or a lock accepts, the
// pinned images by digest among them), the images cosign verified at the
// enrolment (lox live verifies nothing online), and the production
// profiles whose names the human typed to enrol them. A configuration
// that differs from it in anything is not started: lox live says it
// needs an enrolment and waits.

// EnrolmentFile is the workspace's enrolment for lox live, in its state
// directory (0600, the user's).
const EnrolmentFile = "live-enrolment.json"

// Enrolment is what a human enrolled for lox live.
type Enrolment struct {
	Version int `json:"version"`
	// Fingerprint is Applied.Fingerprint when it was enrolled.
	Fingerprint string `json:"fingerprint"`
	// Images are the pinned images (by digest) cosign verified at the
	// enrolment, each with the release its signature names ("" unknown).
	Images map[string]string `json:"images"`
	// Production are the locks that serve a production profile, by
	// instance, with the profile name the human typed to enrol it.
	Production map[string]string `json:"production,omitempty"`
	At         time.Time         `json:"at"`
	By         string            `json:"by,omitempty"`
}

// Reviewed is what a probe (Up.Probe) found applied and unchanged: what
// lox live enrol records.
type Reviewed struct {
	Fingerprint string
	Images      map[string]string
	// Production: the instances whose profile is a production one, with
	// its name.
	Production map[string]string
}

// NewEnrolment is the enrolment of r, by the human by at at.
func NewEnrolment(r *Reviewed, by string, at time.Time) *Enrolment {
	return &Enrolment{Version: 1, Fingerprint: r.Fingerprint, Images: maps.Clone(r.Images), Production: maps.Clone(r.Production),
		At: at.UTC().Truncate(time.Second), By: by}
}

// WriteEnrolment records e in the state directory state.
func WriteEnrolment(state string, e *Enrolment) error {
	if err := checkPrivate(state); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(e, "", "  ")
	return writeAtomic(filepath.Join(state, EnrolmentFile), append(b, '\n'), 0o600)
}

// ReadEnrolment is the workspace's enrolment (nil: none). One that is not
// a regular file of the user's that nobody else reads or writes, in a
// private state directory, is refused: it says what starts unattended.
func ReadEnrolment(state string) (*Enrolment, error) {
	p := filepath.Join(state, EnrolmentFile)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(state); err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !ownedByMe(fi) || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: want a regular file of yours, mode 0600 (lox live enrol writes it)", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var e Enrolment
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("%s: %w", EnrolmentFile, err)
	}
	if e.Version != 1 || e.Fingerprint == "" {
		return nil, fmt.Errorf("%s: not an enrolment of this lox (version %d)", EnrolmentFile, e.Version)
	}
	return &e, nil
}

// NeedsEnrolmentError is an unattended start (Up.Enrolled) that applied
// nothing: what would start is not what a human enrolled.
type NeedsEnrolmentError struct{ Why string }

func (e *NeedsEnrolmentError) Error() string {
	return "needs enrolment: " + e.Why + " (review and apply with lox run at a terminal, then lox live enrol)"
}

func needsEnrolment(format string, args ...any) error {
	return &NeedsEnrolmentError{Why: fmt.Sprintf(format, args...)}
}

// shortDiff is a diff in a few words, for a log line.
func shortDiff(d []string) string {
	const max = 4
	if len(d) > max {
		return strings.Join(d[:max], "; ") + fmt.Sprintf("; and %d more", len(d)-max)
	}
	return strings.Join(d, "; ")
}
