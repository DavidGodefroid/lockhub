package loxadd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// Steps are what applying one lock at once runs: its profile add, init
// claude, doctor, lox add into lockfamily.yaml, lox up with the review of
// this lock, then lox attach for the console's questions.
type Steps struct {
	// Root is the project (the launchers run there); File its
	// lockfamily.yaml; DraftPath where the answers are kept when nothing is
	// kept (a state file, never a secret in it).
	Root, File, DraftPath string
	Run                   loxinit.Runner
	Out                   io.Writer
	// Terminal: stdin is a terminal (lox up's review and lox attach need
	// one).
	Terminal bool
	// AllowedUIDs is the lock's allowed_uids (lea's uid, when lea runs the
	// agents).
	AllowedUIDs []int
	// PinImage is the lock's image, pinned by digest and verified: the
	// -vault variant when vault is true.
	PinImage func(ctx context.Context, lock string, vault bool) (string, error)
	// PinHub is the hub's image, for a lockfamily.yaml that does not exist
	// yet.
	PinHub func(ctx context.Context) (string, error)
	// Up is lox up with the short review of the lock focus.
	Up func(ctx context.Context, focus string) error
	// Attach is lox attach NAME: the policy approval, then the password or
	// the Vault token, at this terminal.
	Attach func(ctx context.Context, name string) error
	// ConsoleAlive reports the lock's console running.
	ConsoleAlive func(ctx context.Context, name string) bool
	// LeaRunning reports a lea container running for this project (nil:
	// none). Lock sockets are mounted when lea's container starts, so lea
	// gets a new lock at its next start.
	LeaRunning func(ctx context.Context) bool
}

// ErrNothingKept is a lock not applied: its profile and lockfamily.yaml
// are as they were before.
var ErrNothingKept = errors.New("nothing kept")

// rollbackError is the error of a rollback: its message is the fixed
// text, and it wraps the cause (a decline, an interrupt, a failed step,
// which was shown above), plus ErrNothingKept when the files are as
// before.
type rollbackError struct {
	msg  string
	errs []error
}

func (e *rollbackError) Error() string   { return e.msg }
func (e *rollbackError) Unwrap() []error { return e.errs }

// Snapshot is a file as it was before: its bytes, or its absence (and
// whether its directory was there).
type Snapshot struct {
	path    string
	data    []byte
	mode    os.FileMode
	existed bool
	dirWas  bool
}

// TakeSnapshot keeps the file at path as it is now.
func TakeSnapshot(path string) (Snapshot, error) {
	s := Snapshot{path: path}
	if _, err := os.Lstat(filepath.Dir(path)); err == nil {
		s.dirWas = true
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if !fi.Mode().IsRegular() {
		return s, fmt.Errorf("%s: not a regular file", path)
	}
	if s.data, err = os.ReadFile(path); err != nil {
		return s, err
	}
	s.mode, s.existed = fi.Mode().Perm(), true
	return s, nil
}

// Restore puts the file back byte for byte, or removes it (and the
// directory made for it, when empty) if it did not exist. It is plain
// file work: nothing in it waits on a context, so an interrupt cannot cut
// it short.
func (s Snapshot) Restore() error {
	if s.existed {
		return family.WriteFileMode(s.path, s.data, s.mode)
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !s.dirWas {
		// Only an empty directory goes: whatever else was made there stays.
		_ = os.Remove(filepath.Dir(s.path))
	}
	return nil
}

func (s *Steps) say(format string, a ...any) { fmt.Fprintf(s.Out, format+"\n", a...) }

// rel is path as shown to the human: relative to the project when inside.
func (s *Steps) rel(path string) string {
	r, err := filepath.Rel(s.Root, path)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return path
	}
	return r
}

// Apply applies l at once. An error, a decline or an interrupt before the
// console started restores the profile file and lockfamily.yaml as they
// were, keeps the answers as a draft and returns an error wrapping
// ErrNothingKept. init claude's files and the doctor's repairs are not
// undone. Once lox up started the console, nothing is rolled back.
func (s *Steps) Apply(ctx context.Context, l Lock, a Answers) error {
	cfg := filepath.Join(s.Root, "."+l.Type, "config.toml")
	var snaps []Snapshot
	for _, p := range []string{cfg, s.File} {
		sn, err := TakeSnapshot(p)
		if err != nil {
			return err
		}
		snaps = append(snaps, sn)
	}
	if err := s.declare(ctx, l); err != nil {
		return s.rollback(ctx, l, a, snaps, cfg, err)
	}
	// A Ctrl-C that lands after the last declare step succeeded: nothing
	// after it would notice (no lox up without a terminal).
	if err := ctx.Err(); err != nil {
		return s.rollback(ctx, l, a, snaps, cfg, err)
	}
	if !s.Terminal {
		s.say("lock %s declared: run lox up at a terminal to review and start it", l.Name)
		s.dropDraft()
		return nil
	}
	if err := s.Up(ctx, l.Name); err != nil {
		if ctx.Err() == nil && !errors.Is(err, family.ErrNotConfirmed) {
			s.say("lox up failed: %v", err)
		}
		return s.rollback(ctx, l, a, snaps, cfg, err)
	}
	s.dropDraft()
	if s.LeaRunning != nil && s.LeaRunning(context.WithoutCancel(ctx)) {
		s.say("lea gets lock %s at its next start: lea stop, then lea", l.Name)
	}
	if err := s.Attach(ctx, l.Name); err != nil {
		// Detaching (Ctrl-P Ctrl-Q) ends docker's attach with a non-zero
		// status too: a console still running was detached from.
		if s.ConsoleAlive(context.WithoutCancel(ctx), l.Name) {
			s.say("detached from %s", l.Name)
			return nil
		}
		return fmt.Errorf("lock %s is declared and its console stopped (above): for Vault, check the address and token (lox vault set --address URL, then lox up); else lox up, then lox attach %s", l.Name, l.Name)
	}
	return nil
}

// declare runs the steps before lox up: profile add, init claude, the
// doctor (advisory) and lox add (with the vault block when it is new).
// Each failure is shown before it is returned. A step cut short by an
// interrupt (a launcher killed, a pin stopped) is not a failure: the
// interrupt is returned, and nothing is shown.
func (s *Steps) declare(ctx context.Context, l Lock) error {
	o := loxinit.Classify(s.Run.Verb(ctx, s.Root, l.Type, l.ProfileArgs(s.Root)...))
	if err := ctx.Err(); err != nil {
		return err
	}
	switch {
	case o.Profile != nil:
		cred := ""
		if o.Profile.Credentials != "" {
			cred = " (credentials " + o.Profile.Credentials + ")"
		}
		s.say("profile add: profile %s written to %s%s", o.Profile.Profile, o.Profile.Config, cred)
	case o.Code == loxinit.CodeExists:
		s.say("profile add: profile %s is there already: kept as it is", l.Profile)
	case o.OK():
		s.say("profile add: done")
	default:
		s.say("profile add failed (%s): %s", o.Code, indent(o.Message))
		return errors.New("profile add failed")
	}
	o = loxinit.Classify(s.Run.Verb(ctx, s.Root, l.Type, "init", "claude"))
	if err := ctx.Err(); err != nil {
		return err
	}
	if !o.OK() {
		s.say("init claude failed (%s): %s", o.Code, indent(o.Message))
		return errors.New("init claude failed")
	}
	s.say("init claude: the agent's files written")
	s.doctor(ctx, l.Type)
	if err := ctx.Err(); err != nil {
		return err
	}
	vault := l.Credentials == CredVault
	image, err := s.PinImage(ctx, l.Type, vault)
	if err != nil {
		return s.failed(ctx, "image", err)
	}
	if _, err := os.Lstat(s.File); errors.Is(err, os.ErrNotExist) {
		hub, err := s.PinHub(ctx)
		if err != nil {
			return s.failed(ctx, "hub image", err)
		}
		if _, err := family.InitHub(s.File, hub); err != nil {
			return s.failed(ctx, "lox add", err)
		}
	}
	// The vault block first: a lock with vault: true needs it to be valid.
	// family's errors name the key (vault.address, vault.ca_file, a scrubbed
	// YAML line), never the value typed.
	if l.Vault != nil {
		if err := family.SetVault(s.File, *l.Vault); err != nil {
			return s.failed(ctx, "vault block", err)
		}
	}
	if err := family.Add(s.File, family.AddOptions{Type: l.Type, Name: l.Name, Image: image, Profile: l.Profile,
		AllowedUIDs: s.AllowedUIDs, Vault: vault}); err != nil {
		return s.failed(ctx, "lox add", err)
	}
	s.say("lock %s declared in %s", l.Name, s.rel(s.File))
	return nil
}

// failed shows a step's error and returns it; a step cut short by an
// interrupt is not shown, and the interrupt is returned.
func (s *Steps) failed(ctx context.Context, step string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	s.say("%s failed: %v", step, err)
	return err
}

// rollback restores the snapshots, saves the draft and returns the
// rollback error for cause (the interrupt, when there was one).
func (s *Steps) rollback(ctx context.Context, l Lock, a Answers, snaps []Snapshot, cfg string, cause error) error {
	errs := []error{cause}
	if cerr := ctx.Err(); cerr != nil && !errors.Is(cause, cerr) {
		errs = append(errs, cerr)
	}
	var bad []string
	for _, sn := range snaps {
		if err := sn.Restore(); err != nil {
			bad = append(bad, fmt.Sprintf("%s could not be restored (%v)", s.rel(sn.path), err))
		}
	}
	if s.DraftPath != "" {
		if err := SaveDraft(s.DraftPath, a); err != nil {
			s.say("the answers could not be kept for the next lox add %s: %v", l.Type, err)
		}
	}
	if len(bad) > 0 {
		// The files are not as before: not ErrNothingKept.
		return &rollbackError{msg: "not applied, and " + strings.Join(bad, ", and ") + ": check it before lox up", errs: errs}
	}
	msg := fmt.Sprintf("nothing kept: %s and %s are as before; lox add %s offers the same answers again", s.rel(cfg), s.rel(s.File), l.Type)
	if ctx.Err() != nil || errors.Is(cause, context.Canceled) {
		msg = "interrupted: " + msg
	}
	return &rollbackError{msg: msg, errs: append(errs, ErrNothingKept)}
}

func (s *Steps) dropDraft() {
	if s.DraftPath != "" {
		_ = os.Remove(s.DraftPath)
	}
}

// doctor runs the lock's doctor (--fix where lox add makes its repairs)
// and shows what it repaired and what still fails. It never stops lox add:
// before lox up the console is not running yet.
func (s *Steps) doctor(ctx context.Context, lock string) {
	args, note := loxinit.DoctorArgs(ctx, s.Run, s.Root, lock, nil)
	name := "doctor"
	if slices.Contains(args, "--fix") {
		name = "doctor --fix"
		if n := loxinit.FixNotice(lock); n != "" {
			s.say("%s", n)
		}
	}
	o := loxinit.Classify(s.Run.Verb(ctx, s.Root, lock, args...))
	if ctx.Err() != nil {
		return // interrupted: Apply rolls back, nothing to report
	}
	if note != "" {
		s.say("%s", note)
	}
	if o.Doctor == nil {
		if !o.OK() {
			s.say("%s could not check (%s): %s", name, o.Code, indent(o.Message))
		}
		return
	}
	for _, f := range o.Doctor.Fixed {
		s.say("%s: fixed %s", name, f)
	}
	var ok, warn int
	var fails []loxinit.Check
	for _, c := range o.Doctor.Checks {
		switch c.Status {
		case "ok":
			ok++
		case "warn":
			warn++
		default:
			fails = append(fails, c)
		}
	}
	s.say("%s: %d ok, %d warning(s), %d failed (advisory before lox up)", name, ok, warn, len(fails))
	for _, c := range fails {
		line := "  " + c.Check + ": " + c.Detail
		if c.Fix != "" {
			line += " (" + c.Fix + ")"
		}
		s.say("%s", line)
	}
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n  ") }

// SaveDraft keeps a's answers at path (0600, its directory 0700) for the
// next lox add of the same type. Only answers some question accepts are
// written: a value that embeds a password never is.
func SaveDraft(path string, a Answers) error {
	b, err := json.MarshalIndent(draftAnswers(a), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return family.WriteFileMode(path, append(b, '\n'), 0o600)
}

// LoadDraft reads the answers SaveDraft kept (none when there is no
// draft). An answer no question accepts (a password typed into an older
// draft, a file since removed) is dropped, so a default never shows it.
func LoadDraft(path string) (Answers, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Answers{}, nil
	}
	if err != nil {
		return nil, err
	}
	var a Answers
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("%s: not a lox add draft", path)
	}
	return draftAnswers(a), nil
}

// draftAnswers are the answers of a that a question of some lock accepts
// as they are, through Answer (the draft does not say its lock type: the
// file's name does, for its caller). Empty answers carry no default and
// are left out.
func draftAnswers(a Answers) Answers {
	out := Answers{}
	for k, v := range a {
		if v != "" && accepted(k, v, a) {
			out[k] = v
		}
	}
	return out
}

func accepted(key, v string, a Answers) bool {
	for _, lock := range []string{"locksql", "lockmq", "lockfile", "lockhttp"} {
		fs, err := Fields(lock, Defaults{})
		if err != nil {
			continue
		}
		for _, f := range fs {
			if f.Key != key {
				continue
			}
			if got, reason := Answer(f, v, a); reason == "" && got == v {
				return true
			}
		}
	}
	return false
}
