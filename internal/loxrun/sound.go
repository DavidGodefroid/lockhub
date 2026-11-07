package loxrun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Sound is how lox run calls the human when a question waits: a sound
// file played through the platform's player, distinct from lea's
// attention sound, so the human knows by ear which tool asks. Auto
// traffic never sounds.
type Sound struct {
	// Question is played when a question card appears; Production when
	// it is a production ticket ("": Question's). Question "" rings the
	// terminal bell instead.
	Question, Production string
	// Remind plays it again while a question waits, every Remind (0: once).
	Remind time.Duration
	// Play plays a file without waiting for it; nil (no player found) or
	// an error rings the terminal bell instead.
	Play func(file string) error
	// Player is the player command Play runs ("" none).
	Player string
	// Notify, if set, shows a desktop notification for a new question:
	// its lock and kind only, never the request.
	Notify func(lock, kind string)
	// Off: silenced (LOX_SOUND=0); the s key toggles it for the session.
	Off bool
}

// Default sound files: lea calls with message-new-instant.oga, lox run
// with these.
const (
	DefaultQuestionSound   = "/usr/share/sounds/freedesktop/stereo/window-question.oga"
	DefaultProductionSound = "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"
	macQuestionSound       = "/System/Library/Sounds/Glass.aiff"
	macProductionSound     = "/System/Library/Sounds/Sosumi.aiff"
	DefaultRemind          = 60 * time.Second
)

// Host is what SoundFromEnv needs of the machine (os, exec in lox).
type Host struct {
	GOOS     string
	LookPath func(string) (string, error)
	Exists   func(path string) bool
	// Start starts a command without waiting for it.
	Start func(name string, args ...string) error
}

// SystemHost is the machine lox runs on.
func SystemHost(goos string) Host {
	return Host{GOOS: goos, LookPath: exec.LookPath,
		Exists: func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.Mode().IsRegular() },
		Start: func(name string, args ...string) error {
			cmd := exec.Command(name, args...)
			if err := cmd.Start(); err != nil {
				return err
			}
			go cmd.Wait() //nolint:errcheck // a sound that fails is only not heard
			return nil
		}}
}

// SoundFromEnv reads lox run's sound settings: LOX_SOUND=0 (off),
// LOX_SOUND_QUESTION=<file>|0, LOX_SOUND_PRODUCTION=<file>|0,
// LOX_SOUND_REMIND=<duration> (60s; 0 once), LOX_NOTIFY=1 (a desktop
// notification). A file set to 0, or one that does not exist, rings the
// terminal bell. The warnings are settings it could not use (their
// defaults are kept).
func SoundFromEnv(lookup func(string) (string, bool), h Host) (*Sound, []string) {
	var warn []string
	s := &Sound{Remind: DefaultRemind}
	if v, ok := lookup("LOX_SOUND"); ok && isOff(v) {
		s.Off = true
	}
	q, p := DefaultQuestionSound, DefaultProductionSound
	if h.GOOS == "darwin" {
		q, p = macQuestionSound, macProductionSound
	}
	file := func(name, def string) string {
		v, ok := lookup(name)
		if !ok || strings.TrimSpace(v) == "" {
			if h.Exists(def) {
				return def
			}
			return ""
		}
		v = strings.TrimSpace(v)
		if isOff(v) {
			return ""
		}
		if !h.Exists(v) {
			warn = append(warn, fmt.Sprintf("%s: no file %s: not played", name, v))
			return ""
		}
		return v
	}
	s.Question, s.Production = file("LOX_SOUND_QUESTION", q), file("LOX_SOUND_PRODUCTION", p)
	if v, ok := lookup("LOX_SOUND_REMIND"); ok && strings.TrimSpace(v) != "" {
		d, err := parseRemind(v)
		if err != nil {
			warn = append(warn, fmt.Sprintf("LOX_SOUND_REMIND: %v: every %s", err, DefaultRemind))
		} else {
			s.Remind = d
		}
	}
	players := []string{"pw-play", "paplay", "aplay"}
	if h.GOOS == "darwin" {
		players = []string{"afplay"}
	}
	for _, name := range players {
		if path, err := h.LookPath(name); err == nil {
			s.Player = name
			s.Play = func(file string) error {
				if name == "aplay" && !strings.EqualFold(filepath.Ext(file), ".wav") {
					return errors.New("aplay plays WAV files only")
				}
				return h.Start(path, file)
			}
			break
		}
	}
	if v, ok := lookup("LOX_NOTIFY"); ok && !isOff(v) && strings.TrimSpace(v) != "" {
		s.Notify = notifier(h)
	}
	return s, warn
}

func isOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "no", "false":
		return true
	}
	return false
}

// parseRemind reads a duration (30s, 2m) or a number of seconds.
func parseRemind(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	d, err := time.ParseDuration(v)
	if err != nil {
		n, nerr := strconv.Atoi(v)
		if nerr != nil {
			return 0, fmt.Errorf("%q is not a duration", v)
		}
		d = time.Duration(n) * time.Second
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is negative", v)
	}
	return d, nil
}

// notifier shows a desktop notification (notify-send, osascript), nil
// when there is none.
func notifier(h Host) func(lock, kind string) {
	text := func(lock, kind string) string {
		return fmt.Sprintf("%s: a %s waits for your decision", plainWord(lock), plainWord(kind))
	}
	if h.GOOS == "darwin" {
		path, err := h.LookPath("osascript")
		if err != nil {
			return nil
		}
		return func(lock, kind string) {
			_ = h.Start(path, "-e", `display notification "`+text(lock, kind)+`" with title "lox run"`)
		}
	}
	path, err := h.LookPath("notify-send")
	if err != nil {
		return nil
	}
	return func(lock, kind string) { _ = h.Start(path, "-a", "lox run", "lox run", text(lock, kind)) }
}

// plainWord keeps a name to letters, digits and . _ - (it goes into a
// script for osascript).
func plainWord(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "?"
	}
	return b.String()
}

// call calls the human for the questions waiting: the production sound
// when one of them is a production ticket. A new question (fresh) also
// shows the desktop notification.
func (st *state) call(fresh *tracked) {
	st.calledAt = st.s.now()
	snd := st.s.Sound
	if snd == nil {
		st.bell = true
		return
	}
	if st.muted {
		return
	}
	file := snd.Question
	for _, t := range st.cards {
		if t.card.Production && snd.Production != "" {
			file = snd.Production
		}
	}
	if file == "" || snd.Play == nil || snd.Play(file) != nil {
		st.bell = true
	}
	if fresh != nil && snd.Notify != nil {
		snd.Notify(fresh.card.Lock, string(fresh.card.Kind))
	}
}

// remind calls the human again while a question waits, every Remind.
func (st *state) remind() {
	snd := st.s.Sound
	if snd == nil || snd.Remind <= 0 || len(st.cards) == 0 || st.muted {
		return
	}
	if st.s.now().Sub(st.calledAt) >= snd.Remind {
		st.call(nil)
	}
}

// toggleSound is the s key.
func (st *state) toggleSound() {
	if st.s.Sound == nil {
		return
	}
	st.muted = !st.muted
	if st.muted {
		st.setFlash("sound off for this session (s turns it on)")
	} else {
		st.setFlash("sound on: a question plays a sound")
	}
}
