package loxrun

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// fakePlayer records the files played.
type fakePlayer struct {
	mu    sync.Mutex
	files []string
	err   error
}

func (p *fakePlayer) Play(file string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.files = append(p.files, file)
	return p.err
}

func (p *fakePlayer) played() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.files)
}

// A question card plays the question sound, a production one the
// production sound; auto-approved traffic plays nothing, and no bell
// rings when the sound played.
func TestSoundWhenToPlay(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	p := &fakePlayer{}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		s.Sound = &Sound{Question: "q.oga", Production: "p.oga", Play: p.Play}
	})
	sel := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT id FROM orders", nil)
	hub.push(sel)
	if e := h.wait(EvDecided, sel.ID); e.Rule == "" {
		t.Fatalf("SELECT not auto: %+v", e)
	}
	if got := p.played(); len(got) != 0 {
		t.Fatalf("auto traffic played %v", got)
	}
	upd := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = true", nil)
	hub.push(upd)
	h.wait(EvQuestion, upd.ID)
	if got := p.played(); !slices.Equal(got, []string{"q.oga"}) {
		t.Fatalf("question played %v, want [q.oga]", got)
	}
	h.keys <- R('n')
	h.wait(EvDecided, upd.ID)
	prod := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "live", "DELETE FROM orders", func(tk *ticket.Ticket) { tk.Flags.Production = true })
	hub.push(prod)
	h.wait(EvQuestion, prod.ID)
	if got := p.played(); !slices.Equal(got, []string{"q.oga", "p.oga"}) {
		t.Fatalf("production played %v, want [q.oga p.oga]", got)
	}
	if strings.Contains(h.output(), "\a") {
		t.Error("the bell rang although the sound played")
	}
}

// No player, a player that fails, or no file: the terminal bell.
func TestSoundBellFallback(t *testing.T) {
	failing := &fakePlayer{err: errors.New("no such player")}
	for name, snd := range map[string]*Sound{
		"no player": {Question: "q.oga"},
		"fails":     {Question: "q.oga", Play: failing.Play},
		"no file":   {Play: (&fakePlayer{}).Play},
	} {
		t.Run(name, func(t *testing.T) {
			lk := newLockKey()
			hub := newFakeHub()
			h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) { s.Sound = snd })
			upd := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = true", nil)
			hub.push(upd)
			h.wait(EvQuestion, upd.ID)
			h.keys <- R('n') // the frame (and its bell) is written before the next key is read
			h.wait(EvDecided, upd.ID)
			if n := strings.Count(h.output(), "\a"); n != 1 {
				t.Errorf("%d bells, want 1", n)
			}
		})
	}
}

// LOX_SOUND=0 silences the sound and the bell; s turns it on and off
// for the session, and the header shows it.
func TestSoundOffAndToggle(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	p := &fakePlayer{}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		s.Sound = &Sound{Question: "q.oga", Play: p.Play, Off: true}
	})
	upd := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = true", nil)
	hub.push(upd)
	h.wait(EvQuestion, upd.ID)
	h.keys <- R('n')
	h.wait(EvDecided, upd.ID)
	if got := p.played(); len(got) != 0 {
		t.Fatalf("LOX_SOUND=0 played %v", got)
	}
	if strings.Contains(h.output(), "\a") {
		t.Error("LOX_SOUND=0 rang the bell")
	}
	h.keys <- R('s')
	waitOutput(t, h, "sound on")
	two := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = false", nil)
	hub.push(two)
	h.wait(EvQuestion, two.ID)
	if got := p.played(); !slices.Equal(got, []string{"q.oga"}) {
		t.Fatalf("after s: played %v, want [q.oga]", got)
	}
	h.keys <- R('n')
	h.wait(EvDecided, two.ID)
	h.keys <- R('s')
	waitOutput(t, h, "sound off")
	three := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = NULL", nil)
	hub.push(three)
	h.wait(EvQuestion, three.ID)
	if got := p.played(); len(got) != 1 {
		t.Fatalf("s again did not silence it: played %v", got)
	}
}

func TestSoundHeader(t *testing.T) {
	st := Style{Unicode: true}
	for state, want := range map[SoundState]string{SoundNone: "", SoundOn: "🔔", SoundOff: "🔕"} {
		got := header(View{Sound: state, HubOK: true}, 100, st)[0].render(false)
		if want == "" {
			if strings.Contains(got, "🔔") || strings.Contains(got, "🔕") {
				t.Errorf("no sound configured: header %q", got)
			}
			continue
		}
		if !strings.Contains(got, want) {
			t.Errorf("sound %d: header %q lacks %s", state, got, want)
		}
		if w := strWidth(got); w > 100 {
			t.Errorf("header is %d columns wide", w)
		}
	}
	if got := header(View{Sound: SoundOff}, 100, Style{})[0].render(false); !strings.Contains(got, "sound off") {
		t.Errorf("ASCII header %q", got)
	}
}

// While a question waits, the sound plays again every Remind, and stops
// once nothing waits; Remind 0 plays it once. A new question shows the
// desktop notification (lock and kind only); a reminder does not.
func TestSoundReminder(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := &fakePlayer{}
	var notes []string
	snd := &Sound{Question: "q.oga", Remind: time.Minute, Play: p.Play,
		Notify: func(lock, kind string) { notes = append(notes, lock+" "+kind) }}
	st := newState(&Session{Out: &strings.Builder{}, Now: func() time.Time { return now }, Sound: snd, IdleConn: time.Hour})
	tr := &tracked{card: &Card{Lock: "locksql", Kind: ticket.KindWrite, Body: []string{"UPDATE secret"}}}
	st.cards = append(st.cards, tr)
	st.call(tr)
	now = now.Add(59 * time.Second)
	st.onTick()
	if got := p.played(); len(got) != 1 {
		t.Fatalf("before the reminder: played %v", got)
	}
	now = now.Add(time.Second)
	st.onTick()
	now = now.Add(time.Minute)
	st.onTick()
	if got := p.played(); len(got) != 3 {
		t.Fatalf("reminders: played %v, want 3", got)
	}
	if !slices.Equal(notes, []string{"locksql write"}) {
		t.Errorf("notifications %q, want one with the lock and kind", notes)
	}
	st.removeCard(tr) // answered
	now = now.Add(5 * time.Minute)
	st.onTick()
	if got := p.played(); len(got) != 3 {
		t.Fatalf("after the answer: played %v", got)
	}

	snd.Remind = 0
	tr.card = &Card{Lock: "locksql", Kind: ticket.KindWrite}
	st.cards = append(st.cards, tr)
	st.call(tr)
	now = now.Add(time.Hour)
	st.onTick()
	if got := p.played(); len(got) != 4 {
		t.Fatalf("Remind 0: played %v, want once", got)
	}
}

type fakeHost struct {
	files   map[string]bool
	bins    map[string]bool
	started [][]string
}

func (f *fakeHost) host(goos string) Host {
	return Host{GOOS: goos,
		LookPath: func(n string) (string, error) {
			if f.bins[n] {
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		},
		Exists: func(p string) bool { return f.files[p] },
		Start: func(name string, args ...string) error {
			f.started = append(f.started, append([]string{name}, args...))
			return nil
		}}
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// leaAttention is lea's attention sound (LEA_SOUND_ATTENTION's default).
const leaAttention = "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga"

func TestSoundSettings(t *testing.T) {
	if DefaultQuestionSound == leaAttention || DefaultProductionSound == leaAttention || DefaultQuestionSound == DefaultProductionSound {
		t.Fatal("lox run's default sounds must differ from lea's and from each other")
	}
	f := &fakeHost{files: map[string]bool{DefaultQuestionSound: true, DefaultProductionSound: true, "/tmp/ding.wav": true},
		bins: map[string]bool{"paplay": true, "aplay": true, "notify-send": true}}

	s, warn := SoundFromEnv(env(nil), f.host("linux"))
	if len(warn) != 0 || s.Off || s.Question != DefaultQuestionSound || s.Production != DefaultProductionSound ||
		s.Remind != DefaultRemind || s.Player != "paplay" || s.Notify != nil {
		t.Fatalf("defaults: %+v %v", s, warn)
	}
	if err := s.Play(s.Question); err != nil || !slices.Equal(f.started[0], []string{"/usr/bin/paplay", DefaultQuestionSound}) {
		t.Fatalf("play: %v %v", err, f.started)
	}

	s, warn = SoundFromEnv(env(map[string]string{"LOX_SOUND": "0", "LOX_SOUND_QUESTION": "/tmp/ding.wav",
		"LOX_SOUND_PRODUCTION": "0", "LOX_SOUND_REMIND": "0", "LOX_NOTIFY": "1"}), f.host("linux"))
	if len(warn) != 0 || !s.Off || s.Question != "/tmp/ding.wav" || s.Production != "" || s.Remind != 0 || s.Notify == nil {
		t.Fatalf("settings: %+v %v", s, warn)
	}
	f.started = nil
	s.Notify("locksql", "write")
	if len(f.started) != 1 || f.started[0][0] != "/usr/bin/notify-send" || !strings.Contains(strings.Join(f.started[0], " "), "locksql: a write waits") {
		t.Fatalf("notify: %v", f.started)
	}

	s, warn = SoundFromEnv(env(map[string]string{"LOX_SOUND_QUESTION": "/nope.oga", "LOX_SOUND_REMIND": "soon"}), f.host("linux"))
	if len(warn) != 2 || s.Question != "" || s.Remind != DefaultRemind {
		t.Fatalf("bad settings: %+v %v", s, warn)
	}
	for v, want := range map[string]time.Duration{"30s": 30 * time.Second, "2m": 2 * time.Minute, "45": 45 * time.Second} {
		if s, warn := SoundFromEnv(env(map[string]string{"LOX_SOUND_REMIND": v}), f.host("linux")); len(warn) != 0 || s.Remind != want {
			t.Errorf("LOX_SOUND_REMIND=%s: %s %v", v, s.Remind, warn)
		}
	}

	// aplay alone plays WAV files only: an .oga rings the bell.
	f.bins = map[string]bool{"aplay": true}
	s, _ = SoundFromEnv(env(nil), f.host("linux"))
	if s.Player != "aplay" || s.Play(DefaultQuestionSound) == nil || s.Play("/tmp/ding.wav") != nil {
		t.Fatalf("aplay: %+v", s)
	}
	// No player: Play nil, the bell.
	f.bins = nil
	if s, _ = SoundFromEnv(env(nil), f.host("linux")); s.Play != nil {
		t.Fatal("a player without one")
	}
	// No default file installed: the bell.
	f.files = nil
	if s, _ = SoundFromEnv(env(nil), f.host("linux")); s.Question != "" || s.Production != "" {
		t.Fatalf("missing defaults kept: %+v", s)
	}
	// macOS: afplay, system sounds.
	f.files = map[string]bool{macQuestionSound: true, macProductionSound: true}
	f.bins = map[string]bool{"afplay": true, "osascript": true}
	s, _ = SoundFromEnv(env(map[string]string{"LOX_NOTIFY": "1"}), f.host("darwin"))
	if s.Player != "afplay" || s.Question != macQuestionSound || s.Production != macProductionSound || s.Notify == nil {
		t.Fatalf("darwin: %+v", s)
	}
	f.started = nil
	s.Notify(`x"; do shell script "rm`, "write")
	if got := strings.Join(f.started[0], " "); strings.Count(got, `"`) != 4 {
		t.Fatalf("osascript text not kept plain: %s", got)
	}
}

// A lock console's question (policy review, password) plays the sound too.
func TestSoundConsoleQuestion(t *testing.T) {
	cons := newFakeConsoles()
	p := &fakePlayer{}
	h := start(t, newFakeHub(), nil, func(s *Session) {
		s.Consoles = cons
		s.Sound = &Sound{Question: "q.oga", Production: "p.oga", Play: p.Play}
	})
	cons.ask("shop", "Apply these changes? [y/N]", "profile shop")
	h.wait(EvQuestion, "")
	if got := p.played(); !slices.Equal(got, []string{"q.oga"}) {
		t.Fatalf("console question played %v, want [q.oga]", got)
	}
}
