package family

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
)

// A rotated chat token is a reviewed change that recreates the hub (which
// reads its tokens at start); the token itself is never shown or stored.
func TestChatTokenRotationRecreatesHub(t *testing.T) {
	for name, tc := range map[string]struct {
		hub  string
		add  func(file, state, token string) error
		file string
	}{
		"slack": {slackHub, func(file, state, tok string) error {
			return AddSlack(file, state, chatconf.Slack{Team: "T01", Channel: "C02", Users: []string{"U03", "U04"}}, "xapp-1-A", "xoxb-"+tok)
		}, chatconf.SlackBotToken},
		"telegram": {tgHub, func(file, state, tok string) error {
			return AddTelegram(file, state, chatconf.Telegram{Chats: []chatconf.TelegramChat{{Chat: -1001, From: 7}, {Chat: 42, From: 42}}}, "123:"+tok)
		}, chatconf.TelegramToken},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWS(t, yamlConf(tc.hub))
			state := filepath.Join(w.dir, "state")
			if err := tc.add(w.file, state, "first-secret"); err != nil {
				t.Fatal(err)
			}
			f := newFake()
			out, err := w.up("y\n", f)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(out, "hub secret "+tc.file+" id ") {
				t.Errorf("token identity not reviewed:\n%s", out)
			}
			first := f.upCompose

			// Same token: nothing to review, the hub service is unchanged.
			f2 := &fake{keys: f.keys}
			if out, err := w.up("", f2); err != nil || !strings.Contains(out, "unchanged") || f2.upCompose != first {
				t.Fatalf("unchanged token: %v\n%s", err, out)
			}

			// Rotated: reviewed, refused without a yes, applied with one.
			if err := tc.add(w.file, state, "second-secret"); err != nil {
				t.Fatal(err)
			}
			out, err = w.up("n\n", &fake{keys: f.keys})
			if err != ErrNotConfirmed || !strings.Contains(out, "- hub secret "+tc.file+" id ") || !strings.Contains(out, "+ hub secret "+tc.file+" id ") {
				t.Fatalf("rotation not reviewed: %v\n%s", err, out)
			}
			f3 := &fake{keys: f.keys}
			applyOut, err := w.up("y\n", f3)
			if err != nil {
				t.Fatal(err)
			}
			out += applyOut
			if f3.upCompose == first {
				t.Error("a rotated token leaves the hub service unchanged: compose would not recreate it, the hub keeps the old token")
			}
			for _, p := range []string{"applied.json", "compose.yaml"} {
				b, _ := os.ReadFile(filepath.Join(state, p))
				if leaks(string(b)) {
					t.Errorf("%s holds a token:\n%s", p, b)
				}
			}
			if leaks(out) {
				t.Errorf("token shown:\n%s", out)
			}
		})
	}
}

// leaks reports whether s holds any token the tests use.
func leaks(s string) bool {
	for _, tok := range []string{"first-secret", "second-secret", "xapp-1-A", "123:one", "123:two"} {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

func TestChatTokenMissingIsALine(t *testing.T) {
	w := newWS(t, yamlConf(slackHub))
	out, err := w.up("y\n", newFake())
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "hub secret "+chatconf.SlackAppToken+" missing") {
		t.Errorf("missing token not said:\n%s", out)
	}
	if lines := chatTokens(&Config{}, t.TempDir()); len(lines) != 0 {
		t.Errorf("tokens without a chat facade: %v", lines)
	}
}

// lock doctor warns when a token changed since the last lock up.
func TestDoctorTokenRotated(t *testing.T) {
	d, _ := healthy(t)
	state := d.State
	os.WriteFile(d.File, []byte(yamlConf(tgHub)), 0o644)
	if err := AddTelegram(d.File, state, chatconf.Telegram{Chats: []chatconf.TelegramChat{{Chat: -1001, From: 7}, {Chat: 42, From: 42}}}, "123:one"); err != nil {
		t.Fatal(err)
	}
	var o strings.Builder
	u := &Up{File: d.File, State: state, Runtime: d.Runtime, User: "1000:1000", Run: &fake{keys: map[string]string{"crm-prod": pubKey(), "events": pubKey()}}, In: bufio.NewReader(strings.NewReader("y\n")), Out: &o}
	if err := u.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, o.String())
	}
	if out, _ := doc(t, d); strings.Contains(out, "changed since") {
		t.Fatalf("warned before any rotation:\n%s", out)
	}
	if err := AddTelegram(d.File, state, chatconf.Telegram{Chats: []chatconf.TelegramChat{{Chat: -1001, From: 7}, {Chat: 42, From: 42}}}, "123:two"); err != nil {
		t.Fatal(err)
	}
	out, _ := doc(t, d)
	if !strings.Contains(out, "chat token changed") || !strings.Contains(out, "hub secret "+chatconf.TelegramToken) {
		t.Errorf("rotation not warned:\n%s", out)
	}
	if leaks(out) {
		t.Errorf("token shown:\n%s", out)
	}
}

// An applied.json from before token identities, or a facade added since
// the last lock up, is no rotation.
func TestDoctorNoTokenWarningWithoutAppliedToken(t *testing.T) {
	d, _ := healthy(t) // applied without a chat facade
	os.WriteFile(d.File, []byte(yamlConf(tgHub)), 0o644)
	if err := AddTelegram(d.File, d.State, chatconf.Telegram{Chats: []chatconf.TelegramChat{{Chat: -1001, From: 7}, {Chat: 42, From: 42}}}, "123:one"); err != nil {
		t.Fatal(err)
	}
	out, _ := doc(t, d)
	if strings.Contains(out, "chat token changed") {
		t.Errorf("rotation warned for a token never applied:\n%s", out)
	}
	if !strings.Contains(out, "lockfamily.yaml changed") {
		t.Errorf("new facade not warned:\n%s", out)
	}
}
