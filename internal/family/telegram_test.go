package family

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
)

const tgHub = "  facades: [tty, telegram]\n  telegram:\n    chats:\n      - {chat: -1001, from: 7}\n      - {chat: 42, from: 42}\n"

func TestTelegramConfigAndUp(t *testing.T) {
	w := newWS(t, yamlConf(tgHub))
	for name, hub := range map[string]string{
		"enabled without allowlist": "  facades: [tty, telegram]\n",
		"allowlist not enabled":     "  telegram:\n    chats:\n      - {chat: 42, from: 42}\n",
		"no sender":                 "  facades: [tty, telegram]\n  telegram:\n    chats:\n      - {chat: 42}\n",
	} {
		bad := newWS(t, yamlConf(hub))
		if _, err := Load(bad.file); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	out, err := w.up("y\n", newFake())
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "hub telegram chat -1001 user 7") || !strings.Contains(out, "hub telegram chat 42 user 42") {
		t.Errorf("allowlist not reviewed:\n%s", out)
	}
	s, err := chatconf.Load(filepath.Join(w.dir, "state", "hub", chatconf.File))
	if err != nil || s.Telegram == nil || len(s.Telegram.Chats) != 2 || s.Slack != nil {
		t.Fatalf("chat.json %+v %v", s, err)
	}
	cy, _ := os.ReadFile(filepath.Join(w.dir, "state", "compose.yaml"))
	if !strings.Contains(string(cy), `"egress-hub"`) {
		t.Errorf("hub without egress:\n%s", cy)
	}
}

func TestAddTelegram(t *testing.T) {
	w := newWS(t, "# mine\n"+yamlConf(""))
	state := filepath.Join(w.dir, "state")
	if err := AddTelegram(w.file, state, chatconf.Telegram{Chats: []chatconf.TelegramChat{{Chat: 42, From: 42}}}, "nope"); err == nil {
		t.Fatal("bad token accepted")
	}
	if _, err := os.Stat(filepath.Join(state, "hub", chatconf.TelegramToken)); !os.IsNotExist(err) {
		t.Fatal("token written on refusal")
	}
	if err := AddTelegram(w.file, state, chatconf.Telegram{Chats: []chatconf.TelegramChat{{Chat: 42, From: 42}}}, "123:abc"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(w.file)
	if err != nil || c.Hub.Telegram == nil || !strings.Contains(strings.Join(c.Hub.Facades, ","), "telegram") {
		t.Fatalf("%v %+v", err, c)
	}
	if got, err := chatconf.ReadSecret(filepath.Join(state, "hub", chatconf.TelegramToken)); err != nil || got != "123:abc" {
		t.Errorf("token %q %v", got, err)
	}
	if b, _ := os.ReadFile(w.file); !strings.Contains(string(b), "# mine") || strings.Contains(string(b), "123:abc") {
		t.Errorf("yaml:\n%s", b)
	}
}

func TestDoctorTelegramToken(t *testing.T) {
	d, _ := healthy(t)
	os.WriteFile(d.File, []byte(yamlConf(tgHub)), 0o644)
	if out, _ := doc(t, d); !strings.Contains(out, "FAIL telegram token") {
		t.Errorf("no token check:\n%s", out)
	}
}
