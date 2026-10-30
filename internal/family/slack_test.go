package family

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

const slackHub = "  facades: [tty, deck, slack]\n  slack:\n    team: T01\n    channel: C02\n    users: [U03, U04]\n"

func TestSlackConfig(t *testing.T) {
	w := newWS(t, yamlConf(slackHub))
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hub.Slack == nil || c.Hub.Slack.Team != "T01" {
		t.Fatalf("%+v", c.Hub)
	}
	for name, hub := range map[string]string{
		"enabled without allowlist": "  facades: [tty, slack]\n",
		"allowlist not enabled":     "  slack:\n    team: T01\n    channel: C02\n    users: [U03]\n",
		"bad user":                  "  facades: [tty, slack]\n  slack:\n    team: T01\n    channel: C02\n    users: [david]\n",
		"no users":                  "  facades: [tty, slack]\n  slack:\n    team: T01\n    channel: C02\n",
	} {
		os.WriteFile(w.file, []byte(yamlConf(hub)), 0o644)
		if _, err := Load(w.file); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSlackUpReviewsAllowlistAndOpensEgress(t *testing.T) {
	w := newWS(t, yamlConf(slackHub))
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "hub slack team T01 channel C02 users U03,U04") {
		t.Errorf("allowlist not reviewed:\n%s", out)
	}
	s, err := chatconf.Load(filepath.Join(w.dir, "state", "hub", chatconf.File))
	if err != nil || s.Slack == nil || strings.Join(s.Slack.Users, ",") != "U03,U04" {
		t.Fatalf("chat.json %+v %v", s, err)
	}
	cy, _ := os.ReadFile(filepath.Join(w.dir, "state", "compose.yaml"))
	if !strings.Contains(string(cy), "    networks: [lockhub, \"egress-hub\"]") || !strings.Contains(string(cy), "  \"egress-hub\": {}") {
		t.Errorf("hub without egress:\n%s", cy)
	}
	// A narrower allowlist is a change to review.
	os.WriteFile(w.file, []byte(yamlConf(strings.Replace(slackHub, "[U03, U04]", "[U03]", 1))), 0o644)
	out, err = w.up("n\n", &fake{keys: f.keys})
	if err != ErrNotConfirmed || !strings.Contains(out, "- hub slack team T01 channel C02 users U03,U04") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestNoChatNoEgress(t *testing.T) {
	w := newWS(t, yamlConf(""))
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	cy, _ := os.ReadFile(filepath.Join(w.dir, "state", "compose.yaml"))
	if strings.Contains(string(cy), "egress-hub") {
		t.Errorf("egress without a chat facade:\n%s", cy)
	}
	b, _ := os.ReadFile(filepath.Join(w.dir, "state", "hub", chatconf.File))
	var s chatconf.Settings
	if json.Unmarshal(b, &s) != nil || s.Slack != nil {
		t.Errorf("chat.json %s", b)
	}
}

func TestAddSlack(t *testing.T) {
	w := newWS(t, "# mine\n"+yamlConf(""))
	state := filepath.Join(w.dir, "state")
	err := AddSlack(w.file, state, chatconf.Slack{Team: "T01", Channel: "C02", Users: []string{"U03"}}, "xapp-1-A", "xoxb-1-B")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(w.file)
	if err != nil || c.Hub.Slack == nil || !strings.Contains(strings.Join(c.Hub.Facades, ","), "slack") {
		t.Fatalf("%v %+v", err, c)
	}
	if b, _ := os.ReadFile(w.file); !strings.Contains(string(b), "# mine") || strings.Contains(string(b), "xoxb") {
		t.Errorf("yaml:\n%s", b)
	}
	for f, want := range map[string]string{chatconf.SlackAppToken: "xapp-1-A", chatconf.SlackBotToken: "xoxb-1-B"} {
		got, err := chatconf.ReadSecret(filepath.Join(state, "hub", f))
		if err != nil || got != want {
			t.Errorf("%s: %q %v", f, got, err)
		}
	}
	// Tokens of the wrong kind: nothing written.
	w2 := newWS(t, yamlConf(""))
	before, _ := os.ReadFile(w2.file)
	if err := AddSlack(w2.file, filepath.Join(w2.dir, "state"), chatconf.Slack{Team: "T01", Channel: "C02", Users: []string{"U03"}}, "xoxb-1", "xoxb-1"); err == nil {
		t.Fatal("bot token as app token accepted")
	}
	if after, _ := os.ReadFile(w2.file); string(after) != string(before) {
		t.Error("yaml changed on refusal")
	}
	if _, err := os.Stat(filepath.Join(w2.dir, "state", "hub", chatconf.SlackAppToken)); !os.IsNotExist(err) {
		t.Error("secret written on refusal")
	}
}

func TestDoctorSlackSecrets(t *testing.T) {
	d, _ := healthy(t)
	os.WriteFile(d.File, []byte(yamlConf(slackHub)), 0o644)
	out, _ := doc(t, d)
	if !strings.Contains(out, "FAIL slack tokens") {
		t.Errorf("no secret check:\n%s", out)
	}
}

// I9 (hub plan), lock up's side: with a lockfamily.yaml without slack or
// telegram, the review names no chat secret (though token files are
// there: lock up identifies a token only for a declared facade, and the
// control shows it would name it), routing.json enables no chat facade,
// chat.json holds no chat settings and the hub's only network is the
// internal lockhub one. (tokenID drops read errors, so a read that names
// nothing would not be seen here.)
func TestI9NoChatNoSecretNoRouteNoEgress(t *testing.T) {
	plant := func(w ws) {
		hub := filepath.Join(w.dir, "state", "hub")
		if err := os.MkdirAll(hub, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{chatconf.SlackAppToken, chatconf.SlackBotToken, chatconf.TelegramToken} {
			os.WriteFile(filepath.Join(hub, f), []byte("planted-token"), 0o600)
		}
	}
	w := newWS(t, yamlConf(""))
	plant(w)
	out, err := w.up("y\n", newFake())
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "hub secret") || strings.Contains(out, "slack") || strings.Contains(out, "telegram") {
		t.Errorf("the review names a chat secret or facade:\n%s", out)
	}
	hub := filepath.Join(w.dir, "state", "hub")
	var r route.Rules
	if b, err := os.ReadFile(filepath.Join(hub, "routing.json")); err != nil || json.Unmarshal(b, &r) != nil {
		t.Fatalf("routing.json: %v %s", err, b)
	}
	if len(r.Enabled) == 0 || slices.Contains(r.Enabled, route.Slack) || slices.Contains(r.Enabled, route.Telegram) {
		t.Errorf("routing.json enables %v (empty means the local facades only)", r.Enabled)
	}
	for _, f := range []string{route.Slack, route.Telegram} {
		if r.Allowed("crm-prod", f, route.Read) == nil {
			t.Errorf("%s may answer a read ticket", f)
		}
	}
	var s chatconf.Settings
	if b, err := os.ReadFile(filepath.Join(hub, chatconf.File)); err != nil || json.Unmarshal(b, &s) != nil || s.Slack != nil || s.Telegram != nil {
		t.Errorf("chat.json: %v %+v", err, s)
	}
	cy, err := os.ReadFile(filepath.Join(w.dir, "state", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The hub service's networks: only lockhub (internal).
	hubSvc, _, _ := strings.Cut(string(cy)[strings.Index(string(cy), "\n  lockhub:\n")+1:], "\n  hubkey:")
	if !strings.Contains(hubSvc, "\n    networks: [lockhub]\n") || strings.Contains(string(cy), "egress-hub") {
		t.Errorf("the hub has a network besides lockhub without a chat facade:\n%s", cy)
	}

	// Control: with slack declared, the review reads and names its tokens.
	c := newWS(t, yamlConf(slackHub))
	plant(c)
	out, err = c.up("y\n", newFake())
	if err != nil || !strings.Contains(out, "hub secret "+chatconf.SlackBotToken+" id ") {
		t.Errorf("control: the review does not name the slack token it read: %v\n%s", err, out)
	}
}
