package family

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
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
