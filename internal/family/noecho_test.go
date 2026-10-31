package family

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// canaries are what a human may paste into a key by mistake: a token, and
// a URL carrying one in its user info.
var canaries = []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h", hexCanary}

// hexCanary is an API key shaped like a lowercase key or instance name.
const hexCanary = "abcdef0123456789abcdef0123456789"

// leaked reports whether msg shows the canary, or a part yaml.v3 could
// quote (up to ten characters, or the first seven).
func leaked(msg, canary string) bool {
	for _, s := range []string{canary, "glsa_", "Canary", "user:", hexCanary[:7]} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// TestErrorsDoNotEchoValues: a value typed in lockfamily.yaml (maybe a
// pasted secret) never shows in its error, which still names the key.
func TestErrorsDoNotEchoValues(t *testing.T) {
	for _, c := range canaries {
		q := `"` + c + `"`
		for name, tc := range map[string]struct{ conf, key string }{
			"version":               {strings.Replace(yamlConf(""), "version: 1", "version: "+q, 1), "version"},
			"hub.image":             {strings.Replace(yamlConf(""), "image: "+hubImg, "image: "+q, 1), "hub.image"},
			"lock image":            {strings.Replace(yamlConf(""), "image: "+sqlImg, "image: "+q, 1), "locks.crm-prod.image"},
			"lock type":             {strings.Replace(yamlConf(""), "type: locksql", "type: "+q, 1), "locks.crm-prod.type"},
			"lock profile":          {strings.Replace(yamlConf(""), "type: locksql", "type: locksql\n    profile: \"!"+c+"\"", 1), "locks.crm-prod.profile"},
			"lock devices":          {strings.Replace(yamlConf(""), "type: locksql", "type: locksql\n    devices: "+q, 1), "locks.crm-prod.devices"},
			"allowed_uids":          {strings.Replace(yamlConf(""), "type: locksql", "type: locksql\n    allowed_uids: ["+q+"]", 1), "allowed_uids[0]"},
			"hub.facades":           {yamlConf("  facades: [tty, " + q + "]\n"), "hub.facades[1]"},
			"hub.routing":           {yamlConf("  routing:\n    crm-prod: [tty, " + q + "]\n"), "hub.routing.crm-prod[1]"},
			"hub.mobile.origin":     {yamlConf("  facades: [mobile]\n  mobile:\n    origin: " + q + "\n"), "mobile.origin"},
			"hub.mobile.port":       {yamlConf("  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    port: " + q + "\n"), "hub.mobile.port"},
			"hub.mobile.seal_clear": {yamlConf("  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    seal_clear: " + q + "\n"), "hub.mobile.seal_clear"},
			"require_device":        {yamlConf("  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    require_device: [" + q + "]\n"), "mobile.require_device[0]"},
			"hub.slack.team":        {yamlConf("  facades: [tty, slack]\n  slack:\n    team: " + q + "\n    channel: C02\n    users: [U03]\n"), "slack.team"},
			"hub.slack.channel":     {yamlConf("  facades: [tty, slack]\n  slack:\n    team: T01\n    channel: " + q + "\n    users: [U03]\n"), "slack.channel"},
			"hub.slack.users":       {yamlConf("  facades: [tty, slack]\n  slack:\n    team: T01\n    channel: C02\n    users: [U03, " + q + "]\n"), "slack.users[1]"},
			"alias":                 {strings.Replace(yamlConf(""), "image: "+hubImg, "image: *"+c, 1), "line 3: image"},
			"explicit tag":          {strings.Replace(yamlConf(""), "version: 1", "version: !!int "+q, 1), "version"},
			"explicit bool tag":     {yamlConf("  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    seal_clear: !!bool " + q + "\n"), "hub.mobile.seal_clear"},
			"instance name":         {strings.Replace(yamlConf(""), "crm-prod:", q+":", 1), "locks"},
			"routing instance":      {yamlConf("  routing:\n    " + q + ": [tty]\n"), "hub.routing"},
			"flow mapping value":    {strings.Replace(yamlConf(""), "image: "+hubImg, "image: {"+c+"}", 1), "hub.image"},
			"unknown key":           {strings.Replace(yamlConf(""), "version: 1", "version: 1\n"+q+": 1", 1), "unknown key"},
			"unknown lock key":      {strings.Replace(yamlConf(""), "type: locksql", "type: locksql\n    "+q+": 1", 1), "unknown key"},
			"key twice":             {strings.Replace(yamlConf(""), "type: locksql", "type: locksql\n    "+q+": 1\n    "+q+": 2", 1), "already defined"},
			"tagged key":            {strings.Replace(yamlConf(""), "version: 1", "version: 1\n!!int \"x`"+c+"\": 1", 1), "explicit tag"},
			"hub.telegram.chats":    {yamlConf("  facades: [tty, telegram]\n  telegram:\n    chats:\n      - {chat: " + q + ", from: 7}\n"), "hub.telegram.chats"},
		} {
			if c == hexCanary && name == "instance name" {
				continue // a valid instance name, shown by design
			}
			p := filepath.Join(t.TempDir(), "lockfamily.yaml")
			if err := os.WriteFile(p, []byte(tc.conf), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if err == nil {
				t.Errorf("%s: %s accepted", name, c)
				continue
			}
			if msg := err.Error(); leaked(msg, c) || !strings.Contains(msg, tc.key) {
				t.Errorf("%s: the error must name %s and not show the value: %s", name, tc.key, msg)
			}
		}
	}
}

func TestFlagErrorsDoNotEchoValues(t *testing.T) {
	c := loadConf(t, yamlConf(""))
	for _, v := range canaries {
		if _, err := PinRef(v); err == nil || leaked(err.Error(), v) || !strings.Contains(err.Error(), "--pin") {
			t.Errorf("--pin %s: %v", v, err)
		}
		if _, err := parseRotate(c, []string{v}); err == nil || leaked(err.Error(), v) || !strings.Contains(err.Error(), "--rotate") {
			t.Errorf("--rotate %s: %v", v, err)
		}
	}
}

// TestWritersDoNotEchoValues: lox add, add slack, import and --pin
// parse the file too.
func TestWritersDoNotEchoValues(t *testing.T) {
	for _, c := range canaries {
		dir := t.TempDir()
		fresh := filepath.Join(dir, "fresh.yaml")
		err := Add(fresh, AddOptions{Type: "locksql", Name: "crm", Image: sqlImg, HubImage: "*" + c})
		if err == nil || leaked(err.Error(), c) || !strings.Contains(err.Error(), "--hub-image") {
			t.Errorf("add --hub-image *%s: %v", c, err)
		}
		if _, err := os.Stat(fresh); err == nil {
			t.Errorf("add --hub-image *%s: file written", c)
		}
		bad := filepath.Join(dir, "lockfamily.yaml")
		if err := os.WriteFile(bad, []byte(strings.Replace(yamlConf(""), "image: "+hubImg, "image: *"+c, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Add(bad, AddOptions{Type: "locksql", Name: "crm", Image: sqlImg}); err == nil || leaked(err.Error(), c) || !strings.Contains(err.Error(), "line 3: image") {
			t.Errorf("add to an alias: %v", err)
		}
		if _, err := setHubImage([]byte("hub:\n  image: *"+c+"\n"), hubImg); err == nil || leaked(err.Error(), c) || !strings.Contains(err.Error(), "image") {
			t.Errorf("setHubImage: %v", err)
		}
		if _, err := (&Releases{}).Image(t.Context(), "locksql", c); err == nil || leaked(err.Error(), c) {
			t.Errorf("release tag %s: %v", c, err)
		}
	}
}

func loadConf(t *testing.T, conf string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUnquoteKeepsPunctuation(t *testing.T) {
	for _, m := range []string{"yaml: line 3: did not find expected ',' or ']'", "yaml: line 2: could not find expected ':'"} {
		if got := unquote(m); got != m {
			t.Errorf("%s became %s", m, got)
		}
	}
	if got := unquote("x 'glsa_Canary' y"); strings.Contains(got, "Canary") {
		t.Errorf("%s", got)
	}
}
