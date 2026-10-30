package family

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// AddSlack enables the Slack facade: the allowlist goes to lockfamily.yaml
// (reviewed at the next lock up), the tokens to 0600 files in the hub's
// data directory under state, never in the workspace. Everything is
// checked before anything is written.
func AddSlack(path, state string, s chatconf.Slack, appToken, botToken string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(appToken, "xapp-") || strings.ContainsAny(appToken, " \t\r\n") {
		return errors.New("the app-level token starts with xapp- (Basic Information, App-Level Tokens, scope connections:write)")
	}
	if !strings.HasPrefix(botToken, "xoxb-") || strings.ContainsAny(botToken, " \t\r\n") {
		return errors.New("the bot token starts with xoxb- (OAuth & Permissions, scope chat:write)")
	}
	return addChat(path, state, route.Slack, s, map[string]string{chatconf.SlackAppToken: appToken, chatconf.SlackBotToken: botToken})
}

// AddTelegram enables the Telegram facade, like AddSlack.
func AddTelegram(path, state string, t chatconf.Telegram, token string) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if id, _, ok := strings.Cut(token, ":"); !ok || id == "" || strings.ContainsAny(token, " /\t\r\n") {
		return errors.New("the bot token from BotFather looks like 123456:ABC…")
	}
	return addChat(path, state, route.Telegram, t, map[string]string{chatconf.TelegramToken: token})
}

// addChat adds facade to hub.facades, sets hub.<facade> to allow, and
// stores the secrets.
func addChat(path, state, facade string, allow any, secrets map[string]string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a lockfamily.yaml mapping", path)
	}
	c, err := decode(b, path, false)
	if err != nil {
		return err
	}
	hub := child(doc.Content[0], "hub")
	facades := c.Hub.Facades
	if !slices.Contains(facades, facade) {
		facades = append(slices.Clone(facades), facade)
	}
	var fn, sn yaml.Node
	if err := fn.Encode(facades); err != nil {
		return err
	}
	fn.Style = yaml.FlowStyle
	if err := sn.Encode(allow); err != nil {
		return err
	}
	*seq(hub, "facades") = fn
	*child(hub, facade) = sn
	out, _, err := encodeValid(&doc)
	if err != nil {
		return fmt.Errorf("%s: not changed: %w", path, err)
	}
	hubData := filepath.Join(state, "hub")
	for _, d := range []string{state, hubData} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	for name, v := range secrets {
		if err := writeSecret(filepath.Join(hubData, name), v); err != nil {
			return err
		}
	}
	return writeFile(path, out)
}

// seq is the value node of key in mapping m, created when absent.
func seq(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	v := &yaml.Node{}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
	return v
}

// writeSecret replaces path with a new 0600 file holding v.
func writeSecret(path, v string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".secret-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.WriteString(v + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
