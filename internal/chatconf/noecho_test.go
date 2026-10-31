package chatconf

import (
	"strings"
	"testing"
)

// TestErrorsDoNotEchoValues: an allowlist value (maybe a pasted token)
// never shows in its error, which still names the key.
func TestErrorsDoNotEchoValues(t *testing.T) {
	for _, c := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h"} {
		for key, s := range map[string]Slack{
			"slack.team":     {Team: c, Channel: "C02", Users: []string{"U03"}},
			"slack.channel":  {Team: "T01", Channel: c, Users: []string{"U03"}},
			"slack.users[1]": {Team: "T01", Channel: "C02", Users: []string{"U03", c}},
		} {
			err := s.Validate()
			if err == nil || strings.Contains(err.Error(), c) || strings.Contains(err.Error(), "Canary") || !strings.Contains(err.Error(), key) {
				t.Errorf("%s: %v", key, err)
			}
		}
	}
	for key, tg := range map[string]Telegram{
		"telegram.chats[1]": {Chats: []TelegramChat{{Chat: 1, From: 1}, {Chat: 987654321, From: -123456789}}},
		"telegram.chats[2]": {Chats: []TelegramChat{{Chat: 1, From: 1}, {Chat: 987654321, From: 123456789}, {Chat: 987654321, From: 123456789}}},
	} {
		err := tg.Validate()
		if err == nil || strings.Contains(err.Error(), "987654321") || strings.Contains(err.Error(), "123456789") || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: %v", key, err)
		}
	}
}
