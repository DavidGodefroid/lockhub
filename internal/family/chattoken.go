package family

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
)

// chatTokens lists, for each enabled chat facade, the identity of each of
// its secret files in hubData: a short hash of the token, never the
// token. They are summary lines, so a rotated token (lock add slack or
// telegram again) is a change lock up reviews and applies: the hub's
// config label changes and compose recreates the hub, which reads its
// tokens at start. Before, a rotation left the old token in use until
// the hub restarted for another reason.
func chatTokens(c *Config, hubData string) []string {
	var files []string
	if c.Hub.Slack != nil {
		files = append(files, chatconf.SlackAppToken, chatconf.SlackBotToken)
	}
	if c.Hub.Telegram != nil {
		files = append(files, chatconf.TelegramToken)
	}
	var s []string
	for _, f := range files {
		s = append(s, fmt.Sprintf("hub secret %s %s", f, tokenID(filepath.Join(hubData, f))))
	}
	return s
}

// tokenID identifies the token in path: the first 64 bits of a
// domain-separated SHA-256 of it, which tells two tokens apart without
// helping anyone guess one (a token has far more entropy than that).
// A file missing or unusable is "missing": lock doctor says why.
func tokenID(path string) string {
	tok, err := chatconf.ReadSecret(path)
	if err != nil {
		return "missing"
	}
	h := sha256.Sum256([]byte("lockfamily chat token id\x00" + tok))
	return "id " + hex.EncodeToString(h[:8])
}
