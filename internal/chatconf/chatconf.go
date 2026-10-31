// Package chatconf is chat.json, the chat facades' settings that lock up
// writes in the hub's data directory from lockfamily.yaml (the allowlist;
// never a secret), and the secret files next to it.
package chatconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// File is chat.json's name in the hub's data directory.
const File = "chat.json"

// Secret files in the hub's data directory (0600, written by
// `lock add slack`).
const (
	SlackAppToken = "slack-app-token"
	SlackBotToken = "slack-bot-token"
	TelegramToken = "telegram-bot-token"
)

// Settings is chat.json.
type Settings struct {
	Slack    *Slack    `json:"slack,omitempty" yaml:"slack,omitempty"`
	Telegram *Telegram `json:"telegram,omitempty" yaml:"telegram,omitempty"`
}

// Telegram is who may answer on Telegram: each entry is a chat and the
// user who may answer in it (a private chat with the bot: both the same
// id; a group: the group's id and the user's).
type Telegram struct {
	Chats []TelegramChat `json:"chats" yaml:"chats"`
}

// TelegramChat is one allowed (chat, sender) pair.
type TelegramChat struct {
	Chat int64 `json:"chat" yaml:"chat"`
	From int64 `json:"from" yaml:"from"`
}

// Validate checks the allowlist.
func (t *Telegram) Validate() error {
	if len(t.Chats) == 0 {
		return errors.New("telegram.chats: list the chat and sender ids who may answer")
	}
	seen := map[TelegramChat]bool{}
	for i, c := range t.Chats {
		if c.Chat == 0 || c.From <= 0 {
			return fmt.Errorf("telegram.chats[%d]: want a chat id and a user id (from > 0)", i)
		}
		if seen[c] {
			return fmt.Errorf("telegram.chats[%d]: listed twice", i)
		}
		seen[c] = true
	}
	return nil
}

// Slack is who may answer on Slack, and where tickets are posted.
type Slack struct {
	Team    string   `json:"team" yaml:"team"`
	Channel string   `json:"channel" yaml:"channel"`
	Users   []string `json:"users" yaml:"users"`
}

var (
	teamID    = regexp.MustCompile(`^T[A-Z0-9]{2,20}$`)
	channelID = regexp.MustCompile(`^[CG][A-Z0-9]{2,20}$`)
	userID    = regexp.MustCompile(`^[UW][A-Z0-9]{2,20}$`)
)

// Validate checks the ids' shapes.
func (s *Slack) Validate() error {
	if !teamID.MatchString(s.Team) {
		return errors.New("slack.team: want a workspace id (T…)")
	}
	if !channelID.MatchString(s.Channel) {
		return errors.New("slack.channel: want a channel id (C… or G…)")
	}
	if len(s.Users) == 0 {
		return errors.New("slack.users: list the member ids (U…) who may answer")
	}
	for i, u := range s.Users {
		if !userID.MatchString(u) {
			return fmt.Errorf("slack.users[%d]: want a member id (U… or W…)", i)
		}
	}
	return nil
}

// Load reads chat.json; missing: no chat settings.
func Load(path string) (Settings, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	} else if err != nil {
		return Settings{}, err
	}
	var s Settings
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", path, err)
	}
	if s.Slack != nil {
		if err := s.Slack.Validate(); err != nil {
			return Settings{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	if s.Telegram != nil {
		if err := s.Telegram.Validate(); err != nil {
			return Settings{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	return s, nil
}

// ReadSecret reads a secret file: a regular file (not a link) that only
// its owner can read.
func ReadSecret(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s: mode %v, want 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("%s: not a single token", path)
	}
	return s, nil
}
