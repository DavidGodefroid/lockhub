package telegram_test

import (
	"context"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/facade/telegram"
)

// A token url.Parse refuses (a % or a control character) never reaches
// the error, which url.Parse would quote with the whole URL.
func TestBadTokenNotEchoed(t *testing.T) {
	const tok = "42:glsa_Canary%zzSecret\x01"
	tg, err := telegram.New(telegram.Config{Chats: []chatconf.TelegramChat{{Chat: 42, From: 42}}, Token: tok, API: "http://127.0.0.1:1"})
	if err != nil {
		t.Skip("token refused up front:", err)
	}
	_, err = tg.Post(context.Background(), chat.Card{ID: "t", Instance: "crm", Risk: "read", Answerable: true})
	if err == nil || strings.Contains(err.Error(), "Canary") {
		t.Errorf("%v", err)
	}
}
