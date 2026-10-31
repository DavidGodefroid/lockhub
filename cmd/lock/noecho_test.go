package main

import (
	"strings"
	"testing"
)

func TestFlagSetDoesNotEchoValues(t *testing.T) {
	const c = "123456:glsa_CanarySecretToken123"
	var ids int64sFlag
	var logs lockLogFlag
	for what, err := range map[string]error{"int": ids.Set(c), "--lock": logs.Set(c)} {
		if err == nil || strings.Contains(err.Error(), "Canary") {
			t.Errorf("%s: %v", what, err)
		}
	}
}
