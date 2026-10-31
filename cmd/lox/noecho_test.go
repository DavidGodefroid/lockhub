package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestFlagsDoNotEchoValues: a token pasted into --chat, --from or --lock
// never shows on stderr (the flag package quotes a value Set refuses).
func TestFlagsDoNotEchoValues(t *testing.T) {
	const c = "123456:glsa_CanarySecretToken123"
	for flag, args := range map[string][]string{
		"--chat": {"add", "telegram", "--chat", c, "--from", "1"},
		"--from": {"add", "telegram", "--chat", "1", "--from", c},
		"--lock": {"audit", "verify", "--data", "/nonexistent", "--hub-key-file", "/nonexistent", "--lock", c},
	} {
		var out, errb bytes.Buffer
		code := run(args, devNull(t), &out, &errb)
		if code != 2 || strings.Contains(errb.String()+out.String(), "Canary") || !strings.Contains(errb.String(), flag) {
			t.Errorf("%s: %d %q", flag, code, errb.String())
		}
	}
}
