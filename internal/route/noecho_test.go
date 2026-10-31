package route

import (
	"strings"
	"testing"
)

func TestAllowedDoesNotEchoValues(t *testing.T) {
	const c = "glsa_CanarySecretToken123"
	for what, err := range map[string]error{
		"facade": Rules{}.Allowed("crm", c, Read),
		"risk":   Rules{}.Allowed("crm", TTY, c),
	} {
		if err == nil || strings.Contains(err.Error(), c) || !strings.Contains(err.Error(), what) {
			t.Errorf("%s: %v", what, err)
		}
	}
}
