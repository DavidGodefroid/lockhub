package mobilecli

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestPairDoesNotEchoTheOrigin(t *testing.T) {
	for _, o := range []string{"glsa_CanarySecretToken123", "http://user:glsa_Canary@h"} {
		err := Pair(context.Background(), nil, "phone", o, t.TempDir(), nil, io.Discard)
		if err == nil || strings.Contains(err.Error(), "Canary") || !strings.Contains(err.Error(), "hub.mobile.origin") {
			t.Errorf("%s: %v", o, err)
		}
	}
}
