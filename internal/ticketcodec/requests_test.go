package ticketcodec_test

import (
	"slices"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// The hub's copies of lockkit's request constants stay in step.
func TestRequestConstantsMatchLockkit(t *testing.T) {
	if hub.RequestTTL != ticket.RevealTTL {
		t.Errorf("RequestTTL %s, lockkit RevealTTL %s", hub.RequestTTL, ticket.RevealTTL)
	}
	if hub.KindReveal != string(ticket.RequestReveal) || hub.KindRenew != string(ticket.RequestRenew) {
		t.Error("request kinds differ")
	}
	for _, f := range []string{"tty", "deck", "mobile", "slack", "telegram", "other"} {
		if route.OnDemand(f) != ticket.CanReveal(f) {
			t.Errorf("OnDemand(%s) = %v, lockkit CanReveal %v", f, route.OnDemand(f), ticket.CanReveal(f))
		}
	}
	codes := []string{hubclient.CodeFacadeRefused, hubclient.CodeNotPending, hubclient.CodeNoClear, hubclient.CodeNotRenewable,
		hubclient.CodeRecheckFailed, hubclient.CodePolicyChanged, hubclient.CodeLimited, hubclient.CodeFailed}
	for _, c := range codes {
		if !slices.Contains(hub.AnswerCodes, c) {
			t.Errorf("lockkit answer code %q unknown to the hub", c)
		}
	}
	if len(codes) != len(hub.AnswerCodes) {
		t.Errorf("hub codes %v, lockkit %v", hub.AnswerCodes, codes)
	}
}
