package browser

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"

	"github.com/DavidGodefroid/lockkit/render"

	"github.com/DavidGodefroid/lockhub/internal/store"
)

const (
	noteNewer    = "A newer pairing of this phone is not confirmed on the host yet."
	noteReplaced = "Paired. Revoke the device this phone replaced: lox mobile revoke NAME on the host."
)

// A phone that works pairs again: until the host confirms the new pairing
// (declined, or not answered yet) it keeps signing in with the device it
// has, and says so; once confirmed, the new pairing replaces it and the
// page asks to revoke the old one.
func TestPendingPairingFallsBack(t *testing.T) {
	e := newEnv(t)
	old := e.confirm(e.pair("phone"))
	if who, st := e.signIn(); who != "phone" || st != "" {
		t.Fatalf("first sign-in: %q, status %q", who, st)
	}
	if d, p := e.idb("device"), e.idb("pending"); d != "phone" || p != "" {
		t.Fatalf("after the first sign-in: device %q, pending %q", d, p)
	}
	e.signOut()

	// signedInAs signs in and checks who, the note and what the page keeps.
	signedInAs := func(step, who, note, device, pending string) {
		t.Helper()
		w, st := e.signIn()
		if w != who || st != note {
			t.Fatalf("%s: signed in as %q, status %q; want %q, %q", step, w, st, who, note)
		}
		if d, p := e.idb("device"), e.idb("pending"); d != device || p != pending {
			t.Fatalf("%s: the page keeps device %q, pending %q; want %q, %q", step, d, p, device, pending)
		}
		e.signOut()
	}

	// A new pairing the host declines.
	declined, _ := e.pair("phone-2")
	e.decline(declined)
	signedInAs("declined", "phone", noteNewer, "phone", "phone-2")

	// A new pairing the host has not answered yet.
	id, fp := e.pair("phone-3")
	signedInAs("unanswered", "phone", noteNewer, "phone", "phone-3")

	// The host confirms it: it replaces the old device.
	dev := e.confirm(id, fp)
	signedInAs("confirmed", "phone-3", noteReplaced, "phone-3", "")

	states := func() map[string]string {
		m := map[string]string{}
		for _, d := range e.devices() {
			m[d.Name] = d.State
		}
		return m
	}
	if s := states(); len(s) != 2 || s["phone"] != store.DeviceActive || s["phone-3"] != store.DeviceActive {
		t.Fatalf("devices before revoking: %v", s)
	}
	e.call("POST", "/v1/mobile/devices/"+old.ID+"/revoke", nil, nil)
	if s := states(); len(s) != 2 || s["phone"] != store.DeviceRevoked || s["phone-3"] != store.DeviceActive {
		t.Fatalf("devices after revoking the old one: %v", s)
	}
	signedInAs("after the revocation", "phone-3", "", "phone-3", "")
	if dev.Name != "phone-3" {
		t.Fatalf("confirmed device %+v", dev)
	}
}

// A fresh phone whose pairing the host declines cannot sign in, pins
// nothing, and takes no decision.
func TestDeclinedPairingFreshPhone(t *testing.T) {
	e := newEnv(t)
	id, _ := e.pair("phone")
	e.decline(id)
	if ds := e.devices(); len(ds) != 0 {
		t.Fatalf("a declined pairing is pinned: %+v", ds)
	}

	// A ticket waits at the hub.
	l := e.lock()
	p, tk := l.newPlan(t)
	tid, err := l.c.Submit(context.Background(), l.st, p.ID, l.caller, tk,
		render.MaskScreen(render.ScreenSource{Header: "crm / shop · write", Body: []render.Line{{{Text: "UPDATE customers"}}}}, render.Masking{}))
	if err != nil {
		t.Fatal(err)
	}

	e.open("/")
	e.waitFor("the sign-in button", `document.getElementById("login").hidden ? "" : "ok"`)
	st := e.retry("sign-in", func() string {
		return e.act("sign-in", `document.getElementById("login-btn").click()`,
			`document.getElementById("status").textContent.includes("not confirmed on the host yet") ? document.getElementById("status").textContent : ""`)
	})
	if !strings.HasPrefix(st, "This phone is not confirmed on the host yet") {
		t.Fatalf("status %q", st)
	}
	if e.eval(`document.getElementById("queue").hidden ? "hidden" : "shown"`) != "hidden" {
		t.Fatal("the queue shows without a sign-in")
	}
	if d, pending := e.idb("device"), e.idb("pending"); d != "" || pending != "phone" {
		t.Fatalf("the page keeps device %q, pending %q", d, pending)
	}
	if ds := e.devices(); len(ds) != 0 {
		t.Fatalf("devices after the sign-in attempt: %+v", ds)
	}

	// No session: neither the queue nor an answer.
	got := e.eval(`(async () => {
		const h = { "Content-Type": "application/json", "X-Lockhub": "1" };
		const q = await fetch("/m/v1/queue?since=0");
		const p = await fetch("/m/v1/tickets/` + inst + `/" + ` + jsString(tid) + ` + "/prepare", { method: "POST", headers: h, body: JSON.stringify({ approve: true, reason: "" }) });
		const d = await fetch("/m/v1/tickets/` + inst + `/" + ` + jsString(tid) + ` + "/decide", { method: "POST", headers: h, body: "{}" });
		return [q.status, p.status, d.status].join(",");
	})()`)
	if got != "401,401,401" {
		t.Fatalf("queue, prepare, decide without a session: %s", got)
	}
	if s := e.ticketState(tid); s != "pending" {
		t.Fatalf("ticket %s", s)
	}
	if _, _, err := l.run(t, tid); err == nil {
		t.Fatal("the lock runs a ticket nobody answered")
	}
}

// A confirmed new pairing that fails on the phone itself (its credential
// is gone from the authenticator) falls back to the older device without
// claiming the host did not confirm it.
func TestPendingPairingFailsOnThePhone(t *testing.T) {
	e := newEnv(t)
	e.confirm(e.pair("phone"))
	if who, _ := e.signIn(); who != "phone" {
		t.Fatalf("first sign-in: %q", who)
	}
	e.signOut()
	e.confirm(e.pair("phone-2"))

	cred := e.eval(`new Promise((ok, ko) => { const r = indexedDB.open("lockhub", 1);
		r.onsuccess = () => { const g = r.result.transaction("keys").objectStore("keys").get("pending");
			g.onsuccess = () => ok(g.result.rec.credential); g.onerror = () => ko(g.error); }; r.onerror = () => ko(r.error); })`)
	raw, err := base64.RawURLEncoding.DecodeString(cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chromedp.Call(e.ctx, webauthn.RemoveCredential, webauthn.RemoveCredentialParams{AuthenticatorID: e.auth, CredentialID: raw}); err != nil {
		t.Fatal(err)
	}
	who, st := e.signIn()
	if who != "phone" || !strings.HasPrefix(st, "The newer pairing of this phone did not sign in: ") {
		t.Fatalf("signed in as %q, status %q", who, st)
	}
	if d, p := e.idb("device"), e.idb("pending"); d != "phone" || p != "phone-2" {
		t.Fatalf("the page keeps device %q, pending %q", d, p)
	}
}
