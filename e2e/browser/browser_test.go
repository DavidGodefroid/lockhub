package browser

import (
	"context"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// The phase-6 exit criterion in a real browser: the web app pairs the
// phone (WebAuthn registration, a non-extractable WebCrypto X25519 key),
// the human confirms the fingerprint the page shows, a real lockkit lock
// seals its clear screen to it, the page opens it with WebCrypto and
// approves with a user-verified assertion, and the lock runs the plan.
func TestWebAppApproves(t *testing.T) {
	e := newEnv(t)
	dev := e.confirm(e.pair("phone"))

	// A lock pinning the phone pushes a ticket with personal data.
	l := e.lock(dev)
	p, tk := l.newPlan(t)
	tk.Requester = ticket.Requester{Agent: `<img src=x onerror="document.title='pwned'">`, Session: "s"}
	masked := render.MaskScreen(render.ScreenSource{Header: "crm / shop · write",
		Body: []render.Line{{{Text: "UPDATE customers SET email = "}, {Text: pii, Value: true, Column: "email", ColumnType: "text"}}}}, render.Masking{})
	clear := &ticket.Screen{Header: "crm / shop · write", Body: []string{"UPDATE customers SET email = '" + pii + "'"}}
	id, err := l.c.SubmitClear(context.Background(), l.st, p.ID, l.caller, tk, masked, clear)
	if err != nil {
		t.Fatal(err)
	}

	// The page: sign in, the ticket, its clear values, approve.
	if who, _ := e.signIn(); who != "phone" {
		t.Fatalf("signed in as %q", who)
	}
	e.waitFor("the ticket", `document.querySelector(".ticket .approve") ? "ok" : ""`)
	got := e.waitFor("the clear values", `(() => { const c = document.querySelector(".ticket .clear"); return c && !c.hidden ? c.textContent : ""; })()`)
	if !strings.Contains(got, pii) {
		t.Fatalf("clear values on the page: %q", got)
	}
	if masked := e.eval(`document.querySelector(".ticket .body").textContent`); strings.Contains(masked, pii) {
		t.Fatalf("the masked screen shows %q", masked)
	}
	if title := e.eval(`document.title`); title == "pwned" || e.eval(`String(document.querySelectorAll(".ticket img").length)`) != "0" {
		t.Fatal("agent text was rendered as markup")
	}
	e.retry("approval", func() string {
		return e.act("approval", `document.querySelector(".ticket .reason").value = "ok from the phone"; document.querySelector(".ticket .approve").click()`,
			`document.getElementById("status").textContent === "Approved." ? "ok" : ""`)
	})

	// The lock runs it: the device's signature verified at the lock.
	pl, d, err := l.run(t, id)
	if err != nil || pl.ID != p.ID {
		t.Fatalf("the lock did not run the phone's approval: %v", err)
	}
	if d.Device == nil || d.Reason != "ok from the phone" || d.Approver.ID != dev.ID {
		t.Fatalf("decision %+v", d)
	}
}
