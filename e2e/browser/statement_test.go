package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/render"
)

// The phone signs only the answer its human gave, on the ticket it shows:
// a hub (or anything between it and the page) that prepares another
// statement, or a challenge of its own, gets no assertion, and the lock no
// decision.
func TestPhoneRefusesMismatchedStatements(t *testing.T) {
	e := newEnv(t)
	dev := e.confirm(e.pair("phone"))
	l := e.lock(dev)
	p, tk := l.newPlan(t)
	id, err := l.c.Submit(context.Background(), l.st, p.ID, l.caller, tk,
		render.MaskScreen(render.ScreenSource{Header: "crm / shop · write", Body: []render.Line{{{Text: "UPDATE customers"}}}}, render.Masking{}))
	if err != nil {
		t.Fatal(err)
	}
	if who, _ := e.signIn(); who != "phone" {
		t.Fatalf("signed in as %q", who)
	}
	e.waitFor("the ticket", `document.querySelector(".ticket .approve") ? "ok" : ""`)

	stmt := func(f func(st map[string]any)) func(map[string]any) {
		return func(res map[string]any) { f(res["statement"].(map[string]any)) }
	}
	at := func(d time.Duration) func(map[string]any) {
		return stmt(func(st map[string]any) { st["at"] = time.Now().Add(d).UTC().Format(time.RFC3339Nano) })
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		status string
	}{
		{"another ticket hash", stmt(func(st map[string]any) { st["ticket_hash"] = "sha256:" + strings.Repeat("0", 64) }),
			"the hub asked to sign another ticket_hash: refused"},
		{"another decision", stmt(func(st map[string]any) { st["decision"] = "denied" }),
			"the hub asked to sign another decision: refused"},
		{"another reason", stmt(func(st map[string]any) { st["reason"] = "not what the human typed" }),
			"the hub asked to sign another reason: refused"},
		{"another plan", stmt(func(st map[string]any) { st["plan_hash"] = "sha256:" + strings.Repeat("1", 64) }),
			"the hub asked to sign another plan_hash: refused"},
		{"another device", stmt(func(st map[string]any) { st["device"] = "webauthn:" + strings.Repeat("2", 32) }),
			"the hub asked to sign another device: refused"},
		{"an extra field", stmt(func(st map[string]any) { st["scope"] = "all tickets" }),
			"the hub asked to sign unexpected fields: refused"},
		{"a missing field", stmt(func(st map[string]any) { delete(st, "hub_key_id") }),
			"the hub asked to sign unexpected fields: refused"},
		{"a time long past", at(-10 * time.Minute), "the hub's time is off: refused"},
		{"a time far ahead", at(10 * time.Minute), "the hub's time is off: refused"},
		{"an unreadable time", stmt(func(st map[string]any) { st["at"] = "yesterday" }), "the hub's time is off: refused"},
		{"another challenge", func(res map[string]any) { res["challenge"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
			"the hub's challenge differs from this phone's: refused"},
	}
	signs := e.signCount()
	for _, c := range cases {
		e.setMutate(c.mutate)
		e.clearStatus()
		got := e.act(c.name, `document.querySelector(".ticket .reason").value = "ok from the phone"; document.querySelector(".ticket .approve").click()`,
			`(() => { const s = document.getElementById("status").textContent; return s && s !== "Preparing…" ? s : ""; })()`)
		if got != c.status {
			t.Errorf("%s: status %q, want %q", c.name, got, c.status)
		}
		if n := e.decides.Load(); n != 0 {
			t.Fatalf("%s: %d decisions reached the hub", c.name, n)
		}
		if n := e.signCount(); n != signs {
			t.Fatalf("%s: the authenticator signed (%v, was %v)", c.name, n, signs)
		}
		if s := e.ticketState(id); s != "pending" {
			t.Fatalf("%s: ticket %s", c.name, s)
		}
	}
	if pl, _, err := l.run(t, id); err == nil {
		t.Fatalf("the lock runs plan %s after refused statements", pl.ID)
	}

	// The same checks, called directly on the last statement the hub
	// prepared (unmodified) and on mutations of it.
	e.setMutate(nil)
	raw, chal := e.lastStatement()
	direct := e.eval(`(async () => {
		const q = await (await fetch("/m/v1/queue?since=0")).json();
		const it = q.tickets[0], t = JSON.parse(it.ticket);
		const dev = { rec: { id: ` + jsString(dev.ID) + `, name: "phone" } };
		const base = ` + string(raw) + `;
		const check = async (st) => { try { return window.lockhub.b64u(await window.lockhub.checkStatement(st, it, t, true, "ok from the phone", dev)); } catch (e) { return "error: " + e.message; } };
		const out = { ok: await check(base) };
		const muts = {
			v: { v: 2 }, v_string: { v: "1" }, ticket: { ticket: "other" }, instance: { instance: "other" },
			key_id: { key_id: "other" }, approver: { approver: "other" }, display: { display: "other" },
			facade: { facade: "slack" }, decision: { decision: "denied" }, nonce_missing: { nonce: undefined },
		};
		for (const [k, m] of Object.entries(muts)) {
			const st = { ...base, ...m };
			if ("nonce" in m) delete st.nonce;
			out[k] = await check(st);
		}
		return JSON.stringify(out);
	})()`)
	var res map[string]string
	if err := json.Unmarshal([]byte(direct), &res); err != nil {
		t.Fatal(direct, err)
	}
	if res["ok"] != chal {
		t.Fatalf("the hub's own statement: the phone computes %q, the hub %q", res["ok"], chal)
	}
	for k, want := range map[string]string{
		"v": "another v", "v_string": "another v", "ticket": "another ticket", "instance": "another instance",
		"key_id": "another key_id", "approver": "another approver", "display": "another display",
		"facade": "another facade", "decision": "another decision", "nonce_missing": "unexpected fields",
	} {
		if !strings.Contains(res[k], want) || !strings.HasSuffix(res[k], "refused") {
			t.Errorf("checkStatement with another %s: %q", k, res[k])
		}
	}

	// Untouched, the same answer goes through.
	e.clearStatus()
	e.retry("approval", func() string {
		return e.act("approval", `document.querySelector(".ticket .reason").value = "ok from the phone"; document.querySelector(".ticket .approve").click()`,
			`document.getElementById("status").textContent === "Approved." ? "ok" : ""`)
	})
	if n := e.decides.Load(); n != 1 {
		t.Fatalf("%d decisions reached the hub", n)
	}
	pl, d, err := l.run(t, id)
	if err != nil || pl.ID != p.ID || d.Approver.ID != dev.ID || d.Reason != "ok from the phone" {
		t.Fatalf("the lock did not run the phone's approval: %v %+v", err, d)
	}
}
