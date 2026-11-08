package loxrun

import (
	"strings"
	"testing"
	"time"
)

// sampleLockFeed is a production lock's feed: a loosening refused at
// start, a plan run, an agent looping on E_COST, a throttled ticket.
func sampleLockFeed() *LockFeed {
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	f := &LockFeed{Instance: "shop", Lock: "locksql"}
	f.take([]string{
		"The policy of profile shop-prod changed since it was approved:",
		"  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)",
		"changes refused: the last approved policy applies",
		"▸ Requests are decided on lockhub at https://hub:8443 as shop",
		"  session        ends in 58 min (max_session 1h0m0s) · idle_timeout 10m0s",
	}, at(0), RefusalLoop)
	f.take(planBox("SELECT title FROM book WHERE supplier = 'ACME' LIMIT 100", "OK",
		"a policy change in the config files was refused by the human; the last approved policy applies"), at(30), RefusalLoop)
	f.take([]string{"✓ done: 93 rows in 3946 ms"}, at(34), RefusalLoop)
	for i := range 11 {
		f.take([]string{"✗ refused [E_COST]: weight check: estimated rows examined 1 943 473 > 200 000"}, at(60+i*5), RefusalLoop)
	}
	f.take(planBox("SELECT 1", "OK"), at(200), RefusalLoop)
	f.take([]string{"✗ not submitted: hubclient: too many tickets: 20 tickets already pending (limit 20, raised by limits.max_pending); retry once one is decided"}, at(201), RefusalLoop)
	return f
}

func withLockTab(reveal bool) func(*View) {
	return func(v *View) {
		f := sampleLockFeed()
		v.Cards = nil
		v.Tabs = []LockTab{{Instance: "mq", Lock: "lockmq"}, {Instance: "shop", Lock: "locksql", Attention: f.Attention(RefusalLoop)}}
		lv := &LockView{Feed: *f, Console: LockConsole{Instance: "shop", Lock: "locksql", State: ConsoleServing}, Reveal: reveal, Loop: RefusalLoop}
		if !reveal {
			lv.Feed.Items = nil
			for _, it := range f.Items {
				c := *it
				c.clear = nil
				lv.Feed.Items = append(lv.Feed.Items, &c)
			}
		}
		v.Lock = lv
		v.Consoles = []LockConsole{lv.Console, {Instance: "mq", Lock: "lockmq", State: ConsoleServing}}
	}
}

// The lock tab never shows a statement's literal unless o revealed it,
// at any size.
func TestLockTabAnySize(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		for _, st := range []Style{{Color: true, Unicode: true}, {}} {
			for w := 40; w <= 200; w += 9 {
				for _, h := range []int{6, 12, 40} {
					v := sampleView()
					withLockTab(reveal)(&v)
					lines := Frame(v, w, h, st)
					if len(lines) != h {
						t.Fatalf("%dx%d: %d lines", w, h, len(lines))
					}
					all := ""
					for i, l := range lines {
						if n := strWidth(visible(l)); n > w {
							t.Fatalf("%dx%d line %d: %d columns: %q", w, h, i, n, visible(l))
						}
						all += visible(l) + "\n"
					}
					if !reveal && strings.Contains(all, "ACME") {
						t.Fatalf("%dx%d: a literal in clear without o:\n%s", w, h, all)
					}
				}
			}
		}
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{10 * time.Minute: "10m", time.Hour: "1h", 90 * time.Minute: "1h30m", 30 * time.Second: "30s"} {
		if got := short(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}
