package loxrun_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// A ticket that asks for a typed value, end to end (#187): a real
// lockkit lock asks for "needle", lox run asks the human for it without
// echo when they approve and seals it to the lock, the lock's run opens
// exactly the value typed. Neither the hub's data directory nor lox
// run's terminal ever holds it.
func TestRunE2EInputs(t *testing.T) {
	const needle = "alice@example.org"
	w := newWorld(t)
	id := w.submitWith(ticket.KindRead, ticket.RiskRead, "B", "grep -r ", func(tk *ticket.Ticket) {
		tk.Subject.Inputs = []string{"needle"}
		tk.Flags.NeverAuto = true
	})
	// AUTO mode, a read: still the human's.
	if q := w.wait(loxrun.EvQuestion, id); q.ID != id {
		t.Fatalf("%+v", q)
	}
	w.press(loxrun.R('y'))
	w.press(typed(needle)...)
	if d := w.wait(loxrun.EvDecided, id); !d.Approved || d.Rule != "" {
		t.Fatalf("decision %+v: want the human's approval", d)
	}
	if d := w.decision(id); d.Auto() || d.Secret == nil {
		t.Fatalf("signed decision %+v: want the human's, with the sealed value", d)
	}
	p, _, err := w.lock.Begin(w.plans, id, caller, func(p *plans.Plan) (string, string, error) {
		return p.Binding.PolicyFP, p.Binding.PlanHash, nil
	})
	if err != nil {
		t.Fatalf("the lock cannot run it: %v", err)
	}
	if len(p.Inputs) != 1 || string(p.Inputs["needle"]) != needle {
		t.Fatalf("the lock opened %q, want the value typed", p.Inputs)
	}

	screen := w.out.String()
	if strings.Contains(screen, needle) {
		t.Error("lox run's terminal shows the typed value")
	}
	if !strings.Contains(screen, "${needle}") {
		t.Error("lox run's terminal does not name the value asked")
	}
	// The hub's store and signed audit, the lock's plans and hub state: none
	// holds it.
	filepath.WalkDir(w.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, _ := os.ReadFile(path); bytes.Contains(b, []byte(needle)) {
			t.Errorf("%s holds the typed value", path)
		}
		return nil
	})
}
