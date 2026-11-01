package loxinit

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// The screens are pure: inputs to text, golden-tested.

// RenderPrereqs is the prerequisites screen.
func RenderPrereqs(w io.Writer, p Prereqs, goos string) {
	fmt.Fprintln(w, "Prerequisites")
	if p.Docker != "" {
		fmt.Fprintf(w, "  ok  Docker %s\n", p.Docker)
	} else {
		fmt.Fprintf(w, "  !!  Docker does not answer: %s\n", DockerHint(goos, p.DockerCLI))
	}
	if p.Cosign != "" {
		fmt.Fprintln(w, "  ok  cosign (lox add and lox up verify every image's signature)")
	} else {
		fmt.Fprintf(w, "  !!  cosign not found: %s\n", CosignHint(goos))
	}
	if p.Lea != "" {
		fmt.Fprintln(w, "  ok  lea")
	} else {
		fmt.Fprintf(w, "  --  lea not found (the locks run without it; lockhttp needs it): %s\n", LeaHint)
	}
	var have, miss []string
	for _, l := range Locks {
		if l == "locklog" {
			continue
		}
		if p.Launchers[l] != "" {
			have = append(have, l)
		} else {
			miss = append(miss, l)
		}
	}
	if len(have) > 0 {
		fmt.Fprintf(w, "  ok  launchers: %s\n", strings.Join(have, ", "))
	}
	if len(miss) > 0 {
		fmt.Fprintf(w, "  --  launchers not installed: %s (https://github.com/DavidGodefroid/<lock>#install)\n", strings.Join(miss, ", "))
	}
}

// RenderDeclared lists the locks lockfamily.yaml declares already.
func RenderDeclared(w io.Writer, decl []Declared) {
	if len(decl) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Declared in .lockfamily/lockfamily.yaml (kept as they are)")
	for _, d := range decl {
		fmt.Fprintf(w, "  %-12s %s\n", d.Instance, declDesc(d))
	}
}

func declDesc(d Declared) string {
	if d.Profile == "" {
		return d.Lock
	}
	return d.Lock + ", profile " + d.Profile
}

// RenderDetected is the detection screen.
func RenderDetected(w io.Writer, sources []Source, warnings []string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Detected (read only: .env*, compose*.yaml, config/; no secret is read or kept)")
	if len(sources) == 0 {
		fmt.Fprintln(w, "  nothing: no PostgreSQL, MySQL, MariaDB or RabbitMQ in these files")
	}
	for i, s := range sources {
		fmt.Fprintf(w, "  %d  %-10s  %s  %s\n", i+1, s.Label(), s.Target(), sourceDesc(s))
		fmt.Fprintf(w, "       from %s\n", strings.Join(s.From, ", "))
		for _, n := range s.Notes {
			fmt.Fprintf(w, "       note: %s\n", n)
		}
	}
	for _, x := range warnings {
		fmt.Fprintf(w, "  warning: %s\n", x)
	}
}

func sourceDesc(s Source) string {
	var p []string
	if s.User != "" {
		p = append(p, "user "+s.User)
	}
	if s.Kind == KindRabbitMQ {
		if s.VHost != "" {
			p = append(p, "vhost "+s.VHost)
		}
		if u := s.AMQPURL(); u != "" {
			p = append(p, "AMQP "+u)
		}
	} else {
		if s.Database != "" {
			p = append(p, "database "+s.Database)
		}
		if s.TLS != "" {
			p = append(p, "tls "+s.TLS)
		}
	}
	return strings.Join(p, ", ")
}

// Item is one row of the manual checklist.
type Item struct {
	// Key is "lea", a lock type, or "declared:INSTANCE".
	Key     string
	Name    string
	Desc    string
	Checked bool
	// Grey is why the row cannot be checked ("" when it can).
	Grey string
}

// Declared reports a row of a lock lockfamily.yaml declares.
func (it Item) Declared() bool { return strings.HasPrefix(it.Key, "declared:") }

// RenderChecklist is the manual checklist: every row is numbered; a
// greyed row ([-]) says why it cannot be checked.
func RenderChecklist(w io.Writer, items []Item) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Manual mode: what to set up (type numbers to toggle, Enter when done)")
	declHeader := false
	for i, it := range items {
		if it.Declared() && !declHeader {
			fmt.Fprintln(w, "  declared in lockfamily.yaml (uncheck to remove; its profile stays in the lock's directory):")
			declHeader = true
		}
		mark, desc := " ", it.Desc
		switch {
		case it.Grey != "":
			mark, desc = "-", it.Grey
		case it.Checked:
			mark = "x"
		}
		fmt.Fprintf(w, "  %-2d [%s] %-10s %s\n", i+1, mark, it.Name, desc)
	}
}

// RenderPlan is what lox init will do, shown before the human's yes.
func RenderPlan(w io.Writer, plans []Planned, kept []Declared, skipped []string, removals []Declared) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Plan (nothing is written before your yes)")
	for _, p := range plans {
		fmt.Fprintf(w, "  %s %s\n", p.Lock, p.Instance)
		fmt.Fprintf(w, "    %s\n", strings.Join(planProfileArgs(p), " "))
		fmt.Fprintf(w, "    then %s init claude, %s doctor, lox add %s %s --profile %s\n", p.Lock, p.Lock, p.Lock, p.Instance, p.Profile)
		if len(p.AllowedUIDs) > 0 {
			fmt.Fprintf(w, "    allowed_uids %v: lea's agents run as uid %d\n", p.AllowedUIDs, p.AllowedUIDs[0])
		}
	}
	for _, d := range kept {
		fmt.Fprintf(w, "  kept: %s (%s), declared already: not changed\n", d.Instance, declDesc(d))
	}
	for _, s := range skipped {
		fmt.Fprintf(w, "  skipped: %s\n", s)
	}
	for _, d := range removals {
		fmt.Fprintf(w, "  remove: %s (%s) from lockfamily.yaml; its profile stays in .%s/\n", d.Instance, d.Lock, d.Lock)
	}
	fmt.Fprintln(w, "Then lox up shows the whole change for your review: nothing starts without your yes there.")
}

// planProfileArgs is the profile add of p as the plan shows it: the
// arguments every run has (--non-interactive --json --project) left out.
func planProfileArgs(p Planned) []string {
	a := p.ProfileArgs("")
	out := []string{p.Lock, "profile", "add"}
	skip := 0
	for i := 2; i < len(a); i++ {
		if skip > 0 {
			skip--
			continue
		}
		switch a[i] {
		case "--non-interactive", "--json":
			continue
		case "--project":
			skip = 1
			continue
		}
		out = append(out, a[i])
	}
	return slices.Clip(out)
}
