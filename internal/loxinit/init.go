// Package loxinit is `lox init`: one command that sets up the Lock
// Family in a project. It checks the prerequisites, detects the
// project's data sources from its files (read only, never a secret),
// proposes one lock per source (auto) or a checklist (manual), and, once
// the human said yes, runs each lock's launcher verbs (lockkit GUIDE.md
// §14), lox add, lox up (whose review is unchanged) and lox attach for
// the consoles' start-up questions.
package loxinit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// Init is one `lox init`.
type Init struct {
	// Root is the project (the workspace whose .lockfamily/ holds
	// lockfamily.yaml); the launchers run there.
	Root string
	Env  Env
	Run  Runner
	In   *bufio.Reader
	Out  io.Writer
	// Terminal: stdin is a terminal (questions, lox up's review and lox
	// attach need one).
	Terminal bool

	// Yes answers lox init's own questions with the flags and defaults
	// (auto mode); lox up's review still asks at the terminal.
	Yes bool
	// Manual: the checklist, not auto mode.
	Manual     bool
	Production bool
	// Credentials: CredAsk (default) or CredVault, for --yes.
	Credentials string
	// VaultPaths are the Vault path per instance (--vault-path INST=P).
	VaultPaths map[string]string
	// TLS is locksql's TLS mode for the sources whose files say none
	// (--tls; default DefaultTLS).
	TLS string
	// NoAttach: do not attach to the consoles after lox up.
	NoAttach bool

	// Declared reads the locks lockfamily.yaml declares (none when it
	// does not exist).
	Declared func() ([]Declared, error)
	// AddLock is lox add for p.
	AddLock func(ctx context.Context, p Planned) error
	// RemoveLock takes an instance out of lockfamily.yaml.
	RemoveLock func(instance string) error
	// Up is lox up, with its review.
	Up func(ctx context.Context) error
	// Consoles are the workspace's running containers, compose service
	// to container id (to see which consoles lox up started or
	// recreated).
	Consoles func(ctx context.Context) (map[string]string, error)
	// Attach is lox attach INSTANCE.
	Attach func(ctx context.Context, instance string) error

	// versions are the launchers' versions, asked once per lock type.
	versions map[string]LauncherVersions
}

// ErrDeclined is the human saying no to the plan.
var ErrDeclined = errors.New("nothing done: the plan was not confirmed")

// errQuit is the human quitting at the mode question.
var errQuit = errors.New("nothing done")

func (in *Init) say(format string, a ...any) { fmt.Fprintf(in.Out, format+"\n", a...) }

// ask prints prompt and reads one line (trimmed); def when empty.
func (in *Init) ask(prompt, def string) (string, error) {
	if !in.Terminal {
		return "", errors.New("lox init asks at a terminal; stdin is not one (pass --yes and flags to run without one)")
	}
	if def != "" {
		fmt.Fprintf(in.Out, "%s [%s] ", prompt, def)
	} else {
		fmt.Fprintf(in.Out, "%s ", prompt)
	}
	line, err := in.In.ReadString('\n')
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return "", errors.New("no answer (end of input)")
		}
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// askValue asks for a value of a target: never a secret (a value that
// embeds a password, or holds a control character, is asked again,
// without quoting it).
func (in *Init) askValue(prompt, def string) (string, error) {
	for {
		v, err := in.ask(prompt, def)
		if err != nil {
			return "", err
		}
		if why := unsafeValue(v); why != "" {
			in.say("  %s: type the target without it (the console asks for the password at its start)", why)
			continue
		}
		return v, nil
	}
}

// unsafeValue says why v cannot go on a command line ("" when it can).
func unsafeValue(v string) string {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "a control character"
		}
	}
	if u, err := url.Parse(v); err == nil && u.User != nil {
		if _, ok := u.User.Password(); ok {
			return "it embeds a password"
		}
	}
	l := strings.ToLower(v)
	if strings.Contains(l, "password=") || strings.Contains(l, "pwd=") {
		return "it embeds a password"
	}
	return ""
}

// Do runs lox init.
func (in *Init) Do(ctx context.Context) error {
	pre := CheckPrereqs(ctx, in.Env)
	in.say("lox init: %s", in.Root)
	in.say("")
	RenderPrereqs(in.Out, pre, in.Env.GOOS)
	if !pre.Ready() {
		return errors.New("prerequisites missing (above): nothing done")
	}
	decl, err := in.Declared()
	if err != nil {
		return err
	}
	RenderDeclared(in.Out, decl)
	sources, warns := Detect(in.Root)
	RenderDetected(in.Out, sources, warns)

	manual := in.Manual
	if !manual && !in.Yes {
		if len(sources) == 0 {
			in.say("")
			in.say("Nothing detected: manual mode.")
			manual = true
		} else {
			in.say("")
			m, err := in.ask("Auto (one lock per source above) or manual (a checklist)? a/m/q", "a")
			if err != nil {
				return err
			}
			switch strings.ToLower(m) {
			case "a", "auto":
			case "m", "manual":
				manual = true
			default:
				return errQuit
			}
		}
	}
	lea := pre.Lea != ""
	var plans []Planned
	var kept, removals []Declared
	var skipped []string
	if manual {
		if in.Yes {
			return errors.New("--manual is interactive: the checklist is answered at a terminal (--yes runs auto mode)")
		}
		plans, kept, removals, lea, err = in.manual(pre, decl, sources)
	} else {
		plans, kept, skipped, err = in.auto(pre, decl, sources)
	}
	if err != nil {
		return err
	}
	if err := in.common(plans); err != nil {
		return err
	}
	RenderPlan(in.Out, plans, kept, skipped, removals)
	if len(plans) == 0 && len(removals) == 0 {
		in.say("")
		in.say("Nothing to add or remove. lox up reviews and applies lockfamily.yaml as it is.")
		return nil
	}
	if !in.Yes {
		a, err := in.ask("Go on? [y/N]", "")
		if err != nil {
			return err
		}
		if strings.ToLower(a) != "y" && strings.ToLower(a) != "yes" {
			return ErrDeclined
		}
	}
	in.say("")
	failed, added := in.apply(ctx, plans)
	for _, d := range removals {
		if err := in.RemoveLock(d.Instance); err != nil {
			in.say("remove %s: %v", d.Instance, err)
			failed++
			continue
		}
		in.say("removed %s from lockfamily.yaml", d.Instance)
		added++
	}
	if added == 0 {
		return fmt.Errorf("%d lock(s) not set up (above): lockfamily.yaml not changed", failed)
	}
	if !in.Terminal {
		in.say("")
		in.say("lockfamily.yaml updated. lox up reviews the change at a terminal: run lox up, then lox attach INSTANCE for each console's questions.")
		in.end(lea)
		return failedErr(failed)
	}
	in.say("")
	in.say("lox up: review the change")
	before, _ := in.Consoles(ctx)
	if err := in.Up(ctx); err != nil {
		return err
	}
	if !in.NoAttach {
		after, err := in.Consoles(ctx)
		if err != nil {
			in.say("could not list the consoles (%v): answer their questions with lox attach INSTANCE", err)
		} else {
			in.attach(ctx, before, after)
		}
	}
	in.end(lea)
	return failedErr(failed)
}

func failedErr(n int) error {
	if n == 0 {
		return nil
	}
	return fmt.Errorf("%d lock(s) not set up (above)", n)
}

func (in *Init) end(lea bool) {
	in.say("")
	if lea {
		in.say("Run `lea` (or `claude` + `lox approve`).")
	} else {
		in.say("Run `claude` + `lox approve` (or install lea and run `lea`: %s).", strings.TrimPrefix(LeaHint, "install lea: "))
	}
}

// attach attaches to each console lox up started or recreated: it asks
// its policy (first start, or loosened) and the password it does not
// read from Vault, masked, at this terminal.
func (in *Init) attach(ctx context.Context, before, after map[string]string) {
	var insts []string
	for svc, id := range after {
		inst, ok := strings.CutPrefix(svc, "lock-")
		if ok && before[svc] != id {
			insts = append(insts, inst)
		}
	}
	sort.Strings(insts)
	if len(insts) == 0 {
		return
	}
	in.say("")
	in.say("Each console that started asks its questions here: its policy (y to approve it, on a first start) and the password it does not read from Vault (masked). Detach with Ctrl-P Ctrl-Q once it says Listening.")
	for _, n := range insts {
		in.say("")
		if err := in.Attach(ctx, n); err != nil {
			// Detaching (Ctrl-P Ctrl-Q) ends docker's attach with a non-zero
			// status too: a console still running was detached from.
			if now, cerr := in.Consoles(ctx); cerr == nil && now["lock-"+n] == after["lock-"+n] {
				in.say("detached from %s", n)
				continue
			}
			in.say("lox attach %s: %v (its console stopped: lox up, then lox attach %s)", n, err, n)
		}
	}
}

// apply runs each plan's verbs and lox add; it returns the plans that
// failed and those declared.
func (in *Init) apply(ctx context.Context, plans []Planned) (failed, added int) {
	for _, p := range plans {
		in.say("%s %s", p.Lock, p.Instance)
		if !in.applyOne(ctx, p) {
			failed++
			continue
		}
		added++
	}
	return failed, added
}

func (in *Init) applyOne(ctx context.Context, p Planned) bool {
	o := classify(in.Run.Verb(ctx, in.Root, p.Lock, p.ProfileArgs(in.Root)...))
	switch {
	case o.Profile != nil:
		cred := ""
		if o.Profile.Credentials != "" {
			cred = " (credentials " + o.Profile.Credentials + ")"
		}
		in.say("  profile add: profile %s written to %s%s", o.Profile.Profile, o.Profile.Config, cred)
	case o.Code == CodeExists:
		in.say("  profile add: profile %s is there already: kept as it is", p.Profile)
	case o.OK():
		in.say("  profile add: done")
	default:
		in.say("  profile add failed (%s): %s", o.Code, indent(o.Message))
		return false
	}
	o = classify(in.Run.Verb(ctx, in.Root, p.Lock, "init", "claude"))
	if !o.OK() {
		in.say("  init claude failed (%s): %s", o.Code, indent(o.Message))
		return false
	}
	in.say("  init claude: the agent's files written")
	in.doctor(ctx, p)
	if err := in.AddLock(ctx, p); err != nil {
		in.say("  lox add failed: %v", err)
		return false
	}
	in.say("  lox add: lock %s declared", p.Instance)
	return true
}

// doctor runs the lock's doctor --fix --yes (lockkit GUIDE.md §14) and
// shows what it repaired and what still fails; it never stops lox init
// (before lox up the console is not running yet). A launcher or image
// older than the release whose --fix leaves the lock's directory as lox
// up reads it, and a lock whose repairs lox init does not make (lockfile),
// get the doctor without --fix (doctorFixes).
func (in *Init) doctor(ctx context.Context, p Planned) {
	args, note := in.doctorArgs(ctx, p.Lock)
	fix := slices.Contains(args, "--fix")
	name := "doctor"
	if fix {
		name = "doctor --fix"
	}
	o := classify(in.Run.Verb(ctx, in.Root, p.Lock, args...))
	if note != "" {
		in.say("  %s", note)
	}
	if o.Doctor == nil {
		if !o.OK() {
			in.say("  %s could not check (%s): %s", name, o.Code, indent(o.Message))
		}
		return
	}
	for _, f := range o.Doctor.Fixed {
		in.say("  %s: fixed %s", name, f)
	}
	var ok, warn int
	var fails []Check
	for _, c := range o.Doctor.Checks {
		switch c.Status {
		case "ok":
			ok++
		case "warn":
			warn++
		default:
			fails = append(fails, c)
		}
	}
	in.say("  %s: %d ok, %d warning(s), %d failed (advisory before lox up)", name, ok, warn, len(fails))
	for _, c := range fails {
		line := "    " + c.Check + ": " + c.Detail
		if c.Fix != "" {
			line += " (" + c.Fix + ")"
		}
		in.say("%s", line)
	}
	if why := noFixReason(p.Lock); why != "" && slices.ContainsFunc(o.Doctor.Checks, func(c Check) bool {
		return c.Status != "ok" && strings.Contains(c.Fix, "--fix")
	}) {
		in.say("    lox init does not run %s doctor --fix: %s (run it yourself if you want that)", p.Lock, why)
	}
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n    ") }

// auto plans one lock per detected source the machine can serve.
func (in *Init) auto(pre Prereqs, decl []Declared, sources []Source) (plans []Planned, kept []Declared, skipped []string, err error) {
	taken := func(n string) bool {
		return slices.ContainsFunc(decl, func(d Declared) bool { return d.Instance == n }) ||
			slices.ContainsFunc(plans, func(p Planned) bool { return p.Instance == n })
	}
	for i := range sources {
		s := sources[i]
		lock := s.Lock()
		name := SuggestName(s)
		if k := keptBy(decl, lock, name); k != nil {
			if !slices.Contains(kept, *k) {
				kept = append(kept, *k)
			}
			continue
		}
		switch {
		case pre.Launchers[lock] == "":
			skipped = append(skipped, fmt.Sprintf("%s %s: %s", s.Label(), s.Target(), LauncherHint(lock)))
			continue
		case s.Unpublished:
			skipped = append(skipped, fmt.Sprintf("%s %s: not reachable from a lock's console (see its note)", s.Label(), s.Target()))
			continue
		}
		p := Planned{Lock: lock, Instance: uniqueName(name, taken), Profile: name, Source: &sources[i],
			AllowedUIDs: uidsFor(lock, pre.Lea != "", in.Env.UID)}
		plans = append(plans, p)
	}
	return plans, kept, skipped, nil
}

// common asks what auto mode asks (environment, where passwords come
// from, TLS when the files say none) and fills the plans' flags. With
// --yes the flags give the answers.
func (in *Init) common(plans []Planned) error {
	if len(plans) == 0 {
		return nil
	}
	prod := in.Production
	cred := in.Credentials
	if cred == "" {
		cred = CredAsk
	}
	if !in.Yes {
		in.say("")
		envAns, err := in.ask("Environment of these locks: dev or prod?", map[bool]string{true: "prod", false: "dev"}[prod])
		if err != nil {
			return err
		}
		switch strings.ToLower(envAns) {
		case "prod", "production":
			prod = true
		case "dev", "development":
			prod = false
		default:
			return errors.New("environment: want dev or prod")
		}
		if slices.ContainsFunc(plans, credentialsApply) {
			c, err := in.ask("Passwords: asked by each console at its start (ask), or read from Vault (vault)?", cred)
			if err != nil {
				return err
			}
			if c != CredAsk && c != CredVault {
				return errors.New("passwords: want ask or vault")
			}
			cred = c
		}
	}
	for i := range plans {
		p := &plans[i]
		p.Production = prod
		if credentialsApply(*p) {
			p.Credentials = cred
			if cred == CredVault {
				vp := in.VaultPaths[p.Instance]
				if vp == "" {
					if in.Yes {
						return fmt.Errorf("--credentials vault: give --vault-path %s=PATH", p.Instance)
					}
					v, err := in.askValue(fmt.Sprintf("Vault path of %s's login (such as database/creds/%s):", p.Instance, p.Instance), "")
					if err != nil {
						return err
					}
					vp = v
				}
				p.VaultPath = vp
			}
		}
		if p.Source == nil || len(p.Target) > 0 {
			continue
		}
		s := *p.Source
		if p.Lock == "lockmq" {
			p.Target = MQTarget(s)
			continue
		}
		tls := s.TLS
		if tls == "" {
			tls = in.TLS
		}
		if tls == "" {
			def := DefaultTLS(s, prod)
			if in.Yes {
				tls = def
				in.say("%s %s: TLS %s (not in the files; --tls to change)", s.Label(), s.Target(), tls)
			} else {
				t, err := in.ask(fmt.Sprintf("TLS to %s %s (%s)?", s.Label(), s.Target(), strings.Join(TLSModes, ", ")), def)
				if err != nil {
					return err
				}
				if !slices.Contains(TLSModes, t) {
					return fmt.Errorf("TLS: want one of %s", strings.Join(TLSModes, ", "))
				}
				tls = t
			}
		}
		p.Target = SQLTarget(s, tls)
	}
	return nil
}

// credentialsApply: the lock's target has a secret the console gets
// (asked at its start, or from Vault).
func credentialsApply(p Planned) bool {
	switch p.Lock {
	case "lockhttp":
		return false
	case "lockfile":
		return !slices.Contains(p.Target, "local")
	case "locksql":
		return !slices.Contains(p.Target, "sqlite")
	}
	return true
}
