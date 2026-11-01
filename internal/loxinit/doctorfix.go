package loxinit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// doctorFix is how lox init runs a lock's doctor: with --fix --yes
// (lockkit GUIDE.md §14) or, for the locks absent from doctorFixes,
// without --fix (advisory).
type doctorFix struct {
	// Min is the first release whose doctor --fix leaves the lock's
	// directory as lox up reads it ("" when every release with the
	// launcher verbs does). An older launcher or image gets the advisory
	// doctor.
	Min string
	// Also is what --fix does besides the repairs lox up needs, shown on
	// the plan ("" when nothing).
	Also string
}

// doctorFixes are the locks whose doctor lox init runs with --fix.
//
//   - locksql and lockmq up to v0.13.0 / v0.6.0 gave the lock's directory
//     to the console account, which lox up then refused (it copies a
//     profile only from the user's own files): fixed in v0.13.1 / v0.6.1.
//     locksql's --fix also wires the installed agents for the user's
//     account.
//   - lockhttp's --fix (v0.7.0, its first release with the verbs) only
//     takes group and others' write away from the policy.
//   - lockfile is left out: its only repair (v0.6.0) wires every installed
//     agent for the user's account, nothing lox up needs, so lox init does
//     not make it behind the user's back (lockfile doctor --fix does it).
var doctorFixes = map[string]doctorFix{
	"locksql":  {Min: "0.13.1", Also: "it also wires your installed agents for your account"},
	"lockmq":   {Min: "0.6.1"},
	"lockhttp": {},
}

// noFixReason says why lox init runs no doctor --fix for lock at all ("" when
// it may, subject to the versions).
func noFixReason(lock string) string {
	if _, ok := doctorFixes[lock]; ok {
		return ""
	}
	if lock == "lockfile" {
		return "its only repair wires every installed agent for your account"
	}
	return "lox init does not run its repairs"
}

// LauncherVersions is what `<lock> version` prints: the launcher's version
// ("dev" for a launcher run from a clone) and its image's ("" when the image
// did not answer).
type LauncherVersions struct {
	Launcher, Image string
}

// parseVersions reads `<lock> version`: "<lock> launcher V (image REF)",
// then the image's "<lock> V".
func parseVersions(lock string, stdout []byte) LauncherVersions {
	var v LauncherVersions
	for _, l := range strings.Split(string(stdout), "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) >= 3 && f[0] == lock && f[1] == "launcher":
			v.Launcher = f[2]
		case len(f) == 2 && f[0] == lock:
			v.Image = f[1]
		}
	}
	return v
}

// semver parses vMAJOR.MINOR.PATCH (the v optional); pre is true for a
// pre-release or build suffix, which sorts before its release.
func semver(s string) (v [3]int, pre, ok bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s, pre = s[:i], true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false, false
		}
		v[i] = n
	}
	return v, pre, true
}

// atLeast reports whether version is a release at or after min.
func atLeast(version, min string) bool {
	v, pre, ok := semver(version)
	m, _, mok := semver(min)
	if !ok || !mok {
		return false
	}
	for i := range v {
		if v[i] != m[i] {
			return v[i] > m[i]
		}
	}
	return !pre
}

// fixRefusal says why v cannot run the doctor --fix of a lock whose fixed
// release is min ("" when it can). The image makes the repairs: it must be
// a release at or after min. The launcher too, or "dev" (a clone, which
// runs the image it is given).
func fixRefusal(lock, min string, v LauncherVersions) string {
	switch {
	case v.Launcher == "" && v.Image == "":
		return fmt.Sprintf("%s version did not say its versions", lock)
	case v.Launcher != "dev" && !atLeast(v.Launcher, min):
		return fmt.Sprintf("launcher %s is older than v%s", orUnknown(v.Launcher), min)
	case !atLeast(v.Image, min):
		return fmt.Sprintf("image %s is older than v%s", orUnknown(v.Image), min)
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "of unknown version"
	}
	return s
}

// doctorArgs are the arguments of the lock's doctor, and the note shown
// when lox init falls back to the advisory doctor ("" otherwise).
func (in *Init) doctorArgs(ctx context.Context, lock string) (args []string, note string) {
	f, ok := doctorFixes[lock]
	if !ok {
		return []string{"doctor", "--json"}, ""
	}
	if f.Min != "" {
		if in.versions == nil {
			in.versions = map[string]LauncherVersions{}
		}
		v, seen := in.versions[lock]
		if !seen {
			out, _, _, err := in.Run.Verb(ctx, in.Root, lock, "version")
			if err == nil {
				v = parseVersions(lock, out)
			}
			in.versions[lock] = v
		}
		if why := fixRefusal(lock, f.Min, v); why != "" {
			return []string{"doctor", "--json"}, fmt.Sprintf(
				"lox init runs %s doctor without --fix: %s, whose doctor --fix gives .%s/ to the console account (lox up then refuses it); update %s to v%s or later, then run %s doctor --fix",
				lock, why, lock, lock, f.Min, lock)
		}
	}
	return []string{"doctor", "--fix", "--yes", "--json"}, ""
}
