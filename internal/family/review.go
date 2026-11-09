package family

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// The short review shows, per lock, what a human decides on (image,
// target, environment, credentials, production, profile sha256). It is
// display only: the fingerprint stays over the full summary, and every
// summary line the short form does not render is listed under "Other
// changes since the last lox run:", so no change escapes the review.

// shortLocks are the locks the short review shows: the focus alone, or all.
func shortLocks(c *Config, focus string) []string {
	if focus == "" {
		return c.Instances()
	}
	if _, ok := c.Locks[focus]; ok {
		return []string{focus}
	}
	return nil
}

// renderShort writes one block per lock (the focus lock, or all of them),
// then the changes the blocks do not render.
func renderShort(w io.Writer, c *Config, focus string, facts map[string]Facts, imagesOK bool, changed []string) {
	renderShortAs(w, c, focus, facts, imagesOK, changed, "Other changes since the last lox run:")
}

// renderShortAs is renderShort with the heading of the lines no block renders.
func renderShortAs(w io.Writer, c *Config, focus string, facts map[string]Facts, imagesOK bool, changed []string, heading string) {
	row := func(k, v string) { fmt.Fprintf(w, "  %-13s%s\n", k, v) }
	for _, n := range shortLocks(c, focus) {
		l, f := c.Locks[n], facts[n]
		sig := "(signature verified)"
		if !imagesOK {
			sig = "(signature NOT verified)"
		}
		fmt.Fprintf(w, "lock %s (%s)\n", n, l.Type)
		row("image", l.Image+" "+sig)
		target := f.Target
		if target == "" {
			target = "(none named in the profile)"
		}
		row("target", target)
		env := "none"
		if l.Vault && c.Vault != nil {
			env = "VAULT_ADDR=" + c.Vault.Address
			if c.Vault.Namespace != "" {
				env += ", VAULT_NAMESPACE=" + c.Vault.Namespace
			}
		}
		row("environment", env)
		creds := f.Credentials
		if creds == "" {
			creds = "ask"
			if l.Vault {
				creds = "vault"
			}
		}
		switch {
		case f.Odd["credentials"] != "":
			creds = "? (" + f.Odd["credentials"] + " in the profile)"
		case creds == "vault":
			switch {
			case f.Odd["vault_path"] != "":
				creds = "vault, ? (" + f.Odd["vault_path"] + " in the profile)"
			case f.VaultPath == "":
				creds = "vault, (no vault_path in the profile)"
			default:
				creds = "vault, " + f.VaultPath
			}
		case creds == "ask":
			creds = "ask, typed at the console's start"
		}
		row("credentials", creds)
		prod := "no"
		if f.Production {
			prod = "yes"
		}
		if o := f.Odd["production"]; o != "" {
			prod = "? (" + o + " in the profile)"
		}
		row("production", prod)
		if f.Egress != "" {
			row("egress", f.Egress)
		}
		for _, r := range f.Unreachable {
			row("unreachable", "WARNING: "+r)
		}
		for _, r := range f.Files {
			row("file", "WARNING: "+r)
		}
		if f.Profile != "" {
			note := "(lox run --review prints it in full)"
			if f.Changed {
				note = "(changed since the last lox run; lox run --review shows the lines)"
			}
			row("profile", f.Profile+"  "+note)
		}
	}
	if len(changed) > 0 {
		fmt.Fprintln(w, heading)
		for _, l := range changed {
			fmt.Fprintln(w, "  "+l)
		}
	}
}

// shortCovered are the summary lines the short blocks of the shown locks
// render (see Summary and the profile lines in Up.Do). A block's profile
// line stands for every line of its type's profile: the sha256 covers
// every byte of it, and lox run --review shows the lines.
func shortCovered(c *Config, focus string, sum []string) map[string]bool {
	cov := map[string]bool{}
	pre := map[string]bool{}
	for _, n := range shortLocks(c, focus) {
		l := c.Locks[n]
		pre["profile "+l.Type+" "] = true
		// The egress row renders the lock's allowlist lines.
		pre["lock "+n+" egress "] = true
		cov[fmt.Sprintf("lock %s type %s", n, l.Type)] = true
		cov[fmt.Sprintf("lock %s image %s", n, l.Image)] = true
		if l.Profile != "" {
			cov[fmt.Sprintf("lock %s profile %s", n, l.Profile)] = true
		}
		if l.Vault && c.Vault != nil {
			cov[fmt.Sprintf("lock %s vault VAULT_ADDR=%s", n, c.Vault.Address)] = true
			if c.Vault.Namespace != "" {
				cov[fmt.Sprintf("lock %s vault VAULT_NAMESPACE=%s", n, c.Vault.Namespace)] = true
			}
		}
	}
	for _, l := range sum {
		for p := range pre {
			if strings.HasPrefix(l, p) {
				cov[l] = true
			}
		}
	}
	return cov
}

// shortChanged keeps the lines of the diff d that the short review lists.
// A removed line is always listed. An added line a block renders is not,
// but for a profile's: the block's profile row shows its sha256, not its
// values, so the new value of a profile line is listed under its old one
// (lockhub#173).
func shortChanged(c *Config, focus string, d []string, cov map[string]bool) []string {
	var prof []string
	for _, n := range shortLocks(c, focus) {
		prof = append(prof, "profile "+c.Locks[n].Type+" ")
	}
	var out []string
	for _, l := range d {
		rest, added := strings.CutPrefix(l, "+ ")
		if !added || !cov[rest] || slices.ContainsFunc(prof, func(p string) bool { return strings.HasPrefix(rest, p) }) {
			out = append(out, l)
		}
	}
	return out
}

// LockProfile is the profile a lock's console serves: the one named in
// lockfamily.yaml, "default" for lockfile, else the only one of config.toml.
func LockProfile(l Lock) string {
	if l.Profile != "" {
		return l.Profile
	}
	if l.Type == "lockfile" {
		return "default"
	}
	return ""
}

// uncovered keeps the lines of lines that no block renders.
func uncovered(lines []string, cov map[string]bool) []string {
	var out []string
	for _, l := range lines {
		if !cov[l] {
			out = append(out, l)
		}
	}
	return out
}

// caChanged tells whether a diff line adds or removes the Vault CA.
func caChanged(d []string) bool {
	for _, l := range d {
		if strings.HasPrefix(l, "- vault ca_file ") || strings.HasPrefix(l, "+ vault ca_file ") {
			return true
		}
	}
	return false
}

// vaultCANote is said once when the reviewed Vault CA changes.
const vaultCANote = "vault CA changed: the locks with vault: true restart (lox run asks what they ask)"
