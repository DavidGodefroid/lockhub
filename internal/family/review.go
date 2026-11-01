package family

import (
	"fmt"
	"io"
	"strings"
)

// The short review shows, per lock, what a human decides on (image,
// target, environment, credentials, production, profile sha256). It is
// display only: the fingerprint stays over the full summary, and every
// summary line the short form does not render is listed under "Other
// changes since the last lox up:", so no change escapes the review.

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
		if creds == "vault" {
			creds = "vault, " + strings.TrimSpace(f.VaultPath)
			if f.VaultPath == "" {
				creds = "vault, (no vault_path in the profile)"
			}
		} else if creds == "ask" {
			creds = "ask, typed at the console's start"
		}
		row("credentials", creds)
		prod := "no"
		if f.Production {
			prod = "yes"
		}
		row("production", prod)
		if f.Profile != "" {
			row("profile", f.Profile+"  (lox up --review prints it in full)")
		}
	}
	if len(changed) > 0 {
		fmt.Fprintln(w, "Other changes since the last lox up:")
		for _, l := range changed {
			fmt.Fprintln(w, "  "+l)
		}
	}
}

// shortCovered are the summary lines the short blocks of the shown locks
// render (see Summary and the profile lines in Up.Do).
func shortCovered(c *Config, focus, ws string, profiles map[string]*Profile, shown map[string][]string) map[string]bool {
	cov := map[string]bool{}
	for _, n := range shortLocks(c, focus) {
		l := c.Locks[n]
		cov[fmt.Sprintf("lock %s image %s", n, l.Image)] = true
		if l.Vault && c.Vault != nil {
			cov[fmt.Sprintf("lock %s vault VAULT_ADDR=%s", n, c.Vault.Address)] = true
			if c.Vault.Namespace != "" {
				cov[fmt.Sprintf("lock %s vault VAULT_NAMESPACE=%s", n, c.Vault.Namespace)] = true
			}
		}
		if p := profiles[l.Type]; p != nil {
			cov[fmt.Sprintf("profile %s %s %s", l.Type, profileDir(ws, l.Type), p.Fingerprint)] = true
			for _, line := range shown[n] {
				cov[fmt.Sprintf("profile %s %s", l.Type, line)] = true
			}
		}
	}
	return cov
}

// lockProfile is the profile a lock's console serves: the one named in
// lockfamily.yaml, "default" for lockfile, else the only one of config.toml.
func lockProfile(l Lock) string {
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
const vaultCANote = "vault CA changed: the locks with vault: true restart (lox attach NAME for what they ask)"
