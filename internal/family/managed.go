package family

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/managed"
)

// The company's managed configuration (lockkit managed, lockfamily
// docs/managed.md): one root-owned file on the host that bounds every
// lock, lox and lea. lox run reads it on the host, copies it read-only
// into every lock's container (the volume managed, at ManagedDir), checks
// each lock against it before starting it, and applies its [lox] section:
// AUTO ceilings, --no-upgrade, minimum images and the egress allowlist.

// ManagedDir is where the locks read the managed file in their
// containers: managed.DefaultPath()'s directory on Linux, whatever the
// host's OS.
const ManagedDir = "/etc/lockfamily"

// maxManaged bounds each file of the managed directory lox copies.
const maxManaged = 256 << 10

// ManagedError is the managed file refusing lox run as a whole (badly
// owned, invalid, a signature that does not verify, a [lox] section lox
// does not take, --no-upgrade forbidden): nothing starts, exit 3.
type ManagedError struct{ Err error }

func (e *ManagedError) Error() string { return e.Err.Error() }
func (e *ManagedError) Unwrap() error { return e.Err }

// LoxPolicy is the managed file's [lox] section.
type LoxPolicy struct {
	// AutoMax is the loosest verdict of lox run's AUTO mode per action
	// (auto, ask, deny); ProductionAutoMax the same for a production
	// ticket, applied with AutoMax (the stricter wins).
	AutoMax           map[string]string `toml:"auto_max"`
	ProductionAutoMax map[string]string `toml:"production_auto_max"`
	// AllowNoUpgrade false forbids lox run --no-upgrade (default true).
	AllowNoUpgrade *bool `toml:"allow_no_upgrade"`
	// ImageMin is the oldest release lox may run, per lock type.
	ImageMin map[string]string `toml:"image_min"`
	// Egress are the host:port patterns a lock may reach: an endpoint of
	// a lock's profile outside them keeps that lock from starting.
	Egress []string `toml:"egress"`
}

// CapActions are the actions [lox] auto_max and production_auto_max cap.
var CapActions = []string{"connect", "read", "write", "ddl", "endpoint", "policy", "action"}

// capValues order the verdicts, strictest first.
var capValues = []string{"deny", "ask", "auto"}

func (p *LoxPolicy) validate() error {
	for _, t := range []struct {
		key string
		m   map[string]string
	}{{"auto_max", p.AutoMax}, {"production_auto_max", p.ProductionAutoMax}} {
		for _, a := range slices.Sorted(maps.Keys(t.m)) {
			if !slices.Contains(CapActions, a) {
				return fmt.Errorf("lox.%s: unknown action %q (want one of %s)", t.key, a, strings.Join(CapActions, ", "))
			}
			if !slices.Contains(capValues, t.m[a]) {
				return fmt.Errorf("lox.%s.%s: want auto, ask or deny", t.key, a)
			}
		}
	}
	for _, typ := range slices.Sorted(maps.Keys(p.ImageMin)) {
		if !slices.Contains(Types, typ) {
			return fmt.Errorf("lox.image_min: unknown lock %q (want one of %s)", typ, strings.Join(Types, ", "))
		}
		if !semverTag.MatchString(p.ImageMin[typ]) {
			return fmt.Errorf("lox.image_min.%s: want a release tag vX.Y.Z", typ)
		}
	}
	if p.Egress != nil && len(p.Egress) == 0 {
		// An empty list allows nothing: say so rather than guess.
		return errors.New("lox.egress: an empty list would let no lock reach anything: remove the key, or list the host:port patterns allowed")
	}
	for i, e := range p.Egress {
		if _, _, err := egressPattern(e); err != nil {
			return fmt.Errorf("lox.egress[%d]: %w", i, err)
		}
	}
	return nil
}

// egressPattern splits a [lox] egress pattern: a host (a DNS name, *.name
// for any name under it, or * for any) and a port (a number, or *: -1).
func egressPattern(s string) (string, int, error) {
	bad := fmt.Errorf("%q: want host:port, the host a DNS name, *.name or *, the port a number or *", s)
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, bad
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	name := strings.TrimPrefix(h, "*.")
	if h != "*" && !hostName.MatchString(name) {
		return "", 0, bad
	}
	if p == "*" {
		return h, -1, nil
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, bad
	}
	return h, port, nil
}

// egressAllowed reports whether [lox] egress allows host:port.
func egressAllowed(patterns []string, host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range patterns {
		h, p, err := egressPattern(s)
		if err != nil || (p != -1 && p != port) {
			continue
		}
		switch {
		case h == "*", h == host:
			return true
		case strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]):
			return true
		}
	}
	return false
}

// Managed is the host's managed file as lox run applies it.
type Managed struct {
	File *managed.File
	Lox  LoxPolicy
	// The bytes lox read and checked against what lockkit verified: the
	// file, and when signed its bundle, signer.toml and the verified
	// stamp lox writes for the locks (VerifiedStamp).
	data, bundle, signer []byte
	stamp                string
	// key names everything copied (file, bundle, signer): a change of any
	// recreates the locks.
	key string
}

// LoadManaged reads the host's managed file (lockkit's managed.Load:
// root-owned, valid, signature verified) and its [lox] section, strictly.
// nil and no error: there is none. Every refusal is a *ManagedError.
func LoadManaged(ctx context.Context) (*Managed, error) {
	f, err := managed.Load(ctx)
	if err != nil {
		return nil, &ManagedError{err}
	}
	if f == nil {
		return nil, nil
	}
	m := &Managed{File: f}
	if _, err := f.Decode(&m.Lox, "lox"); err != nil {
		return nil, &ManagedError{err}
	}
	if err := m.Lox.validate(); err != nil {
		return nil, &ManagedError{fmt.Errorf("managed: %s: %w", f.Path, err)}
	}
	if err := m.read(); err != nil {
		return nil, &ManagedError{err}
	}
	if v := f.Family.Vault; v != nil && v.Address != "" {
		if err := ValidateVaultAddress(v.Address); err != nil {
			return nil, &ManagedError{fmt.Errorf("managed: %s: [family] vault: %w", f.Path, err)}
		}
		if err := ValidateVaultNamespace(v.Namespace); err != nil {
			return nil, &ManagedError{fmt.Errorf("managed: %s: [family] vault: %w", f.Path, err)}
		}
	}
	return m, nil
}

// read reads the bytes lox copies into the locks' containers, and checks
// they are the ones lockkit read and verified: a file changed meanwhile
// is refused, never copied unverified.
func (m *Managed) read() error {
	f := m.File
	dir := filepath.Dir(f.Path)
	changed := fmt.Errorf("managed: %s changed while lox read it: lox run again", f.Path)
	rd := func(name string) ([]byte, error) {
		b, err := readLimited(filepath.Join(dir, name), maxManaged)
		if err != nil {
			return nil, fmt.Errorf("managed: %w", err)
		}
		return b, nil
	}
	var err error
	if m.data, err = rd(managed.FileName); err != nil {
		return err
	}
	if s := sha256.Sum256(m.data); hex.EncodeToString(s[:]) != f.Fingerprint {
		return changed
	}
	h := sha256.New()
	if f.Signed {
		if m.bundle, err = rd(managed.BundleName); err != nil {
			return err
		}
		if m.signer, err = rd(managed.SignerName); err != nil {
			return err
		}
		if m.stamp, err = managed.VerifiedStamp(f); err != nil {
			// A lockkit without the stamp (lockkit#175) cannot vouch for
			// the signature inside a container: refused, not copied.
			return fmt.Errorf("managed: %s is signed, but this lox cannot vouch for its signature inside the locks' containers (%w): upgrade lox", f.Path, err)
		}
	}
	// lockkit's key: the file, its bundle and signer.toml, each prefixed
	// with its length. Signed, it must be the stamp's.
	for _, b := range [][]byte{m.data, m.bundle, m.signer} {
		fmt.Fprintf(h, "%d:", len(b))
		h.Write(b)
	}
	m.key = "sha256:" + hex.EncodeToString(h.Sum(nil))
	if f.Signed && m.key != m.stamp {
		return changed
	}
	return nil
}

// readLimited reads a regular file (links not followed) of at most max
// bytes.
func readLimited(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	b, err := io.ReadAll(io.LimitReader(fd, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes", path, max)
	}
	return b, nil
}

// Fingerprint names what lox copies into the locks (nil: "").
func (m *Managed) Fingerprint() string {
	if m == nil {
		return ""
	}
	return m.key
}

// Line is the review's managed line.
func (m *Managed) Line() string {
	if m == nil {
		return "managed: none"
	}
	s := fmt.Sprintf("managed: %s sha256:%s", m.org(), m.File.Fingerprint[:12])
	if m.File.Signed {
		s += " signed"
	}
	return s
}

func (m *Managed) org() string {
	if m.File.Organisation == "" {
		return "the company"
	}
	return m.File.Organisation
}

// AllowNoUpgrade reports whether lox run --no-upgrade is allowed.
func (m *Managed) AllowNoUpgrade() bool {
	return m == nil || m.Lox.AllowNoUpgrade == nil || *m.Lox.AllowNoUpgrade
}

// CheckNoUpgrade refuses lox run --no-upgrade when [lox] forbids it.
func (m *Managed) CheckNoUpgrade() error {
	if m.AllowNoUpgrade() {
		return nil
	}
	return &ManagedError{errors.New("--no-upgrade: blocked by company policy: lox.allow_no_upgrade = false")}
}

// Tar is the managed directory lox copies into the volume managed: the
// file and, signed, its bundle, signer.toml and the verified stamp, each
// root's, 0644.
func (m *Managed) Tar() []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg, Format: tar.FormatPAX})
		tw.Write(b)
	}
	add(managed.FileName, m.data)
	if m.File.Signed {
		add(managed.BundleName, m.bundle)
		add(managed.SignerName, m.signer)
		add(managed.VerifiedName, []byte(m.stamp+"\n"))
	}
	tw.Close()
	return buf.Bytes()
}

// imageMinRefusal is why lock n (type typ, release tag; "" unknown) is not
// started under [lox] image_min, or "".
func (m *Managed) imageMinRefusal(typ, tag string) string {
	if m == nil {
		return ""
	}
	min, ok := m.Lox.ImageMin[typ]
	switch {
	case !ok:
		return ""
	case tag == "":
		return fmt.Sprintf("blocked by company policy: lox.image_min.%s = %s (the image's release is unknown: its signature names none)", typ, min)
	case semverLess(tag, min):
		return fmt.Sprintf("blocked by company policy: lox.image_min.%s = %s (the image is %s %s)", typ, min, typ, tag)
	}
	return ""
}

// egressRefusal is why lock n is not started under [lox] egress (e its
// allowlist), or "". lockhttp's egress is its own policy's, bounded by
// its own [lockhttp] section: not checked here.
func (m *Managed) egressRefusal(n string, e Egress) string {
	if m == nil || m.Lox.Egress == nil || e.Own {
		return ""
	}
	for _, ep := range e.Endpoints {
		if !egressAllowed(m.Lox.Egress, ep.Host, ep.Port) {
			return fmt.Sprintf("blocked by company policy: lox.egress does not allow %s (lock %s)", ep.Addr(), n)
		}
	}
	return ""
}

// checkRefusal is why a lock is not started from its `<type> managed
// check` (out its output, err the run's error; "" when it passes). An
// image that does not know the command passes only when the managed file
// has no section for its type.
func (m *Managed) checkRefusal(typ, tag string, out []byte, err error) string {
	if err == nil {
		return ""
	}
	var stderr []byte
	var re *RunError
	if errors.As(err, &re) {
		stderr = re.Stderr
	}
	all := string(out) + "\n" + string(stderr)
	if strings.Contains(all, "unknown command") {
		if !m.File.Has(typ) {
			return ""
		}
		v := tag
		if v == "" {
			v = "(release unknown)"
		}
		return fmt.Sprintf("%s %s predates managed support: upgrade it or set [lox] image_min", typ, v)
	}
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) && ec.ExitCode() == 3 {
		if l := firstLine(string(out), "blocked by company policy:"); l != "" {
			return l
		}
		if l := firstLine(all, ""); l != "" {
			return "blocked by company policy: " + l
		}
		return "blocked by company policy (" + typ + " managed check gave no reason)"
	}
	return fmt.Sprintf("%s managed check failed: %v", typ, err)
}

// firstLine is the first non-empty line of s that starts with prefix,
// sanitised for the terminal.
func firstLine(s, prefix string) string {
	for l := range strings.Lines(s) {
		l = strings.TrimSpace(l)
		if l != "" && strings.HasPrefix(l, prefix) {
			return sanitizeLine(l)
		}
	}
	return ""
}

// sanitizeLine drops the control characters of a line a lock's image
// printed, and bounds it.
func sanitizeLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// applyVault puts [family] vault in place of the workspace's vault: block
// for the locks with vault: true (the locks enforce required themselves).
func (m *Managed) applyVault(c *Config) {
	if m == nil || m.File.Family.Vault == nil || m.File.Family.Vault.Address == "" {
		return
	}
	v := m.File.Family.Vault
	c.Vault = &Vault{Address: v.Address, Namespace: TrimVaultNamespace(v.Namespace), CAFile: v.CA}
}

// vaultLine is the review line of [family] vault ("" when none).
func (m *Managed) vaultLine() string {
	if m == nil || m.File.Family.Vault == nil || m.File.Family.Vault.Address == "" {
		return ""
	}
	v := m.File.Family.Vault
	s := "vault from the managed configuration ([family] vault): " + v.Address
	if v.Namespace != "" {
		s += " namespace " + v.Namespace
	}
	if v.Required {
		s += ", required"
	}
	return s
}

// Show is lox managed show's text.
func (m *Managed) Show() []string {
	if m == nil {
		return []string{"no managed configuration"}
	}
	f := m.File
	signed := "no"
	if f.Signed {
		signed = "yes"
	}
	org := f.Organisation
	if org == "" {
		org = "none"
	}
	out := []string{f.Describe(), "path: " + f.Path, "organisation: " + org, "fingerprint: sha256:" + f.Fingerprint, "signed: " + signed}
	var rules []string
	for _, t := range []struct {
		key string
		m   map[string]string
	}{{"auto_max", m.Lox.AutoMax}, {"production_auto_max", m.Lox.ProductionAutoMax}, {"image_min", m.Lox.ImageMin}} {
		for _, k := range slices.Sorted(maps.Keys(t.m)) {
			rules = append(rules, fmt.Sprintf("  %s.%s = %s", t.key, k, t.m[k]))
		}
	}
	if m.Lox.AllowNoUpgrade != nil {
		rules = append(rules, fmt.Sprintf("  allow_no_upgrade = %t", *m.Lox.AllowNoUpgrade))
	}
	if m.Lox.Egress != nil {
		rules = append(rules, "  egress = "+strings.Join(m.Lox.Egress, ", "))
	}
	if len(rules) == 0 {
		out = append(out, "lox: none")
	} else {
		out = append(out, "lox:")
		out = append(out, rules...)
	}
	if l := m.vaultLine(); l != "" {
		out = append(out, l)
	}
	var tools []string
	for _, t := range append(slices.Clone(Types), "lea") {
		if f.Has(t) {
			tools = append(tools, t)
		}
	}
	slices.Sort(tools)
	if len(tools) == 0 {
		out = append(out, "sections: none")
	} else {
		out = append(out, "sections: "+strings.Join(tools, ", "))
	}
	return out
}

// shortFP is a fingerprint as the review shows it ("none" for none).
func shortFP(fp string) string {
	if fp == "" {
		return "none"
	}
	h := strings.TrimPrefix(fp, "sha256:")
	return "sha256:" + h[:min(12, len(h))]
}

// checkManaged applies the managed file to the locks before anything is
// started: a lock whose image is older than [lox] image_min, or whose own
// `<type> managed check` refuses its reviewed profile, is not started
// (skip). The managed file is copied into its volume first: it is the
// admin's, applied without a question, and the check reads it there, as
// the lock will.
func (u *Up) checkManaged(ctx context.Context, m *Managed, c *Config, project string, paths *Paths, profiles map[string]*Profile, tags map[string]string, notStarted map[string]string, skip func(n, why string) error) error {
	paths.Managed = m.Fingerprint()
	res := u.Resolve
	if res == nil {
		res = u.Upgrade
	}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		if _, ok := m.Lox.ImageMin[l.Type]; !ok || notStarted[n] != "" {
			continue
		}
		tag := tags[l.Image]
		if tag == "" && !u.Probe {
			v := ""
			if l.Vault {
				v = "vault"
			}
			if tag = res.releaseOf(ctx, l.Type, v, l.Image); tag != "" {
				tags[l.Image] = tag
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if why := m.imageMinRefusal(l.Type, tag); why != "" {
			if err := skip(n, why); err != nil {
				return err
			}
		}
	}
	if u.Probe {
		// A probe creates nothing: the checks run with lox run.
		return nil
	}
	composeYAML := []byte(Compose(c, *paths))
	if _, err := u.runSetup(ctx, project, composeYAML, m.Tar(), "managed"); err != nil {
		return fmt.Errorf("the managed file for the locks: %w", err)
	}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		if notStarted[n] != "" {
			continue
		}
		out, err := u.runSetup(ctx, project, composeYAML, profiles[l.Type].Tar, "managedcheck-"+n)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if why := m.checkRefusal(l.Type, tags[l.Image], out, err); why != "" {
			if err := skip(n, why); err != nil {
				return err
			}
		}
	}
	return nil
}
