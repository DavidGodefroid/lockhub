package family

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// lox run's automatic upgrade (lockhub#118): at start, the hub and lock
// images the workspace pins are compared with the releases this lox ships
// with; an older one is replaced by the shipped release's image, by its
// digest, once cosign verified it was signed by that release's own
// workflow run. Fail closed: an image that cannot be resolved or verified
// keeps the old one, which was verified above, and says why.

// ShippedLocks are the lock releases this lox ships with: what lox run
// upgrades an older pinned lock image to. Bumped when lox is released
// (the release notes say so); the hub's is lox's own version.
var ShippedLocks = map[string]string{
	"locksql":  "v0.18.1",
	"lockmq":   "v0.9.0",
	"lockfile": "v0.9.1",
	"lockhttp": "v0.9.1",
	"locklog":  "v0.3.0",
	"lockssh":  "v0.2.0",
}

// ShippedPins are the releases a lox of version (X.Y.Z, without the v)
// ships with, by repository: ShippedLocks, and lockhub at lox's own
// version (the hub and lox are released together). A development build
// ("dev") pins no hub.
func ShippedPins(version string) map[string]string {
	p := map[string]string{}
	for k, v := range ShippedLocks {
		p[k] = v
	}
	if v := "v" + strings.TrimPrefix(version, "v"); semverTag.MatchString(v) {
		p["lockhub"] = v
	}
	return p
}

// Upgrade is lox run's automatic upgrade of the pinned images.
type Upgrade struct {
	// Pins are the release tags to upgrade to, by repository (lockhub, a
	// lock type): ShippedPins. A repository not named is left as it is.
	Pins map[string]string
	// Image is the image of repo's release tag (variant "" or "vault"),
	// by digest, once cosign verified its signature by that release's
	// workflow run for that tag (Releases.ImageVariant).
	Image func(ctx context.Context, repo, tag, variant string) (string, error)
	// Tags (Releases.Tags) and Digest (Releases.Digest, unverified) find
	// the release of a pinned image whose signature does not name it
	// (the sigstore bundle format has no certificate subject in cosign
	// verify's output, lockhub#176): the release whose image has its
	// digest, once Image verified it for that release. Unset, such an
	// image is not upgraded.
	Tags   func(ctx context.Context, repo string) ([]string, error)
	Digest func(ctx context.Context, repo, tag, variant string) (string, error)
}

// resolved is Upgrade.Image's answer: the image by digest, or why not.
type resolved struct {
	ref string
	err error
}

// upgraded is one image lox run replaced.
type upgraded struct {
	// lock is the instance ("" for the hub).
	lock, repo, variant, from, to, oldRef, newRef string
}

// line is the summary line of the image before (old) or after.
func (g upgraded) line(old bool) string {
	ref := g.newRef
	if old {
		ref = g.oldRef
	}
	if g.lock == "" {
		return "hub image " + ref
	}
	return fmt.Sprintf("lock %s image %s", g.lock, ref)
}

// signedTag is the release tag cosign verify's output (stdout, a JSON
// array of the verified signatures) says repo's release workflow signed
// the image for: the certificate's subject,
// https://github.com/<Owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>.
// "" when no signature names one (a signature in the sigstore bundle
// format has an empty "optional": Upgrade.release finds its tag), or
// when they name different tags.
func signedTag(out []byte, repo string) string {
	var sigs []struct {
		Optional struct {
			Subject string `json:"Subject"`
		} `json:"optional"`
	}
	if json.Unmarshal(out, &sigs) != nil {
		return ""
	}
	prefix := "https://github.com/" + Owner + "/" + repo + "/.github/workflows/release.yml@refs/tags/"
	tag := ""
	for _, s := range sigs {
		t, ok := strings.CutPrefix(s.Optional.Subject, prefix)
		if !ok || !semverTag.MatchString(t) {
			continue
		}
		if tag != "" && tag != t {
			return ""
		}
		tag = t
	}
	return tag
}

// upgrade replaces, in raw, every pinned image older than u's pin with the
// pin's verified image. tags are the release tags the images were signed
// for (by ref, from their cosign verification); skipHub leaves the hub as
// it is (--pin). It returns the new raw file and what it replaced; every
// image it could not replace is left as it was, and a line says why.
func (u *Upgrade) upgrade(ctx context.Context, out io.Writer, raw []byte, c *Config, tags map[string]string, skipHub bool) ([]byte, []upgraded, error) {
	type want struct{ lock, repo, variant, ref string }
	var ws []want
	if !skipHub {
		ws = append(ws, want{"", "lockhub", "", c.Hub.Image})
	}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		v := ""
		if l.Vault {
			v = "vault"
		}
		ws = append(ws, want{n, l.Type, v, l.Image})
	}
	// One resolution per image: locks of the same type share it.
	type key struct{ repo, tag, variant string }
	cache := map[key]resolved{}
	// image is u.Image, once per release and variant.
	image := func(repo, tag, variant string) resolved {
		k := key{repo, tag, variant}
		r, ok := cache[k]
		if !ok {
			r.ref, r.err = u.Image(ctx, repo, tag, variant)
			if r.err == nil && digestRef.FindStringSubmatch(r.ref) == nil {
				r.err = fmt.Errorf("not an image by digest: %q", r.ref)
			}
			cache[k] = r
		}
		return r
	}
	repoTags := map[string][]string{}
	var done []upgraded
	for _, w := range ws {
		pin, ok := u.Pins[w.repo]
		if !ok {
			continue
		}
		what := "hub image"
		if w.lock != "" {
			what = "lock " + w.lock + ": image"
		}
		cur := tags[w.ref]
		if cur == "" && u.Tags != nil && u.Digest != nil {
			cur = u.release(ctx, w.repo, w.variant, w.ref, repoTags, image)
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
		}
		if cur != "" {
			// Kept for [lox] image_min.
			tags[w.ref] = cur
		}
		if cur == "" {
			fmt.Fprintf(out, "%s: not upgraded: its signature names no %s release, so it cannot be compared with %s\n", what, w.repo, pin)
			continue
		}
		if !semverLess(cur, pin) {
			continue
		}
		r := image(w.repo, pin, w.variant)
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if r.err != nil {
			fmt.Fprintf(out, "%s: not upgraded to %s %s, keeping %s: %v\n", what, w.repo, pin, cur, r.err)
			continue
		}
		var err error
		if w.lock == "" {
			raw, err = setHubImage(raw, r.ref)
		} else {
			raw, err = setLockImage(raw, w.lock, r.ref)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("upgrading the %s: %w", what, err)
		}
		tags[r.ref] = pin
		g := upgraded{lock: w.lock, repo: w.repo, variant: w.variant, from: cur, to: pin, oldRef: w.ref, newRef: r.ref}
		done = append(done, g)
	}
	for _, g := range done {
		what := "hub image"
		if g.lock != "" {
			what = "lock " + g.lock + ": image"
		}
		sig := "signature verified"
		if g.variant != "" {
			sig = g.variant + " image, " + sig
		}
		fmt.Fprintf(out, "%s upgraded: %s %s → %s (%s)\n", what, g.repo, g.from, g.to, sig)
	}
	return raw, done, nil
}

// release is the release tag of repo whose image (variant) is ref, for
// an image whose signature names none: the newest release the registry
// serves ref's digest for, once image (Upgrade.Image) verified ref's
// signature by that release's workflow run for that very tag. "" when no
// release has that digest, or it does not verify. tags caches the
// releases by repository.
func (u *Upgrade) release(ctx context.Context, repo, variant, ref string, tags map[string][]string, image func(repo, tag, variant string) resolved) string {
	ts, ok := tags[repo]
	if !ok {
		ts, _ = u.Tags(ctx, repo)
		tags[repo] = ts
	}
	for _, t := range ts {
		if min, ok := MinRelease[repo]; ok && semverLess(t, min) {
			continue
		}
		if ctx.Err() != nil {
			return ""
		}
		if d, err := u.Digest(ctx, repo, t, variant); err != nil || d != ref {
			continue
		}
		if r := image(repo, t, variant); r.err == nil && r.ref == ref {
			return t
		}
		return ""
	}
	return ""
}

// onlyUpgrades reports whether the change d (diff's lines) is the
// upgraded images and nothing else: what was reviewed is unchanged.
func onlyUpgrades(d []string, ups []upgraded) bool {
	if len(ups) == 0 {
		return false
	}
	var expect []string
	for _, g := range ups {
		expect = append(expect, "- "+g.line(true), "+ "+g.line(false))
	}
	for _, l := range d {
		if !slices.Contains(expect, l) {
			return false
		}
	}
	return true
}

// setLockImage is raw with locks.<name>.image set to ref (the rest of the
// file as it was, comments included).
func setLockImage(raw []byte, name, ref string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, scrubYAML(err, raw)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not a lockfamily.yaml mapping")
	}
	locks := lookup(doc.Content[0], "locks")
	lock := lookup(locks, name)
	if lock == nil {
		return nil, fmt.Errorf("no lock %s", name)
	}
	set := false
	for i := 0; i+1 < len(lock.Content); i += 2 {
		if v := lock.Content[i+1]; lock.Content[i].Value == "image" && v.Kind == yaml.ScalarNode {
			v.Value, v.Tag, v.Style = ref, "!!str", 0
			set = true
		}
	}
	if !set {
		return nil, fmt.Errorf("lock %s has no image", name)
	}
	out, _, err := encodeValid(&doc)
	return out, err
}

// releaseOf is the release of repo whose image (variant) is ref, for an
// image whose signature names none (release): "" when u cannot tell.
func (u *Upgrade) releaseOf(ctx context.Context, repo, variant, ref string) string {
	if u == nil || u.Image == nil || u.Tags == nil || u.Digest == nil {
		return ""
	}
	image := func(repo, tag, variant string) resolved {
		var r resolved
		r.ref, r.err = u.Image(ctx, repo, tag, variant)
		if r.err == nil && digestRef.FindStringSubmatch(r.ref) == nil {
			r.err = fmt.Errorf("not an image by digest: %q", r.ref)
		}
		return r
	}
	return u.release(ctx, repo, variant, ref, map[string][]string{}, image)
}
