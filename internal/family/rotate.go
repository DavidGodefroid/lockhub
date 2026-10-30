package family

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/lockhub/internal/keys"
)

// lock up --pin and --rotate (plan D.5): a previous hub image restored by
// digest, and new hub or lock keys, both through the review.

// HubKeysFile is every hub public key the workspace's hub was signed
// with, oldest first, the current one last (state directory): what lock
// audit verify --hub-key-file takes once the hub key was rotated.
const HubKeysFile = "hub-keys.pub"

// HubImagesFile lists the hub images lock up applied (state directory),
// one "<RFC 3339 time> <image>" line each, oldest first: the digests
// --pin can go back to.
const HubImagesFile = "hub-images.log"

// rotateDir is where a rotated lock's new key is made, in the lock's
// own home (or the gate's), before the human's yes.
const rotateDir = ".lockfamily-rotate"

var pinDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PinRef is the hub image --pin names: a digest (sha256:…), or the whole
// ghcr.io/davidgodefroid/lockhub@sha256:… reference.
func PinRef(pin string) (string, error) {
	if pinDigest.MatchString(pin) {
		return "ghcr.io/davidgodefroid/lockhub@" + pin, nil
	}
	if m := digestRef.FindStringSubmatch(pin); m != nil && m[1] == "lockhub" {
		return pin, nil
	}
	return "", fmt.Errorf("--pin: want sha256:<64 hex> or ghcr.io/davidgodefroid/lockhub@sha256:<64 hex>, got %q", pin)
}

// setHubImage is raw with hub.image set to ref (the rest of the file as
// it was, comments included).
func setHubImage(raw []byte, ref string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not a lockfamily.yaml mapping")
	}
	hub := child(doc.Content[0], "hub")
	set := false
	for i := 0; i+1 < len(hub.Content); i += 2 {
		if hub.Content[i].Value == "image" {
			hub.Content[i+1].Kind, hub.Content[i+1].Value, hub.Content[i+1].Tag, hub.Content[i+1].Style = yaml.ScalarNode, ref, "!!str", 0
			set = true
		}
	}
	if !set {
		hub.Content = append(hub.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "image"}, &yaml.Node{Kind: yaml.ScalarNode, Value: ref, Tag: "!!str"})
	}
	out, _, err := encodeValid(&doc)
	return out, err
}

// rotation is what --rotate names.
type rotation struct {
	hub   bool
	locks []string // sorted
}

func (r rotation) any() bool { return r.hub || len(r.locks) > 0 }

// parseRotate reads --rotate's values: "hub", a lock instance of c, or
// "all" (the hub and every lock), each repeatable or comma-separated.
func parseRotate(c *Config, vals []string) (rotation, error) {
	var r rotation
	insts := c.Instances()
	if slices.Contains(insts, "hub") {
		for _, v := range vals {
			for _, n := range strings.Split(v, ",") {
				if strings.TrimSpace(n) == "hub" {
					return r, errors.New(`--rotate hub: a lock instance is named "hub" too: rotate with --rotate all`)
				}
			}
		}
	}
	for _, v := range vals {
		for _, n := range strings.Split(v, ",") {
			switch n = strings.TrimSpace(n); {
			case n == "all":
				r.hub = true
				r.locks = append(r.locks, insts...)
			case n == "hub":
				r.hub = true
			case slices.Contains(insts, n):
				r.locks = append(r.locks, n)
			default:
				return r, fmt.Errorf("--rotate %q: not hub, all, or a lock of this workspace (%s)", n, strings.Join(insts, ", "))
			}
		}
	}
	slices.Sort(r.locks)
	r.locks = slices.Compact(r.locks)
	return r, nil
}

// rotkeyScript is the setup service rotkey-<instance>: clear drops a new
// key made earlier and not applied; swap moves the new key over the
// lock's (the old private key is gone).
func rotkeyScript(home, inst string) string {
	s, h := home+"/"+rotateDir, home+"/hub"
	return fmt.Sprintf(`case "$1" in clear) rm -rf %[1]s ;; swap) test -f %[1]s/hub/%[3]s.key && mkdir -p %[2]s && chmod 0700 %[2]s && mv -f %[1]s/hub/%[3]s.key %[2]s/%[3]s.key && rm -rf %[1]s ;; *) exit 2 ;; esac`, s, h, inst)
}

// readHubKeys reads the state directory's hub key history (nil when
// absent).
func readHubKeys(state string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(state, HubKeysFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	ks, err := keys.ParsePublics(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(state, HubKeysFile), err)
	}
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = keys.Public(k)
	}
	return out, nil
}

// writeHubKeys records hp as the current hub key: appended after a
// rotation, the whole history otherwise kept.
func writeHubKeys(state, hp string) error {
	ks, err := readHubKeys(state)
	if err != nil {
		return err
	}
	if len(ks) > 0 && ks[len(ks)-1] == hp {
		return nil
	}
	if slices.Contains(ks, hp) {
		return fmt.Errorf("%s: the hub key %s is listed already, not last", HubKeysFile, hp)
	}
	return writeFileMode(filepath.Join(state, HubKeysFile), []byte(strings.Join(append(ks, hp), "\n")+"\n"), 0o644)
}

// hubImages reads the hub images applied in this workspace, oldest
// first.
func hubImages(state string) []string {
	f, err := os.Open(filepath.Join(state, HubImagesFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if _, img, ok := strings.Cut(sc.Text(), " "); ok {
			out = append(out, img)
		}
	}
	return out
}

// recordHubImage appends img to the history unless it is the last one.
func recordHubImage(state, img string, now time.Time) error {
	h := hubImages(state)
	if len(h) > 0 && h[len(h)-1] == img {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(state, HubImagesFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s %s\n", now.UTC().Format(time.RFC3339), img)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// stageHubKey makes the new hub key in the hub's data directory (stage,
// /var/lib/lockhub/rotate in the hub) and returns its public half. A key
// staged by an earlier lock up --rotate hub is reused; done reports one
// the hub took already (that lock up stopped after it), whose rotation
// only needs finishing.
func (u *Up) stageHubKey(ctx context.Context, composeYAML []byte, compose func(...string) []string, stage string) (string, bool, error) {
	if b, err := os.ReadFile(filepath.Join(stage, "hub.pub")); err == nil {
		k := strings.TrimSpace(string(b))
		_, kerr := os.Stat(filepath.Join(stage, "hub.key"))
		_, aerr := os.Stat(filepath.Join(stage, "attempted"))
		switch {
		case !validPub(k):
		case kerr == nil:
			return k, false, nil
		case aerr == nil:
			return k, true, nil
		}
	}
	if err := os.RemoveAll(stage); err != nil {
		return "", false, err
	}
	if err := privateDir(stage); err != nil {
		return "", false, err
	}
	out, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lockhub", "keygen", "--data", "/var/lib/lockhub/rotate")...)
	if err != nil {
		return "", false, err
	}
	k := strings.TrimSpace(string(out))
	if !validPub(k) {
		return "", false, errors.New("lockhub keygen: not a base64 Ed25519 public key")
	}
	return k, false, os.WriteFile(filepath.Join(stage, "hub.pub"), []byte(k+"\n"), 0o600)
}

// stageLockKey makes lock n's new key in its own volume, under
// rotateDir (the lock's hub-key with that home), and returns its public
// half. A key left there by an earlier lock up is dropped first.
func (u *Up) stageLockKey(ctx context.Context, c *Config, n string, composeYAML []byte, compose func(...string) []string) (string, error) {
	if _, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "rotkey-"+n, "clear")...); err != nil {
		return "", err
	}
	l := c.Locks[n]
	var args []string
	if Kinds[l.Type].Gate {
		args = compose("run", "--rm", "-T", "--no-deps", "gatekey-"+n, "hub-key", "--instance", n, "--home", "/g/"+rotateDir)
	} else {
		args = compose("run", "--rm", "-T", "--no-deps", "-e", "HOME=/home/"+l.Type+"/"+rotateDir, "lock-"+n, "hub-key", "--instance", n)
	}
	out, err := u.Run.Run(ctx, composeYAML, "docker", args...)
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(out))
	if !validPub(k) {
		return "", errors.New("not a base64 Ed25519 public key")
	}
	return k, nil
}

// applyRotation applies --rotate once the human said yes, before the hub
// and the locks are given their new lists: the hub (stopped meanwhile)
// takes its new key with lockhub rotate-key, then each rotated lock's
// new key replaces its old one.
func (u *Up) applyRotation(ctx context.Context, c *Config, rot rotation, composeYAML []byte, compose func(...string) []string, stage, attempted, oldHP, hp string, hubRotated bool) error {
	if rot.hub {
		// The history starts with the key the log was signed with first.
		if err := writeHubKeys(u.State, oldHP); err != nil && !hubRotated {
			return err
		}
		if !hubRotated {
			if _, err := u.Run.Run(ctx, composeYAML, "docker", compose("stop", "lockhub")...); err != nil {
				return fmt.Errorf("hub key rotation: stopping the hub: %w", err)
			}
			if err := os.WriteFile(attempted, nil, 0o600); err != nil {
				return err
			}
			out, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lockhub", "rotate-key", "--data", "/var/lib/lockhub", "--new", "/var/lib/lockhub/rotate/hub.key")...)
			if err != nil {
				return fmt.Errorf("hub key rotation: %w (the hub stays stopped: run lock up --rotate hub again to finish it)", err)
			}
			if strings.TrimSpace(string(out)) != hp {
				return fmt.Errorf("hub key rotation: the hub took %q, not the reviewed key (the hub stays stopped)", strings.TrimSpace(string(out)))
			}
		}
		if err := os.WriteFile(filepath.Join(u.State, "hub.pub"), []byte(hp+"\n"), 0o644); err != nil {
			return err
		}
		if err := writeHubKeys(u.State, hp); err != nil {
			return err
		}
		if err := os.RemoveAll(stage); err != nil {
			return err
		}
	}
	for _, n := range rot.locks {
		if _, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "rotkey-"+n, "swap")...); err != nil {
			return fmt.Errorf("key of %s: %w (its old key stays: run lock up --rotate %s again)", n, err, n)
		}
	}
	return nil
}
