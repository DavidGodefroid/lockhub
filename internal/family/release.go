package family

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Owner is the GitHub owner of the Lock Family's repositories; images
// are ghcr.io/davidgodefroid/<repo>.
const Owner = "DavidGodefroid"

// Releases finds the image of a lock's (or the hub's) signed release, by
// digest, for lock add: the newest release of its repository, its image
// in ghcr.io, and the image's cosign signature by that release's own
// workflow run for that very tag.
type Releases struct {
	// API is GitHub's REST API (https://api.github.com), Registry the
	// image registry (https://ghcr.io); tests point them elsewhere.
	API, Registry string
	HTTP          *http.Client
	// Token, when set, authenticates the calls to API (GitHub's rate
	// limit for anonymous calls is low); never sent to Registry.
	Token string
	// Run runs cosign.
	Run Runner
}

// DefaultReleases are GitHub's and ghcr.io's.
func DefaultReleases(r Runner) *Releases {
	return &Releases{API: "https://api.github.com", Registry: "https://ghcr.io", HTTP: &http.Client{Timeout: 30 * time.Second}, Run: r}
}

var semverTag = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.]+)?$`)

type release struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// semverLess orders release tags (pre-releases before their release).
func semverLess(a, b string) bool {
	ma, mb := semverTag.FindStringSubmatch(a), semverTag.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x < y
		}
	}
	switch {
	case ma[4] == mb[4]:
		return false
	case ma[4] == "":
		return false
	case mb[4] == "":
		return true
	}
	return ma[4] < mb[4]
}

// Latest is the tag of repo's newest release: the newest that is not a
// pre-release, else (a repository that only has pre-releases yet) the
// newest pre-release, and whether it is one.
func (r *Releases) Latest(ctx context.Context, repo string) (string, bool, error) {
	var rs []release
	auth := ""
	if r.Token != "" {
		auth = "Bearer " + r.Token
	}
	if err := r.getJSON(ctx, r.API+"/repos/"+Owner+"/"+url.PathEscape(repo)+"/releases?per_page=100", auth, &rs); err != nil {
		return "", false, fmt.Errorf("releases of %s: %w", repo, err)
	}
	best, pre := "", ""
	for _, x := range rs {
		if x.Draft || !semverTag.MatchString(x.Tag) {
			continue
		}
		if x.Prerelease {
			if pre == "" || semverLess(pre, x.Tag) {
				pre = x.Tag
			}
		} else if best == "" || semverLess(best, x.Tag) {
			best = x.Tag
		}
	}
	switch {
	case best != "":
		return best, false, nil
	case pre != "":
		return pre, true, nil
	}
	return "", false, fmt.Errorf("%s has no published release", repo)
}

// MinRelease is each repository's first release that runs under lock up
// (hub mode, lockkit v0.3.1: --hub-plain-http, hub-key).
var MinRelease = map[string]string{"lockhub": "v0.1.1", "locksql": "v0.11.0", "lockmq": "v0.3.0", "lockfile": "v0.4.0", "lockhttp": "v0.3.0"}

// Image is the image of repo's release tag, pinned by the digest the
// registry serves for it, once cosign verified that digest's signature
// by repo's release workflow run for tag.
func (r *Releases) Image(ctx context.Context, repo, tag string) (string, error) {
	if !semverTag.MatchString(tag) {
		return "", errors.New("not a release tag (vX.Y.Z)")
	}
	if min, ok := MinRelease[repo]; ok && semverLess(tag, min) {
		return "", fmt.Errorf("%s %s cannot run under lock up (no hub mode): %s or later is needed", repo, tag, min)
	}
	name := "davidgodefroid/" + repo
	// The release workflows tag the image with the version without the v.
	ver := strings.TrimPrefix(tag, "v")
	var tok struct {
		Token string `json:"token"`
	}
	if err := r.getJSON(ctx, r.Registry+"/token?scope="+url.QueryEscape("repository:"+name+":pull"), "", &tok); err != nil {
		return "", fmt.Errorf("registry token for %s: %w", name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.Registry+"/v2/"+name+"/manifests/"+ver, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", strings.Join([]string{"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json"}, ", "))
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("image %s:%s: registry answered %s", name, ver, resp.Status)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(d) {
		return "", fmt.Errorf("image %s:%s: no sha256 digest from the registry", name, ver)
	}
	ref := "ghcr.io/" + name + "@" + d
	// The digest is only trusted once its signature is: by this
	// repository's release workflow, run for this very tag.
	id := "^" + regexp.QuoteMeta("https://github.com/"+Owner+"/"+repo+"/.github/workflows/release.yml@refs/tags/"+tag) + "$"
	if _, err := r.Run.Run(ctx, nil, "cosign", "verify", "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		"--certificate-identity-regexp", id, ref); err != nil {
		return "", fmt.Errorf("image %s (%s %s) is not signed by its release: %w", ref, repo, tag, err)
	}
	return ref, nil
}

func (r *Releases) getJSON(ctx context.Context, u, auth string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}
