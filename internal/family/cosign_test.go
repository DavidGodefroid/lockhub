package family

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cosignScript is a cosign of version ver whose plain verify answers
// plain and whose --new-bundle-format verify answers bundle; calls are
// its verifications.
type cosignScript struct {
	ver           string
	plain, bundle error
	calls         [][]string
}

func (c *cosignScript) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	if name != "cosign" {
		return nil, errors.New("not cosign")
	}
	if args[0] == "version" {
		return []byte(`{"gitVersion":"` + c.ver + `","platform":"linux/amd64"}`), nil
	}
	c.calls = append(c.calls, args)
	if args[1] == "--new-bundle-format" {
		return []byte("[]"), c.bundle
	}
	return []byte("[]"), c.plain
}

// The errors as cosign v2.6.1 prints them (lockhub#197).
var (
	errNoSigs   = &RunError{Cmd: "cosign verify", Err: errors.New("exit status 10"), Stderr: []byte("Error: no signatures found\nerror during command execution: no signatures found\n")}
	errMismatch = &RunError{Cmd: "cosign verify", Err: errors.New("exit status 1"), Stderr: []byte(`Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value to match regex "^x", got "y"` + "\n")}
	errLegacyID = &RunError{Cmd: "cosign verify", Err: errors.New("exit status 1"), Stderr: []byte("Error: no matching signatures: none of the expected identities matched what was in the certificate\n")}
)

func TestVerifyImage(t *testing.T) {
	const ref, id = "ghcr.io/davidgodefroid/lockfile@sha256:75f3", "^https://github\\.com/DavidGodefroid/lockfile/"
	plain := []string{"verify", "--certificate-oidc-issuer", cosignIssuer, "--certificate-identity-regexp", id, ref}
	bundle := []string{"verify", "--new-bundle-format", "--certificate-oidc-issuer", cosignIssuer, "--certificate-identity-regexp", id, ref}
	for _, tc := range []struct {
		name          string
		ver           string
		plain, bundle error
		calls         [][]string
		err           string // "": verified
	}{
		{name: "v3", ver: "v3.1.3", calls: [][]string{plain}},
		{name: "v3 no signature: no retry", ver: "v3.1.3", plain: errNoSigs, calls: [][]string{plain}, err: "checked with cosign v3.1.3"},
		{name: "v2 legacy", ver: "v2.6.1", calls: [][]string{plain}},
		{name: "v2 bundle only", ver: "v2.6.1", plain: errNoSigs, calls: [][]string{plain, bundle}},
		{name: "v2 bundle identity mismatch", ver: "v2.6.1", plain: errNoSigs, bundle: errMismatch, calls: [][]string{plain, bundle}, err: "legacy and bundle formats checked with cosign v2.6.1"},
		{name: "v2 legacy identity mismatch: no retry", ver: "v2.6.1", plain: errLegacyID, calls: [][]string{plain}, err: "checked with cosign v2.6.1"},
		{name: "v2.5.0", ver: "v2.5.0", plain: errNoSigs, calls: [][]string{plain, bundle}},
		{name: "too old", ver: "v2.4.3", err: "cosign v2.4.3 found, lox needs cosign v2.5.0 or later: brew upgrade cosign"},
		{name: "v1", ver: "v1.13.1", err: "lox needs cosign v2.5.0 or later"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &cosignScript{ver: tc.ver, plain: tc.plain, bundle: tc.bundle}
			_, err := verifyImage(context.Background(), c, ref, id)
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Errorf("error %v, want %q", err, tc.err)
			}
			if len(c.calls) != len(tc.calls) {
				t.Fatalf("calls %q, want %q", c.calls, tc.calls)
			}
			for i := range c.calls {
				if strings.Join(c.calls[i], " ") != strings.Join(tc.calls[i], " ") {
					t.Errorf("call %d: %q, want %q", i, c.calls[i], tc.calls[i])
				}
			}
		})
	}
}

// Every image verification goes through verifyImage: no other cosign
// verify in lox's code.
func TestOneCosignVerify(t *testing.T) {
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), `"cosign", "verify"`) {
			t.Errorf("%s runs cosign verify itself: use verifyImage", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCosignSupported(t *testing.T) {
	for v, want := range map[string]bool{"v2.5.0": true, "v2.6.1": true, "v3.0.0": true, "v2.10.0": true, "v2.5.0-rc.1": true,
		"v2.4.3": false, "v1.13.1": false, "v0.9.0": false, "": true, "devel": true} {
		if got := CosignSupported(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
