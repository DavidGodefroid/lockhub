package family

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// cosignIssuer is the OIDC issuer of the release workflows' signatures.
const cosignIssuer = "https://token.actions.githubusercontent.com"

// CosignMin is the oldest cosign lox verifies images with: v2.5.0, the
// first whose verify reads the sigstore bundle format (--new-bundle-format),
// in which lockfile's releases (cosign v3) sign their images.
const CosignMin = "v2.5.0"

// CosignUpgradeHint is how to get a cosign lox verifies with.
const CosignUpgradeHint = "brew upgrade cosign, or https://docs.sigstore.dev/cosign/system_config/installation/"

// CosignVersion is the version of the cosign r runs ("v2.6.1", from
// cosign version --json), "" when cosign does not tell it.
func CosignVersion(ctx context.Context, r Runner) (string, error) {
	out, err := r.Run(ctx, nil, "cosign", "version", "--json")
	if err != nil {
		return "", err
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if json.Unmarshal(out, &v) != nil {
		return "", nil
	}
	return v.GitVersion, nil
}

// cosignVer is a cosign version's major, minor and patch; ok is false
// for a version that is not vX.Y.Z[-…].
func cosignVer(v string) (n [3]int, ok bool) {
	s, found := strings.CutPrefix(v, "v")
	if !found {
		return n, false
	}
	s, _, _ = strings.Cut(s, "-")
	s, _, _ = strings.Cut(s, "+")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return n, false
	}
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return n, false
		}
		n[i] = x
	}
	return n, true
}

// CosignSupported reports whether lox verifies with cosign version v:
// CosignMin or later. A version cosign did not tell ("") is tried.
func CosignSupported(v string) bool {
	if v == "" {
		return true
	}
	n, ok := cosignVer(v)
	if !ok {
		return true
	}
	min, _ := cosignVer(CosignMin)
	for i := range n {
		if n[i] != min[i] {
			return n[i] > min[i]
		}
	}
	return true
}

// noSignatures reports whether cosign's verify failed for finding no
// signature at all in the format it looked for ("no signatures found"),
// not for a signature it refused (identity, issuer, transparency log).
func noSignatures(err error) bool {
	var re *RunError
	if errors.As(err, &re) && strings.Contains(string(re.Stderr), "no signatures found") {
		return true
	}
	return strings.Contains(err.Error(), "no signatures found")
}

// verifyImage verifies ref's signature with cosign: by the release
// workflows' OIDC issuer, for a certificate identity matching identity.
// It returns cosign's stdout (the verified signatures).
//
// Both signature formats are checked: the legacy one (an image's .sig
// tag) and the sigstore bundle format (an OCI referrer), which cosign v3
// signs in and cosign v3 reads by default. cosign v2 reads it only with
// --new-bundle-format, and then only it: a plain verify that finds no
// signature is tried once more with that flag, with the same issuer and
// identity, so a signature refused is never retried. A cosign older than
// CosignMin is refused up front.
func verifyImage(ctx context.Context, r Runner, ref, identity string) ([]byte, error) {
	v, err := CosignVersion(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("cosign version: %w", err)
	}
	if !CosignSupported(v) {
		return nil, fmt.Errorf("cosign %s found, lox needs cosign %s or later: %s", v, CosignMin, CosignUpgradeHint)
	}
	args := []string{"verify", "--certificate-oidc-issuer", cosignIssuer, "--certificate-identity-regexp", identity, ref}
	out, err := r.Run(ctx, nil, "cosign", args...)
	if err == nil {
		return out, nil
	}
	n, ok := cosignVer(v)
	if !noSignatures(err) || (ok && n[0] >= 3) {
		return nil, fmt.Errorf("%w (checked with cosign %s)", err, cosignName(v))
	}
	out, err2 := r.Run(ctx, nil, "cosign", append([]string{"verify", "--new-bundle-format"}, args[1:]...)...)
	if err2 != nil {
		return nil, fmt.Errorf("%w (legacy and bundle formats checked with cosign %s)", err2, cosignName(v))
	}
	return out, nil
}

// cosignName is v, or "(version unknown)".
func cosignName(v string) string {
	if v == "" {
		return "(version unknown)"
	}
	return v
}
