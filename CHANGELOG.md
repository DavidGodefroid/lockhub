# Changelog

lockhub has no stability promise before v1: pin an exact version (by image
digest).

## Unreleased

- Skeleton (#1): `lockhub serve` with `GET /v1/hello`, `lock version`,
  read-only non-root image (uid 10040), CI, and a release workflow that
  publishes a cosign-signed multi-arch image by digest.
- Release archives of the `lock` CLI (lockfamily#4): static
  `lock_X.Y.Z_<os>_<arch>.tar.gz` for Linux and macOS (amd64, arm64) and
  `checksums.txt`, signed with cosign (keyless, bundle
  `checksums.txt.sigstore.json`) by the release workflow, attached to the
  GitHub release. The Lock Family `install.sh` verifies them.
