# Changelog

lockhub has no stability promise before v1: pin an exact version (by image
digest).

## Unreleased

- Skeleton (#1): `lockhub serve` with `GET /v1/hello`, `lock version`,
  read-only non-root image (uid 10040), CI, and a release workflow that
  publishes a cosign-signed multi-arch image by digest.
