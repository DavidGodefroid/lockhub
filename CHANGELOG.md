# Changelog

lockhub has no stability promise before v1: pin an exact version (by image
digest).

## Unreleased

- Ticket store, state machine and signed decisions (#2): SQLite store
  (pure Go) keyed by (instance, ticket id); states pending, approved,
  denied, withdrawn, expired, consumed; one decision per ticket, signed
  with the hub key in lockkit's decision format; per-risk TTL (lockkit
  `ticket.ClampTTL`), swept every 30 s; per-instance pending cap;
  hash-chained audit log `tickets.jsonl` that the hub refuses to start on
  when broken; production tickets need their name retyped.
- Lock API v1 on the hub network: `POST /v1/tickets`,
  `POST /v1/tickets/{id}/withdraw`, `POST /v1/tickets/{id}/consumed`,
  `GET /v1/decisions?since=&wait=` (long poll). Every request is signed
  with the lock instance's key (lockkit `ticket.RequestMessage`, context
  `lockkit/request/v1`), single-use nonce, ±60 s clock window; an
  instance only sees its own tickets and decisions.
- Routing rules (#6): terminal, deck and mobile answer every risk class;
  Slack and Telegram answer read, read-pii and write only, with no opt-in;
  a workspace can only narrow the table.
- `lockhub keygen`; `lockhub serve --data DIR` reads `hub.key` (0600) and
  `locks.json`.

- Skeleton (#1): `lockhub serve` with `GET /v1/hello`, `lock version`,
  read-only non-root image (uid 10040), CI, and a release workflow that
  publishes a cosign-signed multi-arch image by digest.
- Release archives of the `lock` CLI (lockfamily#4): static
  `lock_X.Y.Z_<os>_<arch>.tar.gz` for Linux and macOS (amd64, arm64) and
  `checksums.txt`, signed with cosign (keyless, bundle
  `checksums.txt.sigstore.json`) by the release workflow, attached to the
  GitHub release. The Lock Family `install.sh` verifies them.
