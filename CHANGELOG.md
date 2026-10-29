# Changelog

lockhub has no stability promise before v1: pin an exact version (by image
digest).

## Unreleased

- `lock audit verify --data DIR --hub-key-file FILE` (#4): checks the
  hub's hash chain, every decision's signature against the pinned hub
  key, and that the database and the log agree (a cut log tail shows as
  a decision missing from the log). Lock audit chains follow with
  lockkit's audit chain (DavidGodefroid/lockkit#30).

- `lock approve` (#3): the terminal facade. It follows the hub's queue on
  the host facade socket (`lockhub serve --facade-socket`, default
  `$XDG_RUNTIME_DIR/lockhub/facade.sock`, mode 0600), shows each masked
  screen through lockkit's terminal sanitizer, and sends y / n <reason> /
  skip; production tickets need their name typed. The approver is
  recorded from the socket peer's uid. Refuses a non-terminal stdin.
- Facade API (host socket only): `GET /v1/queue?wait=`,
  `POST /v1/tickets/{instance}/{id}/decide` (tty or deck),
  `GET /v1/decided?since=` and `GET /v1/tickets/{instance}/{id}` (read-only,
  for lea).

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
