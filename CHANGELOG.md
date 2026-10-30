# Changelog

lockhub has no stability promise before v1: pin an exact version (by image
digest).

## Unreleased

## v0.1.1 (2026-10-30)

Supported locks: images built on lockkit v0.3.1 (tested), such as the
first locksql, lockfile, lockmq and lockhttp releases with hub mode. Locks built
on lockkit v0.3.0 do not know `--hub-plain-http` and refuse the generated
command.

- The generated lock command passes `--hub-plain-http` (#20): lockkit
  refuses an http:// hub without it (DavidGodefroid/lockkit#72), and the
  hub is reached by its service name on the internal `lockhub` network.

- Builds on lockkit v0.3.1 (was a pre-release commit, 1d085bb) (#21).

## v0.1.0 (2026-10-30)

First release. Supported locks: images built on lockkit v0.3.0 (hub
mode). lockkit v0.3.1 and later refuse the generated `http://lockhub:8443`
hub URL without `--hub-plain-http`: use lockhub v0.1.1 with them.

- Telegram facade (#8): same rules as Slack, over long-polled
  `getUpdates` (outbound only). Answers count only from the (chat,
  sender) pairs of `hub.telegram.chats`; agent text is HTML-escaped and
  kept in `<code>`/`<pre>`, link previews off; decisions signed as
  `telegram:<chat>:<from>`. `lock add telegram --chat --from` asks for the
  bot token at the terminal. The hub itself now refuses a production
  ticket answered on any chat facade, and a chat facade that fails for
  good (a revoked token) stops alone instead of stopping the hub.
- Slack facade (#7): runs inside the hub when `hub.facades` lists
  `slack`, in Socket Mode only (an outbound websocket: the hub listens
  for nothing). Only the lock's masked screen is posted, every
  agent-provided string escaped and kept inside code spans; the requester
  is shown as unverified; never a reveal. Answers count only from the
  team, channel and member ids of `hub.slack` in lockfamily.yaml
  (reviewed by lock up, written to the hub's chat.json); production
  tickets and the risk classes kept off chat get no buttons. Decisions
  are signed by the hub as `slack:<team>:<user>`. The hub then joins its
  own `egress-hub` network; without a chat facade it has no route out.
  `lock add slack --team --channel --user` asks for the tokens at the
  terminal and stores them 0600 with the hub's data, never in the
  workspace; the hub reads them only when slack is enabled.
- `lock add`, `lock import`, `lock doctor` (#9). `add` declares a lock
  (image pinned by digest) in lockfamily.yaml, keeping its comments;
  `import` merges sub-projects' lockfamily.yaml, keeping each instance's
  first declaration and the strictest routing, and reports every
  difference; both validate before writing and leave the review to the
  next `lock up`. `doctor` checks the configuration, engine, images,
  state directories, keys, routing, facade socket, containers and the
  hub's internal network, and prints the commands that remove host
  accounts left by pre-hub consoles; it changes nothing.

- `lock up [--file] [--dry-run]` (#5), minimal: reads lockfamily.yaml
  (version 1: which locks run, images pinned by digest, facades and
  routing; a lock's target, production flag and credentials stay in its
  own profile),
  verifies every distinct image's cosign signature against its release workflow,
  gets the hub key (created once) and each lock instance's key
  (`<lock> hub-key`), shows the human the whole configuration on the first
  run and the change afterwards, and applies only on a typed yes: writes
  the hub's locks.json and routing.json (applied by the hub), then
  `docker compose up -d` with the compose file on stdin.
  Everything lock up writes or runs from (compose file, applied
  fingerprint, hub data) lives in `$XDG_STATE_HOME/lockfamily/<project>/`,
  outside the projects directory; lock up refuses a state or runtime
  directory that is a link, not its own, or open to others.
  Generated stack: an internal `lockhub` network for the hub and the
  locks only, one egress network per lock, read-only containers without
  capabilities, the hub's data and facade socket on host directories
  owned by the host user.

- `lock audit verify --data DIR --hub-key-file FILE` (#4): checks the
  hub's hash chain and that every record is signed by the pinned hub key,
  the signed decision matching its audit record, every decision's signature against the pinned hub
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
- Release archives of the `lock` CLI (lockfamily#4): static
  `lock_X.Y.Z_<os>_<arch>.tar.gz` for Linux and macOS (amd64, arm64) and
  `checksums.txt`, signed with cosign (keyless, bundle
  `checksums.txt.sigstore.json`) by the release workflow, attached to the
  GitHub release. The Lock Family `install.sh` verifies them.
