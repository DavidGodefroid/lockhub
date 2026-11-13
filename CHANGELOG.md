# Changelog

lockhub has no stability promise before v1: pin an exact version (by image
digest).

## Unreleased

- `lox run`'s `w` overlay no longer shows again, for a moment, the
  tickets just withdrawn (#171): the hub's list read after the
  withdrawals could be one it made before them, and `x` then picked a
  ticket already withdrawn instead of the selected one.

- `lox add` (every type, both forms) and `lox run` (`--no-start` too)
  refuse a workspace that is not the user's or that group or others can
  write: the workspace directory, `.lockfamily/` and each lock's
  `.<type>/`, with one message for every type and its fix, `chmod go-w
  <directory>` (#178). Only locklog refused it before; a workspace made
  under umask 002 (0775) let a member of the group replace a lock's
  reviewed configuration between two `lox run`s.

- A bad locklog lock no longer stops `lox run` (#177). A lock whose mount
  plan lox run refuses is not started, with its reason (`lock <name>: not
  started: <reason>`, in lox run's header and as a `lox doctor` failure,
  kept in the state's `not-started.json`); the other locks start and are
  served. A locklog lock's `log_roots` (reviewed, passed to its console as
  `LOCKLOG_EXTRA_ROOTS`) allows log directories outside `/var/log` and
  `/run/log/journal`: `lox add locklog --only` writes it for a directory
  `LOCKLOG_EXTRA_ROOTS` lets in, and refuses any other with lox run's
  message, so it never declares a lock lox run refuses.

- `lox run`'s short review lists a changed profile line's new value (#173):
  under `Other changes since the last lox run:` it showed only the old (`-`)
  lines of a profile, never the new (`+`) ones, so a loosening
  (`tier = "write"`, a new host) was approved unseen. A changed line now
  shows `-` and `+`, an added one `+`, a removed one `-`.
- `lox add lockfile --source sftp --known-hosts FILE` no longer writes a host
  path the console cannot open (#174): it copies FILE to
  `.lockfile/known_hosts` and the profile names
  `~/.config/lockfile/known_hosts`, where the console sees its profile's
  reviewed copy. `lox run` checks a lockfile sftp profile's `known_hosts` and
  `key` before the start: in the reviewed copy, or in the console's
  container; a path into the workspace's `.lockfile` is said with the path to
  write instead. e2e: `ci/e2e/lockfile-sftp.sh`.

- `lox run` upgrades an image signed in the sigstore bundle format (#176):
  cosign's output names no release for it (no certificate subject), so a
  lockfile v0.8.x lock stayed on its first pin (`its signature names no
  lockfile release`). Its release is now the newest whose image in ghcr.io
  has the pinned digest (GitHub's release list, then one registry lookup per
  release), once cosign verified the pinned image for that very tag.

- Two workspaces on one host (#172): their hubs share the facade socket,
  and a second workspace's `lox run` used to serve the first one's hub,
  listing its tickets. The hub now answers `GET /v1/hub` (its key) on the
  facade socket; `lox run` and `lox up` compare it with their workspace's
  hub key before starting anything, `lox run` again whenever the hub comes
  back, and refuse another workspace's hub, naming its workspace and
  project (`stop it, or run this workspace with its own XDG_RUNTIME_DIR`),
  so the second hub is never started to fail on the socket. `lox doctor`
  reports it, and the hub's own `another hub is serving it` error points at
  the shared runtime directory. e2e: `ci/e2e/two-workspaces.sh`.

- lockssh is a lock type (#133): `lox add lockssh` (host, port, login, key
  or password, the key and known_hosts files in the lock's home, the allow
  rules, `--exec`), `lox add lockssh NAME`, and `lox run`, digest-pinned to
  `ghcr.io/davidgodefroid/lockssh` (v0.1.0 or later; shipped: v0.1.0). The
  console runs as `10041`, its clients group `10040`, with its launcher's
  limits; its egress reaches the profile's `host`:`port` only (an IP address
  refused); the review shows `ssh user@host:port`, the login and the trusted
  host keys, and checks the key and known_hosts in the lock's home (with the
  command that copies them there). lox run reads its auto rules (`lockssh
  profile rules --json`: connect, run, exec, unmask), keeps them in
  `lockssh/<instance>/rules.json` and applies them by verb; `unmask` and a
  production `exec` are never auto, and unknown rules ask everything. A
  lockssh lock's `read-pii` is never answered in a chat: `routing.json`'s new
  `local_risks`, which the hub applies and `lox doctor` checks. `lox init`
  lists the lockssh launcher and proposes the plain hosts of
  `~/.ssh/config`. e2e: `ci/e2e/lockssh-agent.sh`, a host agent's `lockssh
  mcp` against an SSH server in a container. Supported locks: lockssh joins
  `lox run` (lockssh v0.1.0 or later; `lox run` upgrades an older image to
  v0.1.0).

- `lox run` keeps a session password per profile and endpoint (#165): a
  profile with two `credentials = "ask"` legs (an SSH bastion, then its
  database) asks each leg its own password once, the prompt names the
  endpoint, the database leg right after the bastion's is no longer
  taken for a failed reconnect, and an idle reconnect reuses each leg's
  own password without asking.

- `lox add` / `lox run` home-file checks (#167): a path into the
  profile's directory (such as `tls_ca = ".locksql/ca.pem"`) is checked
  in the copy the review applies, so a first run or a profile change no
  longer reports it "not found"; a key in an inline table
  (`ssh = { auth = "key", key = "…" }`) is checked, and an `ssh` value
  the review cannot read is listed as not checked instead of skipped.

- `lox run` has a tab per lock (`1`…`9`, `Tab`; `0` the global feed, the
  default) with what the lock decides on its own side, read at its
  console's terminal (the docker attach `lox run` holds, which no agent
  reaches; nothing goes to the hub): its plans (class, EXPLAIN summary,
  verdict, row bound, PII masking, the decision and `done: N rows in T
  ms`), each statement masked from its first quote, comment or non-ASCII
  byte on, whatever the dialect, and every number before it (`o` shows
  it in clear, on screen only); its lock-side refusals with code and
  reason, identical ones folded with a counter, a loop of three raising an alert in the global feed;
  tickets not submitted under the lock's rate limits (`THROTTLED`,
  DavidGodefroid/lockkit#150); its policy state (approved, pending,
  refused: the last approved policy applies) with the change, reviewed
  from the tab (`r` types `:review`, the question is a card); its session
  (idle time, time left before `idle_timeout` and `max_session`, the limits
  in force from the console's `:status`, typed once per attach and on `i`).
  A badge marks a tab that wants you (#146).
- Withdraw pending or stuck tickets (#148). In `lox run`, `w` lists every
  ticket pending at the hub, oldest first, with its age, per lock with
  how many lox run cannot verify; `x` withdraws the selected one, `X` all
  of its lock, `U` all of its lock that lox run cannot verify, each after
  a `y/N`. Without the TUI: `lox tickets [--lock NAME] [--error] [--json]`
  and `lox withdraw INSTANCE/ID… | --lock NAME --all-pending|--error`.
  The hub ends the ticket `withdrawn` (it frees the lock's slot at the
  hub), audits it with the human, the facade and the reason (`withdrawn
  by USER in lox run`), and sends the lock a denial it signs with that
  reason: the lock ends the plan, frees its own queue and its agent
  hears that the human withdrew it, instead of a request that hangs. A
  ticket the hub itself can no longer verify is withdrawn without a
  decision (audited as such). New facade route `POST
  /v1/tickets/{instance}/{id}/withdraw`; `lox audit show` prints a
  decision's reason. Locks on a lockkit with DavidGodefroid/lockkit's
  #148 part end the plan as soon as the denial arrives and give reads a
  1 h TTL; older ones end it on the agent's next run of the ticket.

- The `lox add` and `lox run` review checks the files a locksql profile
  names (`tls_ca`, `tls_cert`, `tls_key`, `ssh.key`) in the lock's home
  volume, as the console account, with locksql's `~/` rule (one rule,
  documented in docs/lox-add.md): a missing file gets a `file` row with
  the command that copies it there, a private key readable by others the
  command that runs `chmod 600` on it; a present file says nothing. `lox
  add` offers to copy a missing file from a host path, once you answer
  `y` (#158, follow-up of DavidGodefroid/locksql#194).

- `lox attach NAME` shows the question the console actually waits for,
  read in the lock's container from the question file its console keeps
  next to its socket (DavidGodefroid/lockkit#127,
  DavidGodefroid/locksql#182): only when the console does not listen on
  its socket, only that console's own file (its name, owner and mode
  0600), at most 200 characters, escaped for the terminal (#119): `lock
  NAME waits for: Passphrase for ...: (typed, not shown)`. A console that
  listens says `lock NAME is serving: nothing to answer`; neither gives
  the container's state (starting, or stopped with its exit status). The
  list of what a console may ask is gone: it was taken for the question,
  and a policy answer was typed as an SSH passphrase. A console that ends
  under the attach makes lox attach print its next question once it
  restarted (#143).

## v0.10.1 (2026-11-07)

Supported locks: as v0.10.0. `lox run` upgrades older images to locksql
v0.17.1, lockmq v0.8.1, lockfile v0.8.1, lockhttp v0.8.1 and locklog
v0.2.1 (`family.ShippedLocks`; the lock patches only change their texts
to name `lox run`). Upgrade lox, then start `lox run`: it upgrades the hub
image to v0.10.1.

New: `lox run` answers the consoles' start and reconnect questions in
question cards (lockhub#142): y/n for `[y/N]` and `[yes/N]`, a typed line
otherwise (secrets as dots). The answer is typed at the console's terminal
only, never through the hub nor logged. Values typed this session are
offered again after a console's idle restart; a policy review is never
answered for the human. The header's locks line shows each console:
waiting for you, serving, stopped or not reached. `lox attach` stays as a
debugging fallback.

Fixes:

- A ticket holding `<`, `>` or `&` (a SQL `<`, `>=`, `<>`, `&`) could
  never be decided in `lox run`: the hub's facade sent it HTML-escaped,
  out of its canonical form, so it showed as `unreadable ticket does not
  verify under the pinned lock key: ticket: invalid: not in canonical
  form` and stayed pending (lockhub#147). The facade API, the lock API and
  the mobile facade no longer HTML-escape, nor do `lox run`'s and the
  phone CLI's requests; a decision whose reason holds these characters now
  verifies at the lock too. Tickets already stuck this way are stored
  intact: the upgraded `lox run` reads and decides them.
- `lox run` answers a ticket routed to it that fails verification:
  refused with the reason (`ticket rejected by lox run: …`), so its lock
  ends the plan and frees the slot instead of waiting. Equal failures show
  as one feed line with a counter.
- `lox attach` detaches on its own once the console serves (`lock NAME
  serves: detached, its console keeps running`), and runs docker's attach
  with `--sig-proxy=false`: closing the terminal only detaches, it never
  stops the console (lockhub#144).
- An IP address as host (`host`, `ssh.host`, a URL's host, the Vault
  address) is refused by `lox add`, and `lox run` stops before the review
  naming the key and the fix: the gateway answers by host name only, so
  such a lock failed later with a bare `network is unreachable`
  (lockhub#145).

## v0.10.0 (2026-11-07)

Supported locks: locklog joins `lox run` (locklog v0.2.0 or later).
`lox run` upgrades older images to locksql v0.17.0, lockmq v0.8.0,
lockfile v0.8.0, lockhttp v0.8.0 and locklog v0.2.1
(`family.ShippedLocks`); `lox add` still pins each lock's latest signed
release. lockkit v0.13.0.

New: locklog under `lox run` (lockhub#84, #87, #132):

- `lox add locklog <instance>` is guided (`--only`, `--production`,
  `--name`): locklog's profile add on this host's logs, `locklog init
  claude`, then its doctor. `lox init` lists the locklog launcher and
  hints at log stores and this host's logs. Profiles take `allowed_uids`.
  The console is capped at 2 CPUs (or the Docker host's count, if lower).
- `lox run` mounts what a locklog lock's profile reads: the plan `locklog
  mounts` derives from the reviewed copy, checked on the host, shown in
  the review, and bound read-only and non-recursive. A docker source's
  containers map lives in the state directory, is rewritten by the new
  `lox refresh <instance>` and is checked by `lox doctor`.
- Networks and routing: a locklog lock with local sources only joins the
  hub's network, with no route out; with a remote source it is on its own
  locknet behind its gateway (`LOCKLOG_NETWORK`), which no agent joins.
  Its routing defaults to tty, deck and mobile, and a `hub.routing` entry
  naming slack or telegram is refused. Local log sources are refused on an
  engine older than 19.03, or one whose version or rootless status cannot
  be read.
- `lox run` reads each locklog lock's auto rules from the reviewed copy
  (`locklog profile rules`), shows them in the review and applies them.
  Fail closed: a ticket whose rules are unknown (lock file not readable,
  instance or profile without applied rules) is always asked, never
  auto-approved (lockhub#138). The locklog routing line shows the facades
  in effect.

Fixes:

- `lox doctor` compared the hub's routing with `hub.routing` instead of
  what `lox run` writes.
- `lox doctor` no longer fails a locklog lock with no applied plan; it
  warns to rerun `lox run`.
- `lox add locklog --only` passes the directories trimmed (lockhub#138).

Other changes:

- README and docs list locklog with the supported locks; the README's
  first line uses the harness-security category (lockfamily#19).
- e2e: locklog mounts and a host agent reaching a `lox run` locklog lock
  (a masked count, then an unmask approved at the terminal facade), with
  locklog's host launcher at the release `ShippedLocks` pins (v0.2.1).

## v0.9.0 (2026-11-06)

Supported locks: `lox run` upgrades older images to locksql v0.17.0,
lockmq v0.8.0, lockfile v0.8.0 and lockhttp v0.8.0 (`family.ShippedLocks`,
lockhub#118); `lox add` still pins each lock's latest signed release.
lockkit v0.13.0.

Upgrade notes (behaviour changes):

- `lox run` (lockhub#121): in a terminal of its own, outside the agent, it
  starts the hub and the locks, then shows every ticket and decision live
  (masked) and serves decisions in auto mode by default. Reads are auto;
  writes and DDL are always asked; a connection is asked once per profile
  per session (an `ask` password or an expired Vault token is typed there
  and sealed to the lock); a new lockhttp endpoint is asked once.
  Shift+Tab switches to manual, the bell rings only for questions, and
  quitting fails closed. `NO_COLOR`, light/dark, ASCII and 80 columns are
  supported. `lox up` is deprecated.
- The hub accepts lockkit version-2 tickets (kinds), signs decisions that
  name the deciding rule (an auto rule's id, or human), relays a connect
  ticket's sealed secret, records the rule in its audit, and refuses a
  rule's approval where a human is required (`needs_human`). lockkit
  v0.13.0 (lockhub#121).
- Each lock but lockhttp reaches only the endpoints of its reviewed
  profile (database, broker, source, and Vault with `vault: true`), through
  a per-lock egress gateway on an internal network: no internet, cloud
  metadata or other host ports (lockhub#123). The review shows the
  allowlist and `lox doctor` checks it.
- `lox run` upgrades the hub and lock images older than the releases the
  installed lox ships with, at start (lockhub#118). Each new image is
  resolved by digest and cosign-verified for its release tag, and
  lockfamily.yaml is rewritten; one line is printed per upgraded image. If
  verification fails it keeps the old image and says why. It asks only if
  something besides the images changed. `--no-upgrade` keeps the pins.
- lockfile locks run under lockfile's shipped seccomp profile (as its own
  launcher runs them) instead of Docker's default (lockhub#45). The review
  shows the profile's digest; the copy is unchanged through lockfile
  v0.8.0.

Other changes:

- `lox audit` lists the hub's exchanges (ticket, masked request, decision
  with its rule or human, outcome) in `lox run`'s colours, with filters,
  `--follow`, `--json` and a pager; `lox audit show` draws one exchange's
  masked plan, deciding rule, timings and signatures; `a` in `lox run`
  opens the same view (lockhub#122).
- CI: macOS runs on main and nightly, not on pull requests (lockhub#117).
- e2e: the host launchers are the new releases (locksql v0.17.0, lockmq
  v0.8.0).

## v0.8.0 (2026-11-04)

Supported locks: as v0.7.0.

Upgrade notes (behaviour changes):

- The hub no longer crash-loops after a logout or a reboot (lockhub#112).
  `lox up` (and `lox init`, `lox add`, `lox remove`) makes the facade
  directory `$XDG_RUNTIME_DIR/lockhub` before starting anything, owned by
  you, mode 0700, and repairs one Docker made as root (an empty one is
  removed and made again, with a note). The hub's compose file mounts it
  with `create_host_path: false`, so Docker never makes it again: a hub
  restarted while it is missing stays stopped until the next `lox up`, which
  makes it and recreates the hub. A parent directory that is not yours, or
  is writable by others, is refused. The first `lox up` after the upgrade
  recreates the hub once.
- Approving a production ticket no longer needs a typed name
  (lockhub#113): `y` in `lox approve`, the approve button on the phone or
  the lea deck approves it, whatever its risk. No current Lock (locksql,
  lockmq, lockfile, LockHTTP) sets lockkit's `flags.retype`, the only
  case where the hub still asks for the instance name. Production stays
  flagged on every facade (`PRODUCTION` in `lox approve`, red on the
  phone) and chat facades still never answer it. `GET /v1/queue` items carry `retype` and the phone's
  `retype` flag is set only then, so facades that read them (`lox approve`,
  the phone, the lea deck) need no change. This replaces v0.7.0's rule
  (every production ticket but a plain read, lockhub#105) and v0.6.0's
  (every production ticket, #64).
- `lox add`'s production prompt and `--production` help no longer say
  each approval needs the profile name typed.

## v0.7.0 (2026-11-04)

Supported locks: as v0.6.0.

The lea deck needs this version for the new retype contract (`retype` on
`GET /v1/queue` items) and for the `410 lock_removed` answer.

- A plain read on a production lock (risk `read`, not `never_auto`) is
  approved without typing the instance name (lockhub#105): `y` in `lox
  approve`, the approve button on the phone. Every other production ticket
  (`read-pii`, `write`, `prod-write`, `grant`, `policy-loosen`, `unlock`, or
  a `never_auto` read) still needs the name typed, and the hub enforces it.
  `GET /v1/queue` items carry `retype`: the name to type, empty when none is
  needed, so a facade (the lea deck) reads the rule instead of copying it.
  The phone's `retype` flag follows the same rule.
- A pending ticket of a lock no longer declared (`lox remove`, a lock
  renamed, or dropped from `lockfamily.yaml` by hand) no longer stays in the
  queue forever (lockhub#103). It ends in the new final state `lock_removed`,
  audited (`"event":"remove_lock"`): `lockhub serve` sweeps once at start,
  and `lox up` recreates the hub when the lock set changes. `GET /v1/queue`
  never lists such a ticket, and deciding, revealing or renewing it answers
  `410 Gone`, code `lock_removed` (it answered `401`). `401` stays for the
  signed lock API.
- `lox add locksql` no longer asks for TLS (lockhub#102, following
  locksql#169): `--tls`, a TLS mode the project's files name, or a draft is
  written as is; otherwise the profile has no `tls` key and the driver's
  default applies.
- `lox attach` names the three start questions a console can wait on (the
  policy review, the production profile name, a password) instead of
  claiming it is the policy review, and a detach (Ctrl-P Ctrl-Q) exits 0
  with "detached from NAME" (lockhub#104).

## v0.6.0 (2026-11-03)

Supported locks: as v0.5.0.

- Grant tickets (lockhub#99): the hub knows lockkit v0.12.0's risk class
  `grant`, one approval for a bounded read scope (tables, duration, read
  budget) that the lock then runs reads inside without a ticket each. A grant
  is queued, decided and signed like any ticket (the scope's hash is its
  `plan_hash`) and is answered in the terminal or the deck only: never on the
  phone or a chat facade, and `hub.routing` cannot widen that. `lox approve`
  marks a grant and shows the lock's scope lines before asking "approve this
  grant?"; production still needs the instance name typed. Audit records of a
  grant carry `"risk":"grant"`. Ending a grant stays at the lock for now
  (`:revoke`, end of session, expiry).
- lockkit v0.12.0.

## v0.5.0 (2026-11-01)

Supported locks: as v0.4.0.

The first run is `brew install davidgodefroid/tap/lockfamily`, then lea, then
`lox add` one source at a time.

- Breaking: `lox init` sets no lock up and asks nothing. It checks the
  prerequisites, lists the data sources the project's files name as hints,
  writes a `lockfamily.yaml` with the hub alone and runs `lox up`. The flags
  `--yes`, `--manual`, `--prod`, `--credentials`, `--vault-path`, `--tls` and
  `--no-attach`, the plan screen and the manual checklist are removed,
  without an alias (the project is pre-v1). `lox init` takes `--file`,
  `--hub-image`, `--review` and `-v`.
- `lox add TYPE` (locksql, lockmq, lockfile, lockhttp) sets one source up,
  guided and applied at once: its questions, the lock's `profile add`,
  `init claude` and `doctor`, the declaration in `lockfamily.yaml`, the short
  review of that lock and the console's questions at your terminal. A
  failure, a `n` or Ctrl-C puts the lock's `config.toml` and `lockfamily.yaml`
  back and keeps the answers as a draft (`add-<type>.json` in the state
  directory, no secret) that the next `lox add TYPE` offers. `--non-interactive`
  takes the answers as flags and only declares the lock. `lox add TYPE
  INSTANCE` still only declares one ([docs/lox-add.md](docs/lox-add.md)).
- Each question says what an empty answer means: `(required)`, or
  `(optional: empty = ...)` (`(optional: - = ...)` when it has a default).
  Production is asked per lock, and there is no dev or prod question.
- Vault is per lock: a lock chooses `ask` or `vault`, runs the `-vault`
  image variant, and names its own Vault path. The Vault address, namespace
  and CA file are one shared `vault:` block, asked by the first lock with
  Vault. The token is typed at the console's start, never written.
  `lox vault set --address URL [--namespace NS] [--ca-file PATH]` writes
  that block. The "Not yet" note for Vault is gone from
  [docs/lox-up.md](docs/lox-up.md).
- `lox remove NAME [--purge]` takes a lock out and stops its console after one
  review.
- `lox up` is quiet: cosign's and docker's own output shows only when a step
  fails (`-v` shows it). Its review is short, one block per lock, and
  `--review` shows everything and asks. The first `lox up` of a workspace with
  no lock asks nothing.
- When lea already runs, a lock `lox add` declared reaches it at lea's next
  start: `lea stop`, then `lea`.

## v0.4.0 (2026-11-01)

Supported locks: as v0.3.0. `lox init` drives the launcher verbs of
locksql v0.13.0, lockmq v0.6.0, lockfile v0.6.0 and lockhttp v0.7.0 or
later (lockkit v0.10.0); it runs `doctor --fix --yes` for locksql
v0.13.1 and lockmq v0.6.1 or later, and only the advisory `doctor`
before them.

- Release: each tag bumps the `lox` formula of the Homebrew tap
  (`brew install davidgodefroid/tap/lox`), through a dispatch to
  DavidGodefroid/homebrew-tap once the archives and the image are signed
  (DavidGodefroid/lockfamily#8). The step is skipped while the
  `TAP_DISPATCH_TOKEN` secret is not set.
- `lox init` runs each lock's `doctor --fix --yes --json` again (lockkit
  GUIDE.md §14), which #92 had left out: locksql v0.13.1 and lockmq v0.6.1
  keep `.locksql/` and `.lockmq/` as `lox up` reads them. With a launcher or
  image older than these (asked with `<lock> version`, once per lock type),
  or versions it cannot read, it runs the advisory `doctor --json` and says
  to update. lockhttp's `--fix` only takes group and others' write away
  from its policy. lockfile's doctor still runs without `--fix`: its only
  repair wires every installed agent for your account. The plan says which
  doctor runs and what locksql's `--fix` also does (it wires your installed
  agents for your account) ([docs/lox-init.md](docs/lox-init.md#the-doctor)).
  The e2e drives the launchers of locksql's and lockmq's main (the fix,
  until v0.13.1 / v0.6.1 are tagged) with the images `lox add` pins (the
  latest signed releases), and checks whichever doctor ran: with images
  older than the fix, the advisory one and its note.
- `lox init` (#80): one command activates the Lock Family in a project.
  It checks Docker (with the install command for the system when it does
  not answer), cosign, lea and the locks' launchers; detects PostgreSQL,
  MySQL, MariaDB and RabbitMQ from the project's `.env*`, `compose*.yaml`
  and `config/` (read only; keys named like secrets are skipped and a URL
  keeps no password); proposes one lock per source (auto) or a checklist
  (`--manual`: lea, locksql, lockmq, lockfile, lockhttp, locklog, greyed
  with the reason when not possible); and, once the plan is confirmed, runs
  each lock's launcher verbs (`profile add --non-interactive --json`, `init
  claude`, `doctor`, lockkit GUIDE.md §14), `lox add`, `lox up` (its
  review unchanged) and `lox attach` for each console that started.
  Re-runnable: declared locks are kept, new sources added, unchecked ones
  removed through the same review. `--yes` with flags for non-interactive
  use. Sources on this machine are given as `host.docker.internal`. lea's
  uid goes in `allowed_uids` when lea is found (`lox add` takes it)
  ([docs/lox-init.md](docs/lox-init.md)). New e2e job: a compose project
  (PostgreSQL, RabbitMQ) set up by `lox init --yes`, a host agent's query
  and read approved, then a re-run that adds a database and leaves the
  other locks untouched.
- Host agents reach `lox up`'s locks (#78): the locks' launchers
  (`locksql mcp` and the other agent commands, as `<lock> init` writes them
  in `.mcp.json`; lockmq and lockfile alike) mount the socket volume
  up.json names, read-only, after lea's checks
  ([docs/lox-up.md](docs/lox-up.md#host-agents-the-locks-launchers),
  with the threat model). up.json keeps its two-space indented layout,
  which they read. The e2e (phase 2) drives a host `locksql mcp` from plan
  to rows through a facade approval, and the refusals of a tampered
  up.json or a read-write squatter on the socket volume.
- The e2e (phase 2) runs a lockmq lock too (#78): a RabbitMQ 4.1.8 broker
  with a read-only user and a stream holding one message; a host
  `lockmq mcp` (lockmq v0.5.0's launcher and image) reads it, pending,
  then gets the message once the ticket is approved at `lox approve`.
  lockhub's CI now runs a lockmq image under `lox up`.

## v0.3.0 (2026-10-31)

Supported locks: as v0.2.7.

- Breaking: the host CLI is renamed `lock` → `lox` (#79), without an
  alias: `lock` is taken (GNOME's "Lock" in Nix, AUR, Guix and ALT,
  FreeBSD's `lock(1)`) and too generic to be found. `lox up`, `lox add`, `lox
  import`, `lox attach`, `lox doctor`, `lox approve`, `lox mobile`, `lox
  audit verify`, `lox version` (prints `lox X.Y.Z`); every message, help
  text and error prefix says `lox`. The release archives are
  `lox_X.Y.Z_<os>_<arch>.tar.gz` holding `lox`; the hub image ships
  `/usr/local/bin/lox`; the source is `cmd/lox`, and docs/lock-up.md is
  now docs/lox-up.md. Unchanged: the `lockhub` binary, image and service,
  `$XDG_STATE_HOME/lockfamily`, `.lockfamily/lockfamily.yaml`, up.json,
  the compose project `lockfamily-<sha8>`, the `dev.lockfamily.*` labels
  and `/run/lockfamily*`. The Lock Family install.sh must install `lox`
  from this release on (lockfamily ships in lockstep).

## v0.2.7 (2026-10-31)

Supported locks: as v0.2.6.

- Builds on lockkit v0.8.1 (was v0.6.0). Nothing changes for the hub's
  own API or for the locks it supports: the hub URL lock up gives a lock
  (`http://lockhub:8443`, up.json's `hub_url`) is already the
  `http(s)://host[:port]` form lockkit v0.7.2 and later require. A ticket
  the hub refuses (`bad_ticket`) no longer quotes the value lockkit found
  wrong in it (an unknown risk class).
- CI's lockkit compatibility check also builds lockhub on the lockkit
  release before the pin (v0.8.0), against the same three sets of
  fixtures.

## v0.2.6 (2026-10-31)

Supported locks: as v0.2.5.

- Configuration errors no longer echo the value given (a token pasted
  into the wrong key would have shown in the terminal, the hub's logs and
  an agent's output): they name the key, the list entry (`hub.facades[1]`)
  and the values allowed, never the value. Covers lockfamily.yaml
  (`hub.image`, `hub.facades`, `hub.routing`, `hub.mobile.origin`,
  `require_device`, `allowed_uids`, the slack and telegram allowlists,
  instance names that are not valid), the yaml errors of `lock up`, `lock
  add`, `lock import` and `--pin` (type errors, explicit tags, aliases to
  an unknown anchor, unknown or repeated keys: the line and the key path
  stay, and a key is shown only when lockfamily.yaml knows it or as a
  valid instance name under `locks` and `hub.routing`), chat.json,
  locks.json and routing.json, `lockhub serve --mobile-origin` and
  `--facade-socket-mode`, `lock up --pin` and `--rotate`, `lock add
  --version`, `lock add telegram --chat`/`--from` and `lock audit verify
  --lock`. Still shown: valid instance names (a lowercase hex token pasted
  as a lock's name is one), positional arguments, and a bad value of a
  boolean flag (Go's flag package quotes it).
- `lock add --hub-image` is checked before it is written in a fresh
  lockfamily.yaml: it can no longer make other keys there.
- The telegram facade no longer lets a bot token that is not a valid URL
  part (a `%`, a control character) reach the hub's logs in a URL parse
  error; the lock keys warnings of `lock up` no longer quote an invalid
  instance name.
- Error texts changed: those above, and the hub's refusal of an unknown
  facade or risk class (`route`), which now lists the known ones.

## v0.2.5 (2026-10-31)

Supported locks: as v0.2.4, plus locksql v0.11.2 (lockkit v0.7.1), the
first whose console takes `--allowed-uids`: with a lock's `allowed_uids`,
lea's agents reach a locksql lock too (locksql#139, lea#226). An older
locksql image with `allowed_uids` set refuses the flag and does not start:
leave the key off for it.

- lockfamily.yaml `allowed_uids` on locksql locks too (locksql#139): lock
  up passes it as the console's `--allowed-uids` (locksql v0.11.2 or
  later; an older locksql image refuses the flag and does not start), so
  that lea's agents reach a locksql lock as they reach lockmq and lockfile
  ones. Same rules: uids only, each once, never root, 65534 nor the
  console's own uid (10001); still refused on lockhttp locks.

## v0.2.4 (2026-10-30)

Supported locks: as v0.2.3, plus lockmq v0.4.1 and lockfile v0.5.1
(lockkit v0.6.0), the first whose consoles take `--allowed-uids`: with a
lock's `allowed_uids`, lea's agents reach a lockmq or lockfile lock (lea#226).
An older lockmq or lockfile image with `allowed_uids` set refuses the flag
and does not start: leave the key off for it. A locksql lock still refuses
lea's agents under lock up (locksql#139).

- lockfamily.yaml `allowed_uids` per lockmq or lockfile lock (lea#226):
  lock up passes it as the console's `--allowed-uids` (lockmq v0.4.1,
  lockfile v0.5.1 or later), so that lea's agents, which run as the host
  user's uid with no account in the lock's image, reach it. Reviewed like
  any change; uids only, each once, never root nor the console's own uid;
  never 65534 (nobody); refused on locksql (no such flag yet) and lockhttp locks. `lock import`
  keeps the uids every declaration lists.

## v0.2.3 (2026-10-30)

Supported locks: as v0.2.2, plus locksql v0.11.1 (lockkit v0.7.1), the
first locksql whose audit records of hub decisions carry `hub_sig`
(locksql#118, locksql#133, locksql#137): `lock audit verify --lock` checks
its approvals, denials and renewals of approved tickets against the hub's
signed decisions (older locksql records approvals unsigned, and does not
record denials or renewals, which show as decisions not in the log).

Upgrade notes (behaviour changes):

- Production tickets: approving one now needs its instance name typed on
  every facade (#64). Upgrade the `lock` CLI with the hub: an older `lock
  approve` (v0.2.2 or older) is refused on production tickets by this
  hub, and this `lock approve` is refused by an older hub on a ticket
  whose `flags.retype` is set. An older lea deck (lea v0.3.1 or older)
  asks for `flags.retype`, which this hub refuses, so it no longer
  approves production tickets as it prompts: use this release's `lock
  approve` or the phone (where it is routed), or a lea release with
  DavidGodefroid/lea#222 (planned for lea v0.3.2); likewise, a lea with
  lea#222 needs this hub for tickets whose `flags.retype` is set. A phone
  page left open needs a reload to show the field.
- Routing: a hub without `routing.json`, or with one that lists no
  `facades`, no longer routes anything to Slack or Telegram (#61). Under
  `lock up` nothing changes (it always writes `facades`); a hand-run hub
  must list its chat facades.

Changes:

- Every production ticket needs its instance name typed to be approved,
  on every facade that may answer it: `lock approve`, the deck and the
  phone (#64). The hub, `lock approve` and the mobile web app used to ask
  for lockkit's `flags.retype` instead, and only when it was set: lockkit
  sets it to the console's "retype values" answer (such as `r`), never to
  the instance name, so most production tickets were approved with a
  plain `y`. Chat facades still never answer production.
- A hub started without `routing.json` (or with one that lists no
  `facades`) now routes tickets to the local facades only (terminal,
  deck, phone), never to Slack or Telegram (#61, invariant I9). It used
  to route and notify read, read-pii and write tickets to both chat
  facades, though none ran. A chat facade is routed only when
  `routing.json` lists it, as `lock up` writes it; the phone stays
  implicit (it serves nothing without `--mobile-listen`).
- Slack and Telegram: a message close (`chat.update`, `editMessageText`)
  that fails (a rate limit, a network error, a 5xx) is retried with
  backoff (2 s doubling to 5 min, 15 tries, about 40 min), so a decided,
  withdrawn or expired ticket's message no longer keeps live buttons
  after one failure (#60). Every close is bounded (15 s), and the facade
  goes back to clicks and the queue after two retries. A message the
  service says can no longer be edited is not retried; Telegram's
  "message is not modified" (a retry after another chat failed) counts as
  done. A click on stale buttons is still refused (by the facade and by
  the hub); on Slack it also tries the close again at once, at most once
  per 2 s, without using up a try. A ticket decided on a chat is no
  longer posted again from a queue snapshot taken before the decision.
- CI: phase 5 fails on a `lock doctor` failure (#63); phase 2 drops the
  database and role it made and checks the screen's literal (#62); tests
  for I9 (#58); deflaked chat-close and queue-order tests (#55, #57).
- docs: design notes, the accepted deviations from the hub plan (#59).

## v0.2.2 (2026-10-30)

Supported locks: as v0.2.1. `lock add` now pins locksql v0.11.0 or later
(it was v0.10.0): a locksql lock under `lock up` needs `LOCKSQL_PII_DIR`.
lockhttp's `devices: true` is now wired, through lea's gate (lockhttp
v0.4.0 or later, lea v0.3.0 or later); the v0.2.0 and v0.2.1 notes saying
to leave it off no longer apply.

- A locksql console keeps its PII rule sets in its own home volume
  (`LOCKSQL_PII_DIR`, locksql v0.11.0): `lock up` no longer refuses a
  `.locksql/` without a rule set, and the console writes its first set,
  `pii add` and later proposals there, seeded once from the profile's
  `.locksql/pii/` (#53, #41). `lock add` pins locksql v0.11.0 or later.
- up.json says what lea's lockhttp gate pins (`"lockhttp_gate": 1`): the
  paired devices (top-level `devices`) and, per lock, `devices`,
  `require_device` and `seal_clear` as lock up passes them to its
  consoles, beside `profile` and `reveal` (#51, #40). lea's gate asks the
  hub only from `lockhttp_gate` 1 on (lea#209).
- `devices: true` on a lockhttp lock goes to its gate (its console only
  serves the policy), consistently in validation, docs and tests; when the
  devices or what a gate pins change, `lock up` says to restart lea's gate
  (#54, #46).
- CI: e2e phase 2 runs a locksql lock against Postgres next to the two
  LockHTTP locks: its first PII rule set is written in the console's
  volume, and an approved query reaches the agent with the email masked
  (#53).

## v0.2.1 (2026-10-30)

Supported locks: as v0.2.0 (builds on lockkit v0.6.0), plus locksql
v0.11.0 (lockkit v0.7.1), the first locksql release that takes
`devices: true` and reveals/renewals (lock up's `--devices-file` and
`--facade-keys-file`; lockhttp `devices` is still not wired, see v0.2.0).

- A `lock import` or `lock add` refused for a new workspace no longer
  leaves an empty `.lockfamily/` behind (#48).
- Hub requests (reveal, renew): an open request still unanswered 2 s
  after it was given to a lock is offered again to every poll of the
  instance, so a request taken by an old lock process while the live one
  was between polls no longer times out at the facade (#49).
- CI: the e2e phases verify the hub's signer identity with real cosign and
  check the image the hub runs (#50).
- lock up's refusal of a group- or world-writable profile names the mode
  in octal (`mode 0775`) (#50).

## v0.2.0 (2026-10-30)

### Supported locks

Builds on lockkit v0.6.0. `lock add` pins only releases that run under
`lock up` (hub mode, lockkit v0.3.1 or later); the optional features need
newer locks:

| Lock | Runs under lock up (lockkit ≥ v0.3.1) | `devices: true` (lockkit ≥ v0.4.0) | Reveals (`reveal: true`) and renewals (lockkit ≥ v0.5.0) |
|---|---|---|---|
| locksql | v0.10.0 (lockkit v0.3.1) | no release yet | no release yet |
| lockmq | v0.3.0 (lockkit v0.3.1) | v0.4.0 (lockkit v0.6.0) | v0.4.0 |
| lockfile | v0.4.0 (lockkit v0.3.1) | v0.5.0 (lockkit v0.6.0) | v0.5.0 |
| lockhttp (pre-releases) | v0.3.0 (lockkit v0.3.1) | not wired by lock up yet (the gate takes `--devices-file` from v0.4.0, but up.json does not carry the devices): leave `devices` off | v0.5.0 (lockkit v0.6.0) |

lock up passes `--devices-file` and `--facade-keys-file` to the locksql,
lockmq and lockfile consoles only. The lockhttp console serves the policy;
the hub is asked by a hub-mode gate beside lea's proxy, which takes the
facade keys (not the devices) from up.json; that gate is not in lea yet
(docs/lock-up.md). A lock older than a feature it is asked for refuses the
flag and does not start: leave `devices`/`reveal` off for it. A lock on
lockkit older than v0.5.0 ignores the `requests` member of the decisions
poll: a reveal or renewal asked of it times out. lockssh has no release yet
and is not a lock up type.

Upgrade notes: `lock up --rotate hub` needs a hub image of this release
or later (`lockhub rotate-key`); once a hub key is rotated, an older hub
or `lock audit verify` refuses the log (`key_rotated` record), as an older
`lock audit verify` refuses one with `outbox` fields: upgrade the `lock`
CLI with the hub.

### Changes

- First release of the `lock` CLI with lock up's `.lockfamily/` layout,
  console accounts and `up.json` for lea (#23: the `lock up runs consoles
  lea's agents can reach` entry below): lockfamily's
  install.sh installs the latest release, which was v0.1.1 without them.
- The paired devices' snapshot lock up mounts in the locks is 0644
  whatever the umask (#39): under umask 077 the consoles could not read it.
- CI: workflow e2e-lock-up runs the hub plan's phase 1 (locksql's
  TestHubPhase1 against this tree), phase 2 (lock up, lock attach, a
  ticket approved through the facade socket, I2 directly and through a
  LockHTTP gate, I11, a second lock up) and phase 5 (install.sh, lock add,
  lock up, lock import) end to end with released images.
- Note for upgrades: lock up now resolves the workspace's links, so a
  workspace opened through a symbolic link gets a new project (and state):
  its first lock up is a full review again.

- A renewal's `unchecked` inputs (lockkit v0.6.0: the lock could not
  check them now) are shown as such, and never allow one click.
- Hub requests (reveal, renew) and two pollers of one instance (a lock
  restarted while its old process still polls): a request now ends every
  long poll that began before it was first given to a lock, not only the
  first to take it; the others no longer sleep out their poll with it (a
  lost wake-up). A poll that begins after the request was given still
  waits.
- `lock up --pin sha256:<digest>` restores a previous hub image by digest
  (reviewed, cosign-verified, written to lockfamily.yaml once applied;
  `hub-images.log` keeps the history), and `lock up --rotate
  hub|INSTANCE|all` replaces the hub's or locks' keys through the review
  (docs/lock-up.md). The hub's rotation is `lockhub rotate-key`: a
  `key_rotated` audit record signed by both keys, the old key in the data
  directory's `retired-keys.pub`, which the hub reads at start. `lock
  audit verify --hub-key-file` takes a file of keys, oldest first (lock
  up's `hub-keys.pub`); with one key, as before. An older `lock audit
  verify` or hub refuses a log with a `key_rotated` record.
- `lock up` no longer overwrites the per-user `facades/locks.json` with the
  current workspace's lock keys: each workspace's keys go to
  `facades/locks.d/<project>.json` (with the workspace's path) and
  `locks.json` is their union (one hub per user, many workspaces),
  rewritten under a lock. An instance name two workspaces pin with
  different keys, one key on two instances, or another workspace's file or
  key that does not parse is left out, and `lock up` warns, naming the
  workspaces and files: clear values of those tickets cannot be shown
  until one is renamed, or the file of a workspace that no longer exists
  (moved or deleted) is deleted. After the upgrade, run `lock up` once in
  each workspace; a `lock` binary of an earlier release still overwrites
  `locks.json` without the lock.
- A lockkit compatibility check (`scripts/compat.sh`, CI job `compat`):
  lockhub built on the pinned lockkit, its ticket codec checked against
  the signed ticket fixtures of the pinned lockkit, of the release before
  it and of the newest release (`LOCKKIT_FIXTURES`). A build on the
  release before the pin (`compat.sh prev …`) is manual: lockhub uses
  lockkit v0.6.0's API.

- Mobile facade: optional Web Push (`hub.mobile.push: true` →
  `lockhub serve --mobile-push`; off by default). When a ticket the phone
  may answer becomes pending, the hub sends a payload-less push (no ticket
  content at the push service; `TTL`, `Urgency: high`, `Topic`, at most
  one round per 30 s) with VAPID (RFC 8292, ES256; P-256 key `vapid.key`
  created once in the hub's data directory) to every subscription of an
  active device. Endpoints are restricted to the known push services
  (FCM, Mozilla, Apple, WNS: https, default port, public addresses, no
  redirects); subscriptions are tied to the device session
  (`/m/v1/push`, `/m/v1/push/subscribe|unsubscribe`, Origin and custom
  header), dropped on revoke and on 404/410. The web app gets an "Enable
  notifications" button; the service worker shows a generic
  notification. `lock up` reviews push and gives the hub its `egress-hub`
  network for it.
- lock up runs consoles lea's agents can reach, and tells lea how
  (docs/lock-up.md):
  - lockfamily.yaml lives in `.lockfamily/` (lea mounts it read-only in
    its agents' containers); a legacy `./lockfamily.yaml` is still read,
    with a warning. lock import finds `*/.lockfamily/lockfamily.yaml` (or
    a legacy `*/lockfamily.yaml`).
  - After applying, lock up writes `.lockfamily/up.json`: the compose
    project, the hub's network and key, each lock's socket volume
    (labelled `dev.lockfamily.role=socket`, which lea checks before it
    mounts one) and clients group.
  - Each console runs as its image's console account, with a terminal
    (`tty`, `stdin_open`): it asks its policy and the credentials it does
    not take from Vault there; `lock attach INSTANCE` answers it. Its own
    profile directory (`<workspace>/.<type>`) is never mounted: lock up
    snapshots it (no links, the user's own files only), shows its
    fingerprint in the review, and copies the reviewed archive into a
    root-written volume, read-only in the lock (at the same path for
    locksql and lockmq, whose socket name derives from the project path). `profile:` (optional)
    names the profile; lockfile's defaults to `default`.
  - The hub's public key reaches the locks in the `hubkey` volume, written
    by root, read-only in the locks (locksql refuses a key file another
    account could rewrite).
  - lockhttp: the hub is asked by the gate, which lea runs beside its
    proxy, not by the console (lockhttp#11). lock up runs the lockhttp
    console (policy only, no hub network) and makes the gate's own volume
    and instance key; lea's gate uses them.
- lock add pins the latest release (or `--version vX.Y.Z`) of the lock,
  and of the hub for a new workspace, by digest, once cosign verified it
  was signed by that repository's release workflow for that tag.
  `--image` still pins one by hand.
- Mobile facade (#10): an installable web app (embedded, no build step) on
  its own listener, published on host loopback for the human's TLS reverse
  proxy or tunnel (`hub.facades: [mobile]`, `hub.mobile.origin`). Phones
  pair with `lock mobile pair` (one-time code, WebAuthn registration with
  user verification, fingerprint confirmed at the terminal); `lock up`
  reviews paired devices and pins them at the locks that set
  `devices: true` (`--devices-file`; their image needs lockkit ≥ v0.4.0),
  with `seal_clear` (clear screens sealed end to end to the phones) and
  `require_device` (locks refuse approvals of those risk classes not
  signed by a phone). Each decision on the phone is a WebAuthn assertion
  over the decision and the hash of the lock's signed ticket, checked by
  the hub before it signs and by the locks after (lockkit v0.4.0). Sign
  counters, single-use challenges and drafts, `__Host-` session cookie,
  Origin and custom-header checks on every POST, strict CSP. The phone
  answers every risk class but `unlock`. Audit records carry the device;
  device pairings and revocations are audited. `lock mobile list|revoke`;
  `lock doctor` reports devices paired since the last `lock up`.
- Tickets and decisions without devices are unchanged: locks on lockkit
  v0.3.1 still work; pinning devices needs lockkit v0.4.0 in the lock.
- `lock audit verify --lock INSTANCE=PATH` (repeatable) also verifies
  lock-side audit logs (lockkit's `audit.log`, or its directory): the
  chain (lockkit `audit.Verify`), and every record of a hub decision
  (`approval: hub` approved or denied, or any record with `hub_sig`)
  against the decision the hub signed for that instance and ticket: same
  outcome, approver and facade, and same signature when the record has
  one (locksql does not record `hub_sig` yet: its records are checked on
  the rest, and counted). A record whose hub fields do not read fails.
  Hub decisions the log has no record of are counted (not acted on yet,
  or cut). With `--anchors FILE` (host only, 0600) each verified log's
  anchor is kept between runs and the next run uses lockkit
  `audit.VerifyAnchored`, so a log cut before it or stripped of its chain
  is refused; a failed log keeps its old anchor (a cut after the anchor
  is not seen until the next run). A second hub approval of one ticket
  fails. Not checked: records a hub-mode lock should not write at all
  (a local approval).

- `lock doctor` asks the hub for its queue over the facade socket: it
  says whether the hub answers, shows the pending caps and rate limit
  (lockkit's defaults: each lock 20 pending plans, 10 new tickets per
  5 min, counted in memory; the hub: 50 per lock), that this quota is per
  lock instance, shared by every agent of the workspace, and each lock's
  pending tickets on the hub (warned from 80%).

- Audit records are written after the database commit, through a
  transactional outbox: each change stores its record in its own
  transaction, signed with the hub key together with its outbox row id,
  and the record is appended to `tickets.jsonl` once the transaction
  commits (after a crash, at the next start, before serving). A
  rolled-back change never has an audit record, and a committed one
  always gets one, exactly once: each record now carries its `outbox` id,
  ids only grow along the log, and a row replayed into the database, or
  not signed for its id, stops the flush instead of being signed into
  the log. While the log cannot be written, every change starting after
  the failure is refused (HTTP 503 `audit_down`); the changes already in
  flight commit with their records waiting in the outbox, and their
  decisions are delivered to locks meanwhile (durable and signed, not yet
  in the log). A failed append is cut back from the log, and a torn last
  line left by a power loss is cut at start, so a retry chains the record
  once. `lock audit verify` reads the database as of one instant, then
  the log, so it can run against a live hub; it accepts a decision whose
  record is still in the outbox, says how many records await the log, and
  reports replayed or foreign outbox rows. An older `lock audit verify`
  refuses a log with `outbox` fields: use this release's.
  A `hub.db` restored from a backup older than `tickets.jsonl` makes
  every new outbox row look like a replay, and the hub refuses to start:
  restore both together (or set `audit_outbox`'s row in `sqlite_sequence`
  past the log's last `outbox` id). Not detected: an outbox row deleted
  from the database by someone who can write it, before its flush, for a
  record other than a decision (decisions are cross-checked).

- `GET /v1/hello` also answers `ticket_versions` (the ticket schema
  versions the hub verifies: lockkit's `ticket.Version`) and `hub_key_id`
  (lockkit `ticket.KeyID` of the hub key). Unsigned like the rest of the
  hello: for display and diagnosis only, never to pick or pin a hub key
  (a lock trusts only the key it pinned). An N-1 version appears once
  lockkit verifies two ticket versions.

- A rotated Slack or Telegram token (`lock add slack`/`telegram` again)
  is now a change `lock up` reviews and applies: the summary carries
  each chat secret's identity (a short hash, never the token), so the
  hub's config label changes and compose recreates the hub, which reads
  its tokens at start. Before, the hub kept the old token until it
  restarted. `lock doctor` warns about a token rotated since the last
  `lock up`. The first `lock up` after upgrading with a chat facade
  shows the new `hub secret` lines once, asks for a yes, and recreates
  the hub.
- Clear values on demand (Ctrl-O) and re-approval of expired tickets
  (decision H1).
  - Hub requests: the hub signs a `reveal` or `renew` request
    (lockkit `ticket.HubRequest`), hands it to the lock in its
    `GET /v1/decisions` long poll (new `requests` member, waking the poll),
    and relays the lock's answer (`POST /v1/requests/{id}/answer`, signed
    like every lock call, accepted once and only from that instance) to the
    waiting facade. In memory only, 8 open per instance, 30 s wait (504),
    bounded bodies; a lock's error is a fixed code, never its text.
  - Facade socket: `POST /v1/tickets/{instance}/{id}/reveal` (tty and deck
    only, routed to the ticket, the key signed for the caller's facade) and
    `…/renew`; `GET /v1/queue` gains an `expired` list (expired in the last
    24 h, not renewed yet). The hub relays the sealed answer without storing
    or logging it; the audit log records `reveal` and `renew` events (who,
    which facade, outcome), never content.
  - Renewals: a ticket that renews another ends it expired (pending, or
    approved and not run; only a renewal ends an approval, never the
    sweeper) and links them. A renewal asked from the terminal or the deck
    within 24 h of the expiry, unchanged, with the old ticket's risk and
    flags, and not for production, is approved at once; otherwise it waits
    with its changes, production still asks for the typed name.
  - `lock up` creates per-user tty and deck facade keys
    (`$XDG_STATE_HOME/lockfamily/facades/`, 0600), reviews them
    (`facade tty key …`), mounts their public halves read-only in every lock
    with `reveal: true` at `/run/lockfamily-facades/facades.json` with
    `--facade-keys-file` (reviewed: `lock … pins the host facades' keys`),
    and keeps a host-only copy of the pinned lock keys there for facades to
    verify a lock's answers. up.json carries the same set (`facade_keys`)
    and each lock's `reveal` for lea's lockhttp gate (`--facade-keys-file`,
    lockhttp#16, lockhttp v0.5.0 or later), which lock up does not run.
  - A renewal routed to mobile with Web Push on may send a push for a
    ticket the one-click path approves a moment later (the push carries no
    content; the phone then finds nothing waiting).
  - `lock approve`: `o` reveals (Ctrl-O too where the terminal passes it;
    macOS keeps ^O), clearly marked and escaped; `r` on an expired ticket
    approves it again; a renewal shows what changed.

## v0.1.1 (2026-10-30)

Supported locks: images built on lockkit v0.3.1 (tested), such as the
first locksql, lockfile, lockmq and lockhttp releases with hub mode. Locks built
on lockkit v0.3.0 do not know `--hub-plain-http` and refuse the generated
command.

- The generated lock command passes `--hub-plain-http` (#20): lockkit
  refuses an http:// hub without it (DavidGodefroid/lockkit#72), and the
  hub is reached by its service name on the internal `lockhub` network.

- Builds on lockkit v0.3.1 (was a pre-release commit, 1d085bb) (#21).

Correction (v0.2.3): the note above overstates what v0.1.1's `lock up`
runs. It passes no `--profile`, mounts no profile and gives the consoles
no terminal: lockfile (v0.4.0 requires `--profile`) and lockhttp (its
console takes no `--hub`) refuse the generated command, and locksql
v0.10.0 and lockmq v0.3.0 refuse to run without a terminal (and would
find no profile in their empty home volume). Use `lock up` from v0.2.0
on with any lock (see the v0.2.0 table).

## v0.1.0 (2026-10-30)

First release. Supported locks: images built on lockkit v0.3.0 (hub
mode). lockkit v0.3.1 and later refuse the generated `http://lockhub:8443`
hub URL without `--hub-plain-http`: use lockhub v0.1.1 with them.
(v0.2.3: neither this release's nor v0.1.1's `lock up` runs a released
lock as generated, see the v0.1.1 correction; use v0.2.0 or later.)

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
