# lox run and lea

`lox run` runs the hub and a workspace's locks with Docker Compose. Agents
reach the locks' sockets, never the hub: lea's agents in their containers,
and a host agent (Claude Code, Codex... run in a terminal) through the
locks' own launchers (`locksql mcp`, `lockmq mcp`, `lockfile mcp`, `locklog
mcp`, as `<lock> init` writes them in `.mcp.json`). The locks `lox run` runs:
locksql, lockmq, lockfile, lockhttp and locklog. This page is the contract
between `lox run` and both.

## Serving decisions

`lox run` is meant for a terminal of its own, outside lea and any agent: it
first starts (or reuses) the hub and the locks (everything below: the
review, `--review`, `-v`, `--pin`, `--rotate`, and the upgrade of images
older than this lox's releases, `--no-upgrade`), then serves the hub's
decisions in the foreground until you quit. `--no-start` only serves
decisions (the stack runs already); `--manual` starts in manual mode;
`--theme light|dark` overrides `COLORFGBG`. stdin must be a terminal: an
answer is typed by a human, never piped.

It follows the hub's queue over the facade socket, checks each ticket under
the lock key it pinned (`locks.json`), and decides it with its engine
(`internal/loxrun`):

| Ticket (lockkit kind) | Auto mode | Rule named in the decision |
|---|---|---|
| `read` (risk read, read-pii) | approved | `default:read` |
| `action` that only reads (MQ peek, file read) | approved | `default:action` |
| `action` that writes, `write`, `ddl` | asked every time | (human) |
| `connect` | asked once per instance/profile per session, then approved | `session:connect` |
| `endpoint` (lockhttp host + route) | asked once per session, then approved | `session:endpoint` |
| `policy`, a grant, `never_auto`, a production name to type | always asked | (human) |
| version-1 ticket (no kind), or one not checked under a pinned key | always asked | (human) |

Manual mode (Shift+Tab, `--manual`) asks every ticket. A rule is only ever
applied to a version-2 ticket: the hub signs its decision with the rule
(`rule: {by: auto, id}` in lockkit's decision, `"rule"` in the hub's audit
record), refuses a rule's approval of a never-auto ticket or of one whose
approval needs a typed name (`needs_human`), and accepts a rule from the
terminal facade only. Per-profile auto rules (`auto`/`ask`/`deny` per action,
`Engine.Rules`) are applied when a lock provides them: locklog's (below,
[locklog: auto rules](#locklog-auto-rules)); for the other locks (locksql#185,
lockmq) the defaults above hold until they do. A `deny` rule holds in both
modes.

**Connections.** A lock starts disconnected (lockkit `lazyconn`): an agent's
first request for a profile reaches the lock over its socket, the lock sends a
`connect` ticket, and it connects on the signed decision. When the profile's
credentials are `ask` (or its Vault token expired), the ticket carries a
one-use key of the lock: `lox run` asks the password (or token) in the card,
seals it to that key (`ticket.SealSecret`, only for a ticket it verified under
the pinned lock key) and sends the box with the approval; the hub relays a box
it cannot open and the agent never sees it. An `ask` password is kept in `lox
run`'s memory only once the lock connected with it (its connect ticket was
consumed), to answer the profile's next connect ticket after an idle close;
it is wiped when `lox run` ends. A connect that never runs drops it. A profile
that asks to connect again within 30 seconds of connecting, with nothing run
on it in between, has it dropped and is asked again, so a password the
backend refused after the dial is not sent on every retry. `x` drops a
profile's session connection, endpoints and password by hand (the profile of
the question on top; with no question up, every profile). `y` on a connect
always shows the password prompt: Enter alone keeps the session's password,
anything typed replaces it. A Vault token is asked
each time the lock asks. The header lists the connected profiles (a connect
ticket the lock acted on) with their age, until they have been idle for the
locks' idle timeout.

**The screen.** A fixed header (workspace, the `AUTO`/`MANUAL` badge, hub
status, locks, waiting questions, connected profiles), the feed (one line per
ticket: time, agent in a stable colour, lock icon and instance, profile in red
for production, kind, the masked request with SQL/HTTP/MQ keywords
highlighted and masked values set apart as `‹…›` in dim italic, the decision
with the rule that made it: `auto:read` (`auto:action`, `auto:session` for a
connection or endpoint approved earlier in the session) dim green, `✔ you`
green, `◆ ask:<why>` bold yellow (`ask:write`, `ask:connect`, `ask:lock`
when the lock wants a human: its profile's auto rule is not auto,
`ask:name` for a production name to type, `ask:grant`, `ask:v1`,
`ask:unsigned`, `ask:manual`), `✘ denied` red, `! error` magenta, then `✓`
once the lock ran it; below 64 columns `auto` and `◆ asked` alone), and the
footer's keys. A profile whose lock asked one of its reads (`read = "ask"` in
its auto table) shows `reads asked` next to it in the header: production
alone never asks a read.
Equal auto reads fold into one line (`× 12 SELECT on orders`). A question is a
framed card above the feed: what, who, which profile, the masked screen,
why it is asked, and `y` / `n` / `d` (details) / `x` (forget the profile); a production name or a secret
is typed in the card. A sound plays only when a card appears (see below).
`Tab` brings the next card up (with one card or none, it shows the next
lock tab), `a` shows the hub's audit (as `lox audit`
lists it, read again every second while open), `s` turns the sound on or off
for the session, `?` the keys, `q q` or Ctrl-C quits.

**A tab per lock.** Next to the global feed (`0`, the default), each lock
whose console `lox run` follows has a tab (`1`…`9`, `Tab`): what the lock
decides on its own side, which never reaches the hub, read at its console's
terminal over the docker attach `lox run` holds (an agent has no Docker: it
can neither read nor write this channel, and nothing of it goes to the hub).

- **The console feed**: each plan as the console frames it (the requester,
  the agent's words, the statement, its class, EXPLAIN summary and verdict,
  the verdict's reasons, the row bound and PII masking), how it was sent on
  (`pending: ticket …`) and what it gave (`done: 93 rows in 3946 ms`, an
  error). The statement (and the agent's words, a k-anonymity count's
  statement) shows in clear only up to its first byte that may open a
  literal, a quoted identifier or a comment in some dialect (`'` `"` `` ` ``
  `[` `$` `#` `--` `/*`, or a non-ASCII byte): from there on each line is
  one `‹?›`, so no dialect's reading can show a value; numbers before it
  are masked too, but for a `LIMIT`, `OFFSET` or `TOP` bound. `o` shows
  the statements in clear on this screen only (they never leave
  `lox run`'s memory). A line the tab does not
  know (a result row printed with results on) is left out.
- **Lock-side refusals** (`refused [E_COST]: …`, a refused construct, a
  ticket not submitted because the lock's rate limits are reached,
  `THROTTLED`, lockkit#150): their code and reason, the same refusal from
  the same requester folded into one line with a counter (`×11`). Three in
  a row (`Session.RefusalLoop`) raise an alert line in the global feed
  (`lock-side refusal loop: E_COST ×3 …`) and ring the bell: an agent is
  looping on a refusal the hub never sees.
- **The policy state**: approved, **pending** (a loosening in the files
  waits for its review) or **refused** (the human refused it, at the
  console's start or at `:review`: the last approved policy applies, not the
  files'), with the change as the console worded it. `r` types `:review` at
  the console; its question comes up as a card (the change, `y`, the
  production name typed) and is answered at the console's terminal, without
  `lox attach`. A loosening refused once is offered again by the console
  only once the files change (lockkit keeps its refusal until then).
- **The session state**: serving or ended (and why), the idle time since
  the last request seen and the time left before `idle_timeout`, the time
  left before `max_session`, from the limits the console says are in force
  (its `:status`, the approved policy's values, never the files'). `lox run`
  types `:status` once each time it attaches to a serving console (a line
  typed counts as activity for its idle timeout); `i` types it again.
- **A badge** on a tab that wants you: `policy pending`, `policy refused`,
  `refusal loop`, `question`.

`lox run` reads what a console printed before it attached (its start, a
policy change refused there) from its container's logs (`docker logs`, the
last 200 lines, then what it printed since the last attach).

**Stuck tickets are withdrawn, not waited out.** `w` lists every ticket
pending at the hub, oldest first, with its age and where lox run stands on
it (`asked`, `unverifiable`, `not answerable here`…), and per lock how many
wait and how many lox run cannot verify. `↑`/`↓` (or `j`/`k`) select, `x`
withdraws the selected ticket, `X` every pending ticket of its lock, `U` its
lock's unverifiable ones; each asks `[y/N]` first, Esc closes. A withdrawn
ticket ends `withdrawn` at the hub, audited with you and the reason
(`withdrawn by USER in lox run`, shown by `lox audit show`), and its lock
gets the hub's signed denial with that reason: it ends the plan, its queue
frees, and its agent is told the human withdrew it. For scripts and
recovery, without lox run: `lox tickets [--lock NAME] [--error] [--json]`
lists them, `lox withdraw INSTANCE/ID…` or `lox withdraw --lock NAME
--all-pending` (or `--error`) withdraws them.

**A question calls you by ear.** When a question card appears (an approval, a
connection, a policy review, a secret), `lox run` plays a sound file through
the platform's player (`pw-play`, `paplay`, or `aplay` for WAV files on Linux;
`afplay` on macOS), and plays it again every 60 s while a question waits, until
none does. Auto-approved and rule-denied traffic plays nothing. The sounds
differ from lea's attention sound (`message-new-instant.oga`), so you know which
tool asks: `window-question.oga` for a question, `dialog-warning.oga` for a
production ticket (freedesktop theme, `/usr/share/sounds/freedesktop/stereo/`);
`Glass` and `Sosumi` on macOS. With no player, no such file, or a file set to
`0`, the terminal bell rings instead. The header shows 🔔 (on) or 🔕 (off).

| Setting | Effect |
| --- | --- |
| `LOX_SOUND=0` | start silent (no sound, no bell); `s` turns it on |
| `LOX_SOUND_QUESTION=FILE\|0` | the question sound (`0`: the terminal bell) |
| `LOX_SOUND_PRODUCTION=FILE\|0` | the production sound (`0`: the question sound) |
| `LOX_SOUND_REMIND=DURATION` | play it again every `30s`, `2m`… while a question waits (default `60s`; `0`: once) |
| `LOX_NOTIFY=1` | also a desktop notification (`notify-send`, `osascript`) with the lock and kind only, never the request |

**A key answers the card it was pressed for.** When the card on top changes
(answered, decided elsewhere, withdrawn, expired, or `Tab`), the keys already
typed are dropped, and `y`, `n` (or Enter in its prompt) answer the new card
only once it has been on screen for 400 ms: a key meant for the card that went
away never approves the one that took its place. If a card goes away while its
prompt (a password, the instance name) is being typed, what is typed next is
dropped until Enter or Esc, never read as keys on the next card.

**Quitting fails closed.** Once `lox run` ends, nothing decides: pending and
new tickets wait at the hub until the next `lox run` (or another facade), and
the locks close their connections once idle, so the next request asks again.

## lox audit

`lox audit` lists the hub's exchanges: each ticket and its answer, read from
the hub's data directory (`hub.db`, read only; `--data` for another one), in
the same columns and colours as the feed of `lox run` (one style, package
`internal/loxrun`). A line is the time the ticket was asked, the agent, the
lock and instance, the profile, the kind, the lock's masked request and the
decision: `auto` (a rule), `✔ human` (a human, on any facade), `✘ rule` or `✘
denied`, `◆ asked` (waiting), `– none` (ended undecided), then what became of
it (`✓` ran, `⌛` expired, `↩` withdrawn). On top, a summary: exchanges,
auto, human, denied, waiting, writes, connections opened. Day separators and
the `lox run` sessions (who started one, when, `── switched to MANUAL ──`)
come from `lox run`'s journal, `runs.jsonl` in the workspace's state
directory (unsigned: it only places the sessions).

Filters: `--agent`, `--lock` (an instance or a lock: `locksql`), `--profile`,
`--since` (`30m`, `2h`, `7d`, a date, RFC 3339), `--decision
denied|human|auto|pending`, `--writes`; `--follow` keeps printing new
exchanges and changed decisions; `--json` writes one object per exchange.
`lox audit show INSTANCE/ID` (or an id, or its start) draws one exchange in a
framed panel: its whole masked plan, the auto rule or the human and facade
that decided, timings (asked, decided `+Δ`, ended `+Δ`), and its signatures:
the ticket's under the pinned lock key, the decision's under the pinned hub
keys (`✓`, `✗`, or `?` without a key). `lox audit verify` checks the whole
chain.

On a terminal the listing goes through `$PAGER` (else `less -R`, `/` to
search) when it does not fit; piped, it is plain aligned text (`COLUMNS`, 120
by default); `NO_COLOR`, `--theme light|dark` and 80 columns hold as in `lox
run`. Nothing printed is ever a value in clear, a credential or a result row:
the hub keeps none (tickets are masked by their locks), and the sealed parts
of a ticket or a decision (a password for the lock, a clear copy for a
device) and the agent's free-text note are never read out. The hub records no
row or message counts: the outcome shown is the ticket's state.

Extension points: the image update (lockhub#118) and the lockfile seccomp
profile under Vault (lockhub#45) belong to the start; the engine takes
per-profile rules through `Session.Rules`.

## Files

| Path | Written by | Read by |
|---|---|---|
| `<workspace>/.lockfamily/lockfamily.yaml` | the human (`lox add`, `lox import`) | `lox` |
| `<workspace>/.lockfamily/up.json` | `lox run`, after a confirmed apply | lea; the locks' launchers (host agents) |
| `<workspace>/.<type>/` (`.locksql`, `.lockmq`, `.lockfile`, `.lockhttp`, `.locklog`) | the human (the lock's own profile tools) | `lox run`, which copies it (see below) |
| `$XDG_STATE_HOME/lockfamily/<project>/` | `lox run` | `lox` only (hub data, applied fingerprint, compose copy) |
| `$XDG_STATE_HOME/lockfamily/facades/` (`tty.key`, `deck.key`: private, `0600`; `locks.json`: the lock keys lox run pinned, the union of every workspace's `locks.d/<project>.json`; an instance two workspaces pin with different keys, or a key two instances share, is left out with a warning naming both workspaces: rename it in one, or delete the `locks.d` file of a workspace that was moved or deleted) | `lox run` (one directory per user, shared by workspaces) | `lox approve` (tty), lea's deck: they sign a reveal's ephemeral key and verify the lock's signed answer |
| `$XDG_STATE_HOME/lockfamily/<project>/facades.json` | `lox run` (public keys only) | the locks with `reveal: true`, mounted at `/run/lockfamily-facades/facades.json` (`--facade-keys-file`) |
| `$XDG_RUNTIME_DIR/lockhub/facade.sock` | the hub | `lox approve`, lea's deck |

`$XDG_RUNTIME_DIR/lockhub` is on a tmpfs wiped at logout and reboot. Every
`lox run` (and `lox init`, `lox add`, `lox remove`, which run it) makes it
before starting anything, yours, mode `0700`, and repairs it: one of yours
with another mode is closed, an empty one of another account (a Docker
engine that restarted the hub while it was missing made it as root, `0755`)
is removed and made again, and the hub starts again on it. Anything else (a
link, a file, another account's directory that holds something or that lox
cannot remove) is left as it is, and `lox run` prints the commands to run.
The hub mounts it with `create_host_path: false`: when it is missing, the
engine no longer makes it, the hub stays stopped until `lox run`.
`create_host_path` is a Compose Specification option (Docker Compose v2
honours it); a compose implementation that ignores it makes the missing
directory as before (as root under a rootful engine), the hub refuses it
and its error names the fix, and the next `lox run` repairs it.

When `XDG_RUNTIME_DIR` is unset, the runtime directory is
`$TMPDIR/lockhub-<uid>` (`/tmp` when `TMPDIR` is unset): `lox run` makes it (0700) and refuses one that is
not yours, is a link, or that group or others can write.

`lox run` refuses a `.lockfamily/` that is a link, not the user's, or
writable by group or others, and keeps its own copy of up.json in its state
directory. It writes up.json through a fresh file renamed into place (a
planted link is replaced, never followed).

lea creates `.lockfamily/` (owned by the host user, 0755) before it mounts
it read-only in its agents' containers: no agent can change
lockfamily.yaml or up.json. A `lockfamily.yaml` at the workspace's root
(the layout before this page) is still read, with a warning: agents can
write there. The first confirmed `lox run` copies exactly what was reviewed
into `.lockfamily/lockfamily.yaml` and says so; from then on only that file
counts (remove the root one). Once `.lockfamily/` exists, a root file is
never adopted (an agent could have planted it). The workspace keeps its
project and state.

## up.json (version 1)

```json
{
  "version": 1,
  "project": "lockfamily-1a2b3c4d",
  "workspace": "/home/me/projects",
  "hub_network": "lockfamily-1a2b3c4d_lockhub",
  "hub_url": "http://lockhub:8443",
  "hub_key": "<base64 Ed25519 public key>",
  "facade_keys": {"v": 1, "facades": [{"facade": "tty", "key": "<base64>"}, {"facade": "deck", "key": "<base64>"}]},
  "lockhttp_gate": 1,
  "devices": {"v": 1, "devices": [{"id": "<device id>", "...": "..."}]},
  "locks": {
    "crm": {"type": "locksql", "socket_volume": "lockfamily-1a2b3c4d_crm-run", "client_gid": "10000"},
    "web": {"type": "lockhttp", "profile": "strict", "socket_volume": "lockfamily-1a2b3c4d_web-run",
            "gate_home_volume": "lockfamily-1a2b3c4d_web-gate", "client_gid": "10020", "reveal": true,
            "devices": true, "require_device": ["prod-write"], "seal_clear": true}
  }
}
```

What a lock's gate pins (lea's lockhttp gate; `"lockhttp_gate": 1` says
these members are written, and lea runs its gate only then):

- `devices` (top level): the paired devices (lockkit `ticket.DeviceSet`,
  public keys only), the set lox run mounts read-only for the consoles at
  `/run/lockfamily-devices/devices.json`. Absent while no device is
  paired (`lox mobile pair`).
- per lock, `devices: true` when the lock pins them (lockfamily.yaml
  `locks.<name>.devices`); then `require_device` and `seal_clear`, from
  `hub.mobile`, exactly as lox run passes `--require-device` and
  `--seal-clear` to its consoles once a device is paired (with none
  paired, the gate pins none, as the consoles). Without `devices`, neither
  is written.
- per lock, `profile`: the console's profile (absent: `default`), which
  the gate takes as `--profile`.
- per lock, `reveal` (below).

lea reads up.json only if it is a regular file of the user's that no one
else can write, in a `.lockfamily/` of the same kind. Then, for each lock of
a type it has switched on:

- checks that the volume exists with the labels
  `com.docker.compose.project=<project>`, `dev.lockfamily.role=socket`,
  `dev.lockfamily.instance=<name>`, `dev.lockfamily.type=<type>`, and
  refuses any other volume (a lock's home holds its private key: no
  agent ever mounts it);
- mounts it and adds the clients group, instead of the fixed `<type>-run`
  volume of a console started by the tool's own launcher. One lock of a
  type: `/run/<type>`; several: each on `/run/<type>/<instance>` (Codex
  gets one server per instance; a Claude agent passes `--instance NAME`
  or sets `<TOOL>_INSTANCE`).

For a lockhttp instance, lea's gate (beside lea's proxy) mounts the socket
volume on `/run/lockhttp` and the volume of role `gate-home` as its
`--home`, writes `hub_key` to its own read-only input, joins **only the
proxy** to `hub_network`, and runs `lockhttp gate --hub <hub_url>
--hub-plain-http --hub-key-file … --instance <name> --home … --hub-net <the
network's subnet>`. When the lock has `"reveal": true` (lockfamily.yaml
`reveal: true`; lockhttp v0.5.0 or later), the gate also writes
`facade_keys` (the host facades' public keys, the set every console with
`reveal: true` pins at `/run/lockfamily-facades/facades.json`) to a
read-only input of its own and passes `--facade-keys-file …` (or
`LOCKHTTP_FACADE_KEYS_FILE`): a reveal (Ctrl-O) is sealed only to an
ephemeral key one of those facade keys signed. Without it the gate pins no
facade and refuses reveals; renewals work either way. When the lock has
`"devices": true` (lockhttp v0.4.0 or later), the gate writes the top-level
`devices` to a read-only input of its own and passes `--devices-file …`,
with `--require-device` and `--seal-clear` as the lock says: a decision
of those risk classes must be device-signed, and clear screens go to the
phones sealed. lea stops (saying why, and to run `lox run` once a device
is paired) when `require_device` is set and no device is paired. The gate refuses the hub's addresses as targets,
so an agent cannot reach the hub through it (invariant I2). No agent
container joins `hub_network`.

## Host agents: the locks' launchers

An agent on the host runs a lock's launcher, as `.mcp.json` says: `locksql
mcp` (and the other agent commands: `status`, `plan`, `run`...; lockmq's and
lockfile's alike; lockhttp has no agent command: its gate is lea's). The
launcher runs the command in the lock's image, with the socket volume of the
workspace's lock of its type mounted **read-only** on `/run/<type>`
(connecting to a socket needs no write), never a fixed volume: the consoles
run hub-attached only, started by `lox run`. It takes the volume only after
lea's checks, in POSIX sh:

- up.json is found in the nearest directory up from the working directory
  whose `.lockfamily` holds one: that directory is the workspace. The
  `.lockfamily` directory and up.json are no link, are the user's, and
  neither group nor others may write them; up.json is at most 1 MiB, and is
  the same file after the read as before.
- up.json is read as `lox run` writes it: Go's `json.MarshalIndent` with a
  two-space indent, the members the launcher reads (`version`, `project`,
  `workspace`, and per lock `type`, `socket_volume`, `client_gid`) at their
  depth, their values with nothing escaped. Anything else is not lox run's
  state. lox run keeps that layout (`TestUpWritesLeaContract`).
- version 1, `project` `lockfamily-<8 hex of sha256(workspace)>` and
  `workspace` this physical directory.
- the lock: the workspace's only lock of the launcher's type, or the one
  `--instance NAME` names (the launcher's option, taken out of the command
  line; in `.mcp.json`, `"args": ["mcp", "--instance", "NAME"]`). With
  several and no `--instance`, the error names them.
- `socket_volume` is `<project>_<instance>-run`, `client_gid` the image's
  clients group.
- Docker confirms the volume: `docker volume inspect` prints its labels
  `com.docker.compose.project`, `com.docker.compose.volume`
  (`<instance>-run`), `dev.lockfamily.role` (`socket`),
  `dev.lockfamily.instance`, `dev.lockfamily.type`,
  `dev.lockfamily.workspace`, each as JSON on a line of its own, compared
  whole with what they must be.
- every container that mounts the volume (`docker ps -a --filter
  volume=…`, then `docker inspect` of each, labels as JSON) is lox run's own
  (compose ran it with `com.docker.compose.project.working_dir` lox run's
  state directory `$XDG_STATE_HOME/lockfamily/<project>`, and
  `config_files` `-` or that directory's `compose.yaml`) or mounts the
  volume read-only. A container that mounts it read-write, of another
  compose run or none, could listen on the socket's path: the launcher then
  trusts none of that socket.

Without up.json, or with a lock or volume it cannot trust, the launcher
says why and what to do (`lox run`), exits 2 (as a client that finds no
console) and runs nothing: it never falls back to the fixed `<type>-run`
volume of the consoles the launchers used to start. up.json only names the
lock: what is mounted is what Docker's labels prove. `.mcp.json` stays
`<lock> mcp`.

The socket's name is the lock's: `<project hash>-<profile>.sock`, where
the project hash comes from the lock's profile directory up from the
working directory (`.locksql`, `.lockmq`; lockfile has none: `user`) and the
profile is the one the console serves (lox run passes `--profile` only for
a lock that names one, and `default` for lockfile). Run the agent from the
workspace, whose profile directory lox run's console serves.

lockhub's end-to-end test (`ci/e2e/phase2.sh`, run by the e2e workflow's
phase 2 on every pull request) drives both launchers as `.mcp.json` starts
them, over MCP on stdio, against the images `lox add` pins: `locksql mcp`
plans and runs a query and, once the ticket is approved at `lox approve`,
gets its rows; `lockmq mcp` reads a stream (RabbitMQ) and, once approved,
gets its message. `ci/e2e/locklog-agent.sh` does the same for locklog:
`locklog init claude` writes `.mcp.json`, and the `locklog mcp` it names
counts the records of a log file (masked, no ticket), then asks to unmask
one e-mail address of a record: pending on the hub, approved at `lox
approve`, then run with the ticket. It also checks the launcher's refusals of a tampered
up.json and of a squatted socket volume (with locksql's launcher; lockmq's
makes the same checks).

### Threat model

The checks are against mistakes (a stale or copied up.json, another
workspace's lock, a volume or compose file of the same name, a container
squatting the volume) and against files others than the user can write.
They are **not** a boundary against the host agent itself: it usually runs
as the user, often with Docker access, and can then rewrite up.json, create
volumes and containers with any labels, `docker exec` into lox run's
containers, or read a lock's home volume. What it still cannot do: decide a
ticket (the hub signs decisions with its key, which the consoles pin, and
only a human at a facade approves), or see a lock's credentials through
the socket (the console holds them). An impostor socket could at most feed
another agent false answers or collect its requests. To contain the agent,
run it in lea: its containers have no Docker access and see `.lockfamily`
read-only.

Binding the volume to lox run's state (a nonce label that lox run records in
its state directory and the launchers compare) would also stop a look-alike
volume made with `docker volume create` and the same labels; it adds
nothing against an agent with Docker access, which can read the state
directory too.

## The review and the output

`lox run` keeps cosign's and docker's own output out of the way: it is shown
when a step fails, or with `-v`.

The review a human confirms is short by default. For each lock (only the one
`lox add` or `lox remove` is about, when they run `lox run`) it shows one
block:

```
lock shop-db (locksql)
  image        ghcr.io/davidgodefroid/locksql@sha256:… (signature verified)
  target       …
  environment  none
  credentials  ask, typed at the console's start
  production   no
  profile      sha256:…  (lox run --review prints it in full)
```

`environment` is `VAULT_ADDR=…` (and the namespace) for a lock with Vault, and
`credentials` then reads `vault, <path>`. A profile that changed since the last
`lox run` says so. Every summary line that no block renders is listed under
`Other changes since the last lox run:` (`Also applied:` on the first run), so
the fingerprint that `lox run` compares still covers everything the review
shows or lists. The question is `Apply? [y/N]`.

`lox run --review` shows everything: on the first run the whole configuration,
then, for a later change, the lines that changed and every profile line by
line. It asks even for a hub with no lock.

The first `lox run` of a workspace with no lock declared and none applied
before asks nothing (the hub alone cannot reach a credential) and says so.

## Profiles: a reviewed copy

A lock's profile directory is in the workspace, which agents may write. lox
up never mounts it. It reads it once, following no link, taking only the
user's own regular files and directories that no one else can write (256 KiB and 256 entries
at most, read through one handle on the directory: no swapped link leads out), shows its fingerprint in the review (`profile <type> <dir>
sha256:…`; a change is a change to confirm), and after the yes copies
exactly that archive, on the setup service's stdin (never an argument), into the volume `profile-<type>` (written by root,
read-only in the lock). A new copy recreates the lock's console.

The review lists every file of the copy (name, size, sha256) and each line
of its TOML files (lockkit's configuration refuses secrets there; control
characters are shown escaped), so a change of target or of the production
flag is a line you read, not only a new hash. The copy belongs to the
console's account and keeps owner-only modes (a 0600 key stays 0600). A
directory or file your umask made group-writable is refused: `chmod -R
go-w <workspace>/.<type>`.

One profile directory per workspace and type: the console runs in the
workspace, and the socket name of locksql and lockmq derives from the
project path, so an agent in a sub-project with its own `.locksql` would
look for another socket.

## Consoles under compose

Every lock's console asks a human at its terminal: its policy on the first
start and after a loosening, the typed profile name of a production
profile, an SSH host key, the SSH passphrase and the database password its
profile does not take from Vault, a Vault token. lox run runs each console
with a terminal (`tty: true`, `stdin_open: true`) as its image's console
account, and asks these questions itself: it attaches to each console
through a pseudo-terminal of its own (`docker attach --sig-proxy=false`, so
quitting lox run never signals a console), reads the question the console
records next to its socket (lockkit v0.12.1 or later: `<socket>.question`,
the prompt only, mode 0600, the console account's) and the lines the
console printed above it, and shows them as a **question card**: the lock,
the PRODUCTION banner when the console shows one or asks the profile name,
the bell. Several waiting locks queue, one card at a time (`1 of N
waiting`).

- A yes/no question (`Apply these changes? [y/N]`, a host key's `[yes/N]`)
  is answered with **y** or **n**. The lines above it are on the card (the
  policy review's changes, the host key's fingerprint), up to 12, all of
  them with **d**.
- A value is typed into the card: the production profile name and a
  fingerprint's last characters in clear, anything else (a password, a
  passphrase, a token, a prompt lox run does not know) as dots only.
  Enter types it at the console's terminal; Esc closes the line, **y**
  opens it again, **n** answers an empty line.
- A value typed this session is kept in lox run's memory, for that lock and
  that prompt: when the console asks the same again (it restarted at the
  end of an idle session, Docker starting it again), **Enter alone** gives
  it. A policy review is never answered for you. The same question asked
  again within 30 seconds of the session's answer means the console refused
  it (a changed password): the value is dropped and typed again. **x** on
  the card forgets the lock's values; quitting lox run wipes them all.

The header's `locks` line shows each console's state, the waiting ones
first: `waiting for you: <question>`, `serving`, `stopped: <its last line>`
(the container does not run; Docker restarts it), `starting`, or `not
reached here (…): lox attach NAME` when lox run cannot reach its terminal
(no pseudo-terminal on this system, no docker).

An answer goes from lox run's memory to the console's terminal through the
Docker CLI only: never through the hub (which sees masked tickets only),
never to a log (the consoles have no Docker log, `logging: none`, as with
their own launchers; lox run's pty echoes nothing and the console echoes no
secret; the card shows dots). An agent cannot answer: it has no Docker,
the question file is the console account's, and lox run types only what
the human typed in its own terminal.

`lox attach NAME` stays as a fallback for debugging: it attaches your
terminal to the console and, at a terminal, detaches by itself once a
console that did not serve yet listens on its socket: `lock NAME serves:
detached, its console keeps running`. Attached to a console that already
serves (to use its commands), it stays. Ctrl-P Ctrl-Q detaches at any time
and exits 0 (`detached from NAME`); Ctrl-C at the console stops it. The
attach does not proxy signals (`--sig-proxy=false`): closing the terminal
only detaches. A question answered there takes lox run's card away. The
consoles have no log, so attaching replays nothing: lox attach first reads
the question file (only that console's own, at most 200 characters, escaped
for the terminal) and prints one of:

- `lock NAME waits for: <question>`, with `(typed, not shown)` for a
  passphrase, a password, a token or a secret: after the restart of a
  production lock behind an SSH bastion, `Passphrase for
  /home/locksql/.ssh/bastion_key: (typed, not shown)`;
- `lock NAME is serving: nothing to answer`: the console listens on its
  socket, whatever question file is left there;
- `lock NAME is starting` or `lock NAME is stopped (restarting, exit status
  N)`: no question recorded and no socket, from the container's state.

It never lists what a console may ask. Each following question shows on
the attached terminal as the console asks it. A console that ends under the
attach (a wrong answer) makes lox attach fail; it then waits a few seconds
for the restarted console and prints its next question (`the console of
lock NAME ended; now lock NAME waits for: ...`). A console that
printed its policy review before lox run attached to it (the first start,
during lox run's own start) shows the question without the lines above it;
lox run's own review showed the profile it reviews. Locks are pending
(agents get no answer) until answered. Memory and process limits are the
ones each lock's own launcher sets.

The copy is read-only in the lock. A locksql console keeps its PII rule sets
in its own home volume instead (`LOCKSQL_PII_DIR`, locksql v0.11.0 or later):
its first start writes the first rule set there after your review at its
terminal, as do `pii add` and the later PII proposals. The rule sets of
`.locksql/pii/` in the workspace, if any, are copied in once; from then on
the console's copy is in force (`/home/locksql/pii-rules/pii/<set>.toml` in
the volume `<project>_<instance>-home`): at each start it takes the
profile's new mask rules (a tightening you made in the workspace and lox run
reviewed), never what would loosen it or change its mode (allow rules,
removed masks, mode changes), which you change at the console. A locksql image older than v0.11.0 ignores the variable and cannot
write its first rule set: `lox add locksql <instance>` again pins a newer
release.

Several instances of one type share the type's profile directory; each
serves the profile its `profile:` names in lockfamily.yaml (a profile of
that directory's configuration, such as `[profiles.crm-prod]` and
`[profiles.crm-uat]` of one `.locksql/config.toml`). A profile directory per
instance is not supported (lockhub#44).

lea's agents run as the host user's uid, which has no account in a lock's
image: the console refuses them unless the lock names that uid. In
lockfamily.yaml, per locksql, lockmq or lockfile lock:

```yaml
locks:
  events:
    type: lockmq
    image: ghcr.io/davidgodefroid/lockmq@sha256:…
    allowed_uids: [1000]   # id -u of the account that runs lea
```

lox run passes it as the console's `--allowed-uids 1000` (locksql v0.11.2,
lockmq v0.4.1, lockfile v0.5.1 or later; an older image refuses to start), and the review
shows it (`lock events serves uids 1000 besides its clients group`): a
change of it is a change to confirm. Only uids, each once: never root, 65534
(nobody), nor the console's own uid. `.lockfamily/` is read-only in lea's containers,
and every `allowed_uids` (from a legacy root file or a sub-project `lox
import` reads, which agents may write, too) is in the review you confirm. A lockhttp lock takes none (lox run refuses
the key there): it is reached by lea's gate, an account of its image. `lox import` keeps the uids every
declaration of an instance lists.

`lox add` pins only releases that run under lox run (hub mode on lockkit
v0.3.1): lockhub v0.1.1, locksql v0.11.0, lockmq v0.3.0, lockfile v0.4.0,
lockhttp v0.3.0 or later.

A TOML file of a profile must be UTF-8 of at most 64 KiB: every line of it is
in the review.

### Egress: each lock reaches its reviewed endpoints only

Every lock but lockhttp (whose egress is its own policy's job) sits on an
internal network, `locknet-<name>`: no route out, so no internet, no cloud
metadata (`169.254.169.254`), no other host. `lox run` reads the endpoints
from the **reviewed copy** of the lock's profile (never from the workspace,
which agents can write) and gives the lock a small gateway that forwards only
those:

| lock | endpoints |
|---|---|
| locksql | `host`:`port` (default 5432 for postgres, 3306 for mysql and mariadb); sqlite none; with an `ssh` table, the bastion only |
| lockmq | `url`, `amqp_url`, `stream_url` (default ports of their schemes); with `ssh`, the bastion only |
| lockfile | s3: the `endpoint`, else `<bucket>.s3.<region>.amazonaws.com:443`; sftp: `host`:`port` (22); local none |
| locklog | the `url` of each `loki`, `elastic` and `opensearch` source (80 for http, 443 for https); file, journald and docker none. A lock whose mount plan reads no remote source gets none at all (see below) |
| any, with `vault: true` | the `vault.address` |

The lock's profile names the profile it serves (`locks.<name>.profile`); when
it names none, the endpoints of every profile of `config.toml` (the human picks
one at the console). The gateway, `gw-<name>`, answers on the lock's network
under the endpoints' own names (network aliases), so host names and TLS server
names stay the profile's, `host.docker.internal` included; its back half,
`gwout-<name>`, is the only container with a route out (`out-<name>`) and dials
only those endpoints. Both run the hub's image (`lockhub egress-gateway`), with
the hub's hardening. Two endpoints on one port are told apart by their TLS
server name when both start with TLS (https, amqps, rabbitmq-stream+tls);
otherwise `lox run` stops with an error naming both: move one to another port.

The review shows the allowlist (the `egress` row of each lock; `lox run
--review` lists the lines `lock <name> egress host:port (what)`), so a
profile change that changes it is reviewed again. Fail closed: what the
allowlist cannot name exactly is reached by nothing, and the review says why
in an `unreachable` row of its own (`egress unreachable: …` in the lines): a
`proxy_command`, a value it cannot read. An IP address (a `host`, an
`ssh.host`, a URL's host or the Vault address; loopback aside) is refused
outright: the gateway answers by host name only, so the lock could never reach
it. `lox add` refuses it as an answer, and `lox run` stops before the review,
naming the key (`profiles.<p>.ssh.host in config.toml`) and the fix: name the
host (a DNS name that resolves to it, or `host.docker.internal` for this
machine). The files a locksql profile names (`tls_ca`, `tls_cert`, `tls_key`,
`ssh.key`) are checked in the lock's home volume before the review, a `file`
row per missing or open file with the command that fixes it
([lox-add.md](lox-add.md#the-files-a-locksql-profile-names)). `lox doctor` checks each lock's effective egress: every
network of its container is internal, and its gateway runs and forwards exactly
what the last `lox run` reviewed. A hub image older than the gateway (pinned
with `--pin`) cannot run it: the lock then reaches nothing until `lox run`
upgrades the hub. The bridge a lock had before (`egress-<name>`, with a route
out) is removed by the first `lox run` that moves the lock off it.

Vault is per lock. A lock with `vault: true` in lockfamily.yaml runs the
`-vault` variant of its image (`lox add` pins it) and gets `VAULT_ADDR` (and
`VAULT_NAMESPACE`, and the reviewed CA copy mounted read-only when the block
names a `ca_file`) from the workspace's one `vault:` block; its profile names
its own Vault path. The review shows the environment and the path of each such
lock. The token is typed at the console's start (`lox attach`), never
written anywhere. See [lox-add.md](lox-add.md#vault-per-lock) and `lox vault
set`.

A lockfile lock runs under the seccomp profile lockfile ships
(`seccomp.json`, beside its launcher in each release), as lockfile's own
launcher runs its console, not under Docker's default (which varies with the
engine's version) and never `unconfined`. The image does not carry the
profile: lox carries a byte-for-byte copy, writes it after the yes to the
state directory (`lockfile-seccomp.json`), and the lock's service sets
`security_opt: ["no-new-privileges:true", "seccomp=<that file>"]` with its
digest as a label, so a new profile recreates the console. The review shows
`lock NAME seccomp lockfile's shipped profile sha256:…`; `docker inspect`
shows the profile under `HostConfig.SecurityOpt`. The other locks and the hub
keep Docker's default.

## locklog: the mount plan and the containers map

A locklog console reads host logs, so lox run mounts the directories its
profile names, as locklog's own launcher does. Before the review, lox run runs
`locklog mounts [--profile P]` in the lock's image (setup service
`mounts-<instance>`: the image's agent account, no network, the reviewed copy
unpacked in a tmpfs at the workspace's path) and checks every line it prints
on the host:

- a `file` line binds its directory: one under `/var/log` or
  `/run/log/journal`, a real path (no link, not `/`), with no character a
  mount cannot carry;
- a `journald` line binds the host's `/var/log/journal` and
  `/run/log/journal`;
- a `docker` line binds the Docker containers root (`docker info`'s
  `DockerRootDir` + `/containers`) with group 0. That group applies to the
  whole console, so a docker source is refused beside file or journald
  sources: put it in a lock of its own;
- a `remote` line binds nothing;
- local sources are refused on macOS (Docker Desktop), under rootless
  Docker, and on an engine older than 19.03 (it ignores a bind's
  non-recursive option). Fail closed: an engine whose `docker info` or
  `docker version` does not answer, or whose version cannot be read, is
  refused too. That includes Podman's Docker-compatible API: it reports
  Podman's own version (such as `4.9.3`), whose major is below 19, so
  local sources are refused under Podman; a remote-only profile is not
  (lox run asks the engine nothing for it).

Every directory is bound read-only and non-recursive (Compose
`bind: {recursive: disabled}`: no submount of it appears) at its own path.
The console joins only the groups its files grant: `adm` and `systemd-journal`,
and gid 0 for the containers root; lox run warns about a file the console will
not reach. It also gets `LOCKLOG_EXPECT_ROOTS` (the device and inode of each
root it could stat), `LOCKLOG_EXPECT_DIR` (the profile copy's, printed by
its copy service), `LOCKLOG_DOCKER_ROOT` and `LOCKLOG_PII_DIR` (its home
volume). The review lists the plan's header and lines, each bind, the groups
and the map directory, so a new log directory is a change to confirm.

A docker source's containers map (`map.v<N>`: the names and ids of the
containers its approved globs name, json-file only, locklog consoles
excluded, 0644 in a 0755 directory) lives in the state directory,
`$XDG_STATE_HOME/lockfamily/<project>/locklog/<instance>/map`. It is bound
read-only at `/run/locklog-map`, the last two versions kept. lox run writes
it before the consoles start and again once they exist (their ids are
excluded); `lox refresh <instance>`
rewrites it from the globs lox run applied (the console re-reads it). No loop
follows `docker events` under lox run, and `lox doctor` says when the map is
stale. A locklog lock with no applied plan (a workspace applied before lox
run derived mount plans) is a warning in `lox doctor`: run `lox run` to
review and apply it.

### locklog: networks and routing

A locklog lock whose plan has local sources only (or no plan yet) joins the
hub's network alone: it is internal, so the console has no route out. It gets
no `locknet-<instance>`, no gateway and no `LOCKLOG_NETWORK`, whatever its
profile or `vault:` names (the review's egress row says so). A lock whose plan
reads a remote source (Loki, Elasticsearch, OpenSearch) is on its own
network, `locknet-<instance>`, behind its gateway, which forwards only the
sources' urls (and Vault's, with `vault: true`); no agent and no other lock
joins it. Its console gets `LOCKLOG_NETWORK=<project>_locknet-<instance>`,
the engine's name of that network. The review says which:
`lock NAME network lockhub only (local sources: no route out)`, or
`lock NAME network lockhub and <project>_locknet-NAME, its own, which no
agent joins`.

A locklog ticket is a read of masked logs, and an unmask or a lookup is
`read-pii`: a locklog lock is answered on the local facades only. A
`hub.routing` entry of it naming `slack` or `telegram` is refused, and with
no entry it is routed to `tty`, `deck` and `mobile` (narrowed away from mobile
when it pins no device, as every lock). The review shows the facades that
can answer it in effect, those of that routing the hub runs (`hub.facades`):
`lock NAME routed only to tty,deck (locklog's default: no chat facade)`, or
`(hub.routing)` for an entry. `lox doctor` compares the hub's `routing.json`
with that routing, as lox run writes it.

### locklog: auto rules

A locklog profile says what `lox run`'s auto mode does with each action that
becomes a ticket (locklog#126): `read` (an approved scan, risk `read`),
`unmask` and `lookup` (with `lookup = "approved"`; both `read-pii`), each
`auto`, `ask` or `deny` (locklog's default: `ask` for all three). Before the
review, lox run runs `locklog profile rules --json [--profile P]` in the
lock's image on the reviewed copy (setup service `rules-<instance>`, as
`mounts-<instance>`: the image's agent, no network, no volume) and shows the
served profile's rules:

```
lock logs auto rules of profile files: read ask · unmask ask · lookup ask (locklog profile rules, on the reviewed copy)
```

A change of rules is a change to confirm. The rules are kept with the applied
plan (`plan.json`), where `lox run --no-start` reads them. The engine applies
`read` to a locklog scan and the stricter of `unmask` and `lookup` to its
`read-pii` tickets (a ticket does not tell them apart; rule `read-pii`). Rules
lox run cannot read (an error, an answer it does not parse, a profile not
listed) leave every ticket of the lock asked, with a warning before the
review. The engine keys this on the ticket's lock: a locklog ticket whose
rules are unknown to it, because lockfamily.yaml no longer loads after the
start, its instance is not in it, or its profile is not the one lox run
applied, has its `read` and `read-pii` asked, never the auto mode's default
(fail closed). The console enforces its own side whatever lox run does: an action
its rules deny is refused before any ticket, and the ticket of an `ask` is
signed never-auto, which lox run always asks and the lock refuses an auto
approval of. A `read-pii` decision is taken on `tty`, `deck` or `mobile`
only: the routing above, and the console refuses one from any other
facade.

## Upgrading the images

At start, `lox run` compares the images lockfamily.yaml pins with the
releases the installed `lox` ships with: lockhub at lox's own version (they
are released together), and one release per lock type
(`family.ShippedLocks`, bumped when lox is released). The release an image
is, is read from its signature: cosign's verification of every pinned image
names the release workflow run, so the tag, that signed it. After `brew
upgrade lox`, an image older than the shipped release is upgraded, with no
command to run:

1. the shipped release's image is resolved by digest in ghcr.io (the
   `-vault` variant for a lock with `vault: true`), and cosign verifies it
   was signed by that release's own workflow run for that very tag, as
   `lox add` does;
2. the configuration reviewed and applied is lockfamily.yaml with the new
   digests, and compose recreates the containers whose image changed;
3. lockfamily.yaml takes the new digests once applied.

It prints one line per upgraded image:

```
hub image upgraded: lockhub v0.10.0 → v0.10.1 (signature verified)
lock shop-db: image upgraded: locksql v0.16.2 → v0.17.1 (vault image, signature verified)
```

Fail closed: an image that cannot be resolved or whose signature does not
verify is not used; the old image (verified above) is kept and a line says
why (`lock shop-db: image: not upgraded to locksql v0.17.1, keeping v0.16.2:
…`). An image newer than the shipped release (`lox add --version`) is kept,
and so is one whose signature names no release (it cannot be compared).

The image lines are part of what the review fingerprints, but a new image
changes nothing a human reviewed: when the upgraded images are the only
change since the last `lox run`, it is applied without a question
(`only the upgraded images changed since the last lox run`). Anything else
that changed (a profile, a policy, a line of lockfamily.yaml) is reviewed as
always, the image lines with it, and nothing is applied, nor written back,
without the yes. A lock's console still reviews its own policy at its start
when the new version loosens it (`lox attach`).

`--no-upgrade` keeps the pinned images; `--pin` leaves the hub as pinned
for that run. `lox up` (deprecated) never upgrades. A development build of
lox (`lox version` says `dev`) upgrades only the locks.

## Restoring a hub version, rotating keys

`lox run --pin sha256:<digest>` (or the whole
`ghcr.io/davidgodefroid/lockhub@sha256:…` reference) runs the hub on that
image: a previous version restored by digest. The review shows the image
line that changes; cosign checks the image is a lockhub release as for any
other; once applied, lockfamily.yaml takes the digest. The next lox run
upgrades it again if it is older than this lox's release (see above): run
`lox run --no-upgrade` to keep it. `hub-images.log` in the state directory lists the hub images
applied in the workspace, oldest first. An older hub on data a newer one
wrote may refuse to start: the hub's data has no downgrade path. A hub
image from before key rotation (no `lockhub rotate-key`) refuses an audit
log whose key was rotated.

`lox run --rotate hub`, `--rotate <instance>` or `--rotate all`
(repeatable, or comma-separated) replaces keys. The new keys are made
before the review, which shows each key line that changes; declined (or
`--dry-run`), they are dropped.

- A lock's new key is made by its own `hub-key`, in its own volume, under
  `.lockfamily-rotate` (its home, or the gate's `--home` for lockhttp);
  after the yes, the setup service `rotkey-<instance>` (the key's account,
  no network) moves it over the old one, whose private key is gone. The
  hub's lock list takes the new key and the lock's console restarts.
- The hub's new key is made by `lockhub keygen` in the hub's data
  directory (`rotate/`); the hub image must have `lockhub rotate-key`. After the yes, lox run stops the hub and runs
  `lockhub rotate-key`: the audit outbox is flushed under the old key, a
  `key_rotated` record signed by the old and the new key ends the old
  key's part of the audit log, the old key is listed in
  `retired-keys.pub` (data directory) and the new one replaces `hub.key`.
  Every lock restarts to pin the new key (the `hubkey` volume and
  up.json carry it). lea's gate reads the hub key at its start: restart
  it.
- A restarted console asks again for what it does not take from Vault
  (`lox attach`).

Before the review, lox run checks the hub image has `rotate-key` (and
refuses a `--pin` to an image without it once the hub key was rotated: it
would refuse the log). `rotate-key` takes the data directory's lock
(`hub.lock`, which a running hub holds), so it never runs beside a hub.
If the hub's rotation stops halfway, the hub stays stopped (no lock
executes anything) and lox run refuses to start it until `lox run
--rotate hub` is run again, which finishes the same rotation with the same
new key, after asking the hub which key it holds (`lockhub pubkey`).

`hub-keys.pub` in the state directory lists every hub key, oldest first,
the current one last. `lox audit verify --hub-key-file` takes it (a file
with one key is the same as before any rotation): the log must be signed
by each key in turn, handed over by a `key_rotated` record signed by both,
and end on the last key, so that a log cut back to before a rotation is
refused; each decision must be signed by the key of the record that
vouches for it.

## Why lockhttp is different

(lea's side of this is lea#209: lea runs its gate in hub mode for the one
lockhttp lock of a workspace's up.json from `"lockhttp_gate": 1` on. Since
lea v0.4.0 (lea#232) there is no standalone gate: without a trusted up.json
naming one lockhttp lock, with an older lox run, or with anything in up.json
it cannot check, lea stops, says why, and says to run `lox run`.)

lockhttp's hub mode is in the gate (`lockhttp gate --hub`, lockhttp#11),
not in its console, and the gate must sit in the network namespace of
lea's proxy to see the agents' requests. lox run therefore does not run a
gate: it runs the lockhttp console (it serves the policy, with no hub
network), creates the gate's own volume, makes the gate's instance key in
it as the gate's account (`lockhttp hub-key --home`), and registers that
key with the hub. lea runs the gate.
