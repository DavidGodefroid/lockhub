# lox up and lea

`lox up` runs the hub and a workspace's locks with Docker Compose. Agents
reach the locks' sockets, never the hub: lea's agents in their containers,
and a host agent (Claude Code, Codex... run in a terminal) through the
locks' own launchers (`locksql mcp`, `lockmq mcp`, `lockfile mcp`, as
`<lock> init` writes them in `.mcp.json`). This page is the contract
between `lox up` and both.

## Files

| Path | Written by | Read by |
|---|---|---|
| `<workspace>/.lockfamily/lockfamily.yaml` | the human (`lox add`, `lox import`) | `lox` |
| `<workspace>/.lockfamily/up.json` | `lox up`, after a confirmed apply | lea; the locks' launchers (host agents) |
| `<workspace>/.<type>/` (`.locksql`, `.lockmq`, `.lockfile`, `.lockhttp`) | the human (the lock's own profile tools) | `lox up`, which copies it (see below) |
| `$XDG_STATE_HOME/lockfamily/<project>/` | `lox up` | `lox` only (hub data, applied fingerprint, compose copy) |
| `$XDG_STATE_HOME/lockfamily/facades/` (`tty.key`, `deck.key`: private, `0600`; `locks.json`: the lock keys lox up pinned, the union of every workspace's `locks.d/<project>.json`; an instance two workspaces pin with different keys, or a key two instances share, is left out with a warning naming both workspaces: rename it in one, or delete the `locks.d` file of a workspace that was moved or deleted) | `lox up` (one directory per user, shared by workspaces) | `lox approve` (tty), lea's deck: they sign a reveal's ephemeral key and verify the lock's signed answer |
| `$XDG_STATE_HOME/lockfamily/<project>/facades.json` | `lox up` (public keys only) | the locks with `reveal: true`, mounted at `/run/lockfamily-facades/facades.json` (`--facade-keys-file`) |
| `$XDG_RUNTIME_DIR/lockhub/facade.sock` | the hub | `lox approve`, lea's deck |

`lox up` refuses a `.lockfamily/` that is a link, not the user's, or
writable by group or others, and keeps its own copy of up.json in its state
directory. It writes up.json through a fresh file renamed into place (a
planted link is replaced, never followed).

lea creates `.lockfamily/` (owned by the host user, 0755) before it mounts
it read-only in its agents' containers: no agent can change
lockfamily.yaml or up.json. A `lockfamily.yaml` at the workspace's root
(the layout before this page) is still read, with a warning: agents can
write there. The first confirmed `lox up` copies exactly what was reviewed
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
  public keys only), the set lox up mounts read-only for the consoles at
  `/run/lockfamily-devices/devices.json`. Absent while no device is
  paired (`lox mobile pair`).
- per lock, `devices: true` when the lock pins them (lockfamily.yaml
  `locks.<name>.devices`); then `require_device` and `seal_clear`, from
  `hub.mobile`, exactly as lox up passes `--require-device` and
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
phones sealed. lea stops (saying why, and to run `lox up` once a device
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
run hub-attached only, started by `lox up`. It takes the volume only after
lea's checks, in POSIX sh:

- up.json is found in the nearest directory up from the working directory
  whose `.lockfamily` holds one: that directory is the workspace. The
  `.lockfamily` directory and up.json are no link, are the user's, and
  neither group nor others may write them; up.json is at most 1 MiB, and is
  the same file after the read as before.
- up.json is read as `lox up` writes it: Go's `json.MarshalIndent` with a
  two-space indent, the members the launcher reads (`version`, `project`,
  `workspace`, and per lock `type`, `socket_volume`, `client_gid`) at their
  depth, their values with nothing escaped. Anything else is not lox up's
  state. lox up keeps that layout (`TestUpWritesLeaContract`).
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
  volume=…`, then `docker inspect` of each, labels as JSON) is lox up's own
  (compose ran it with `com.docker.compose.project.working_dir` lox up's
  state directory `$XDG_STATE_HOME/lockfamily/<project>`, and
  `config_files` `-` or that directory's `compose.yaml`) or mounts the
  volume read-only. A container that mounts it read-write, of another
  compose run or none, could listen on the socket's path: the launcher then
  trusts none of that socket.

Without up.json, or with a lock or volume it cannot trust, the launcher
says why and what to do (`lox up`), exits 2 (as a client that finds no
console) and runs nothing: it never falls back to the fixed `<type>-run`
volume of the consoles the launchers used to start. up.json only names the
lock: what is mounted is what Docker's labels prove. `.mcp.json` stays
`<lock> mcp`.

The socket's name is the lock's: `<project hash>-<profile>.sock`, where
the project hash comes from the lock's profile directory up from the
working directory (`.locksql`, `.lockmq`; lockfile has none: `user`) and the
profile is the one the console serves (lox up passes `--profile` only for
a lock that names one, and `default` for lockfile). Run the agent from the
workspace, whose profile directory lox up's console serves.

lockhub's end-to-end test (`ci/e2e/phase2.sh`, run by the e2e workflow's
phase 2 on every pull request) drives both launchers as `.mcp.json` starts
them, over MCP on stdio, against the images `lox add` pins: `locksql mcp`
plans and runs a query and, once the ticket is approved at `lox approve`,
gets its rows; `lockmq mcp` reads a stream (RabbitMQ) and, once approved,
gets its message. It also checks the launcher's refusals of a tampered
up.json and of a squatted socket volume (with locksql's launcher; lockmq's
makes the same checks).

### Threat model

The checks are against mistakes (a stale or copied up.json, another
workspace's lock, a volume or compose file of the same name, a container
squatting the volume) and against files others than the user can write.
They are **not** a boundary against the host agent itself: it usually runs
as the user, often with Docker access, and can then rewrite up.json, create
volumes and containers with any labels, `docker exec` into lox up's
containers, or read a lock's home volume. What it still cannot do: decide a
ticket (the hub signs decisions with its key, which the consoles pin, and
only a human at a facade approves), or see a lock's credentials through
the socket (the console holds them). An impostor socket could at most feed
another agent false answers or collect its requests. To contain the agent,
run it in lea: its containers have no Docker access and see `.lockfamily`
read-only.

Binding the volume to lox up's state (a nonce label that lox up records in
its state directory and the launchers compare) would also stop a look-alike
volume made with `docker volume create` and the same labels; it adds
nothing against an agent with Docker access, which can read the state
directory too.

## The review and the output

`lox up` keeps cosign's and docker's own output out of the way: it is shown
when a step fails, or with `-v`.

The review a human confirms is short by default. For each lock (only the one
`lox add` or `lox remove` is about, when they run `lox up`) it shows one
block:

```
lock shop-db (locksql)
  image        ghcr.io/davidgodefroid/locksql@sha256:… (signature verified)
  target       …
  environment  none
  credentials  ask, typed at the console's start
  production   no
  profile      sha256:…  (lox up --review prints it in full)
```

`environment` is `VAULT_ADDR=…` (and the namespace) for a lock with Vault, and
`credentials` then reads `vault, <path>`. A profile that changed since the last
`lox up` says so. Every summary line that no block renders is listed under
`Other changes since the last lox up:` (`Also applied:` on the first run), so
the fingerprint that `lox up` compares still covers everything the review
shows or lists. The question is `Apply? [y/N]`.

`lox up --review` shows everything: on the first run the whole configuration,
then, for a later change, the lines that changed and every profile line by
line. It asks even for a hub with no lock.

The first `lox up` of a workspace with no lock declared and none applied
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
profile, the credentials its profile does not take from Vault. lox up runs
each console with a terminal (`tty: true`, `stdin_open: true`) as its
image's console account, and prints `lox attach <instance>` for each; that
command attaches the terminal (detach: Ctrl-P Ctrl-Q). The consoles have no
Docker log (`logging: none`, as with their own launchers: the log would keep
every screen), so attaching does not replay the pending question; on a
first start it is the policy review, `Apply these changes? [y/N]`. A console
that restarts asks again: attach again. Locks are pending (agents get no
answer) until answered. Memory and process limits are the ones each lock's
own launcher sets.

The copy is read-only in the lock. A locksql console keeps its PII rule sets
in its own home volume instead (`LOCKSQL_PII_DIR`, locksql v0.11.0 or later):
its first start writes the first rule set there after your review at its
terminal, as do `pii add` and the later PII proposals. The rule sets of
`.locksql/pii/` in the workspace, if any, are copied in once; from then on
the console's copy is in force (`/home/locksql/pii-rules/pii/<set>.toml` in
the volume `<project>_<instance>-home`): at each start it takes the
profile's new mask rules (a tightening you made in the workspace and lox up
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

lox up passes it as the console's `--allowed-uids 1000` (locksql v0.11.2,
lockmq v0.4.1, lockfile v0.5.1 or later; an older image refuses to start), and the review
shows it (`lock events serves uids 1000 besides its clients group`): a
change of it is a change to confirm. Only uids, each once: never root, 65534
(nobody), nor the console's own uid. `.lockfamily/` is read-only in lea's containers,
and every `allowed_uids` (from a legacy root file or a sub-project `lox
import` reads, which agents may write, too) is in the review you confirm. A lockhttp lock takes none (lox up refuses
the key there): it is reached by lea's gate, an account of its image. `lox import` keeps the uids every
declaration of an instance lists.

`lox add` pins only releases that run under lox up (hub mode on lockkit
v0.3.1): lockhub v0.1.1, locksql v0.11.0, lockmq v0.3.0, lockfile v0.4.0,
lockhttp v0.3.0 or later.

Locks resolve `host.docker.internal` to the host, as their launchers do
(their profile wizards name a local database or broker so). A TOML file of a
profile must be UTF-8 of at most 64 KiB: every line of it is in the review.

Vault is per lock. A lock with `vault: true` in lockfamily.yaml runs the
`-vault` variant of its image (`lox add` pins it) and gets `VAULT_ADDR` (and
`VAULT_NAMESPACE`, and the reviewed CA copy mounted read-only when the block
names a `ca_file`) from the workspace's one `vault:` block; its profile names
its own Vault path. The review shows the environment and the path of each such
lock. The token is typed at the console's start (`lox attach`), never
written anywhere. See [lox-add.md](lox-add.md#vault-per-lock) and `lox vault
set`.

Not yet (lockhub#45): lockfile's shipped seccomp profile (lox up uses
Docker's default).

## Restoring a hub version, rotating keys

`lox up --pin sha256:<digest>` (or the whole
`ghcr.io/davidgodefroid/lockhub@sha256:…` reference) runs the hub on that
image: a previous version restored by digest. The review shows the image
line that changes; cosign checks the image is a lockhub release as for any
other; once applied, lockfamily.yaml takes the digest, so the next lox up
keeps it. `hub-images.log` in the state directory lists the hub images
applied in the workspace, oldest first. An older hub on data a newer one
wrote may refuse to start: the hub's data has no downgrade path. A hub
image from before key rotation (no `lockhub rotate-key`) refuses an audit
log whose key was rotated.

`lox up --rotate hub`, `--rotate <instance>` or `--rotate all`
(repeatable, or comma-separated) replaces keys. The new keys are made
before the review, which shows each key line that changes; declined (or
`--dry-run`), they are dropped.

- A lock's new key is made by its own `hub-key`, in its own volume, under
  `.lockfamily-rotate` (its home, or the gate's `--home` for lockhttp);
  after the yes, the setup service `rotkey-<instance>` (the key's account,
  no network) moves it over the old one, whose private key is gone. The
  hub's lock list takes the new key and the lock's console restarts.
- The hub's new key is made by `lockhub keygen` in the hub's data
  directory (`rotate/`); the hub image must have `lockhub rotate-key`. After the yes, lox up stops the hub and runs
  `lockhub rotate-key`: the audit outbox is flushed under the old key, a
  `key_rotated` record signed by the old and the new key ends the old
  key's part of the audit log, the old key is listed in
  `retired-keys.pub` (data directory) and the new one replaces `hub.key`.
  Every lock restarts to pin the new key (the `hubkey` volume and
  up.json carry it). lea's gate reads the hub key at its start: restart
  it.
- A restarted console asks again for what it does not take from Vault
  (`lox attach`).

Before the review, lox up checks the hub image has `rotate-key` (and
refuses a `--pin` to an image without it once the hub key was rotated: it
would refuse the log). `rotate-key` takes the data directory's lock
(`hub.lock`, which a running hub holds), so it never runs beside a hub.
If the hub's rotation stops halfway, the hub stays stopped (no lock
executes anything) and lox up refuses to start it until `lox up
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
naming one lockhttp lock, with an older lox up, or with anything in up.json
it cannot check, lea stops, says why, and says to run `lox up`.)

lockhttp's hub mode is in the gate (`lockhttp gate --hub`, lockhttp#11),
not in its console, and the gate must sit in the network namespace of
lea's proxy to see the agents' requests. lox up therefore does not run a
gate: it runs the lockhttp console (it serves the policy, with no hub
network), creates the gate's own volume, makes the gate's instance key in
it as the gate's account (`lockhttp hub-key --home`), and registers that
key with the hub. lea runs the gate.
