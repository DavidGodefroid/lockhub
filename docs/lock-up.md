# lock up and lea

`lock up` runs the hub and a workspace's locks with Docker Compose. lea's
agents reach the locks' sockets, never the hub. This page is the contract
between the two.

## Files

| Path | Written by | Read by |
|---|---|---|
| `<workspace>/.lockfamily/lockfamily.yaml` | the human (`lock add`, `lock import`) | `lock` |
| `<workspace>/.lockfamily/up.json` | `lock up`, after a confirmed apply | lea |
| `<workspace>/.<type>/` (`.locksql`, `.lockmq`, `.lockfile`, `.lockhttp`) | the human (the lock's own profile tools) | `lock up`, which copies it (see below) |
| `$XDG_STATE_HOME/lockfamily/<project>/` | `lock up` | `lock` only (hub data, applied fingerprint, compose copy) |
| `$XDG_STATE_HOME/lockfamily/facades/` (`tty.key`, `deck.key`: private, `0600`; `locks.json`: the lock keys lock up pinned, the union of every workspace's `locks.d/<project>.json`; an instance two workspaces pin with different keys, or a key two instances share, is left out with a warning naming both workspaces: rename it in one, or delete the `locks.d` file of a workspace that was moved or deleted) | `lock up` (one directory per user, shared by workspaces) | `lock approve` (tty), lea's deck: they sign a reveal's ephemeral key and verify the lock's signed answer |
| `$XDG_STATE_HOME/lockfamily/<project>/facades.json` | `lock up` (public keys only) | the locks with `reveal: true`, mounted at `/run/lockfamily-facades/facades.json` (`--facade-keys-file`) |
| `$XDG_RUNTIME_DIR/lockhub/facade.sock` | the hub | `lock approve`, lea's deck |

`lock up` refuses a `.lockfamily/` that is a link, not the user's, or
writable by group or others, and keeps its own copy of up.json in its state
directory. It writes up.json through a fresh file renamed into place (a
planted link is replaced, never followed).

lea creates `.lockfamily/` (owned by the host user, 0755) before it mounts
it read-only in its agents' containers: no agent can change
lockfamily.yaml or up.json. A `lockfamily.yaml` at the workspace's root
(the layout before this page) is still read, with a warning: agents can
write there. The first confirmed `lock up` copies exactly what was reviewed
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
these members are written, and lea runs its gate in hub mode only then):

- `devices` (top level): the paired devices (lockkit `ticket.DeviceSet`,
  public keys only), the set lock up mounts read-only for the consoles at
  `/run/lockfamily-devices/devices.json`. Absent while no device is
  paired (`lock mobile pair`).
- per lock, `devices: true` when the lock pins them (lockfamily.yaml
  `locks.<name>.devices`); then `require_device` and `seal_clear`, from
  `hub.mobile`, exactly as lock up passes `--require-device` and
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
- mounts it on `/run/<type>` and adds the clients group, instead of the
  fixed `<type>-run` volume of a console started by the tool's own
  launcher. One instance per type: with two of a type, lea leaves the
  type out and says so.

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
phones sealed. lea refuses hub mode (and runs the standalone gate, saying
why) when `require_device` is set and no device is paired. The gate refuses the hub's addresses as targets,
so an agent cannot reach the hub through it (invariant I2). No agent
container joins `hub_network`.

## Profiles: a reviewed copy

A lock's profile directory is in the workspace, which agents may write. lock
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
profile, the credentials its profile does not take from Vault. lock up runs
each console with a terminal (`tty: true`, `stdin_open: true`) as its
image's console account, and prints `lock attach <instance>` for each; that
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
profile's new mask rules (a tightening you made in the workspace and lock up
reviewed), never what would loosen it or change its mode (allow rules,
removed masks, mode changes), which you change at the console. A locksql image older than v0.11.0 ignores the variable and cannot
write its first rule set: `lock add locksql <instance>` again pins a newer
release.

Several instances of one type share the type's profile directory; each
serves the profile its `profile:` names in lockfamily.yaml (a profile of
that directory's configuration, such as `[profiles.crm-prod]` and
`[profiles.crm-uat]` of one `.locksql/config.toml`). A profile directory per
instance is not supported (lockhub#44).

lea's agents run as the host user's uid, which has no account in a lock's
image: the console refuses them unless the lock names that uid. In
lockfamily.yaml, per lockmq or lockfile lock:

```yaml
locks:
  events:
    type: lockmq
    image: ghcr.io/davidgodefroid/lockmq@sha256:…
    allowed_uids: [1000]   # id -u of the account that runs lea
```

lock up passes it as the console's `--allowed-uids 1000` (lockmq v0.4.1,
lockfile v0.5.1 or later; an older image refuses to start), and the review
shows it (`lock events serves uids 1000 besides its clients group`): a
change of it is a change to confirm. Only uids, each once: never root, nor
the console's own uid. lockfamily.yaml is read-only in lea's containers, so
no agent can add one. A locksql lock takes none yet (its console has no such
flag; lock up refuses the key there), and a lockhttp lock is reached by
lea's gate, an account of its image. `lock import` keeps the uids every
declaration of an instance lists.

`lock add` pins only releases that run under lock up (hub mode on lockkit
v0.3.1): lockhub v0.1.1, locksql v0.11.0, lockmq v0.3.0, lockfile v0.4.0,
lockhttp v0.3.0 or later.

Locks resolve `host.docker.internal` to the host, as their launchers do
(their profile wizards name a local database or broker so). A TOML file of a
profile must be UTF-8 of at most 64 KiB: every line of it is in the review.

Not yet (lockhub#45): Vault (`credentials = "vault"` needs `VAULT_ADDR` and the
`-vault` image variant, which lock up does not pass or pin), and lockfile's
shipped seccomp profile (lock up uses Docker's default).

## Restoring a hub version, rotating keys

`lock up --pin sha256:<digest>` (or the whole
`ghcr.io/davidgodefroid/lockhub@sha256:…` reference) runs the hub on that
image: a previous version restored by digest. The review shows the image
line that changes; cosign checks the image is a lockhub release as for any
other; once applied, lockfamily.yaml takes the digest, so the next lock up
keeps it. `hub-images.log` in the state directory lists the hub images
applied in the workspace, oldest first. An older hub on data a newer one
wrote may refuse to start: the hub's data has no downgrade path. A hub
image from before key rotation (no `lockhub rotate-key`) refuses an audit
log whose key was rotated.

`lock up --rotate hub`, `--rotate <instance>` or `--rotate all`
(repeatable, or comma-separated) replaces keys. The new keys are made
before the review, which shows each key line that changes; declined (or
`--dry-run`), they are dropped.

- A lock's new key is made by its own `hub-key`, in its own volume, under
  `.lockfamily-rotate` (its home, or the gate's `--home` for lockhttp);
  after the yes, the setup service `rotkey-<instance>` (the key's account,
  no network) moves it over the old one, whose private key is gone. The
  hub's lock list takes the new key and the lock's console restarts.
- The hub's new key is made by `lockhub keygen` in the hub's data
  directory (`rotate/`); the hub image must have `lockhub rotate-key`. After the yes, lock up stops the hub and runs
  `lockhub rotate-key`: the audit outbox is flushed under the old key, a
  `key_rotated` record signed by the old and the new key ends the old
  key's part of the audit log, the old key is listed in
  `retired-keys.pub` (data directory) and the new one replaces `hub.key`.
  Every lock restarts to pin the new key (the `hubkey` volume and
  up.json carry it). lea's gate reads the hub key at its start: restart
  it.
- A restarted console asks again for what it does not take from Vault
  (`lock attach`).

Before the review, lock up checks the hub image has `rotate-key` (and
refuses a `--pin` to an image without it once the hub key was rotated: it
would refuse the log). `rotate-key` takes the data directory's lock
(`hub.lock`, which a running hub holds), so it never runs beside a hub.
If the hub's rotation stops halfway, the hub stays stopped (no lock
executes anything) and lock up refuses to start it until `lock up
--rotate hub` is run again, which finishes the same rotation with the same
new key, after asking the hub which key it holds (`lockhub pubkey`).

`hub-keys.pub` in the state directory lists every hub key, oldest first,
the current one last. `lock audit verify --hub-key-file` takes it (a file
with one key is the same as before any rotation): the log must be signed
by each key in turn, handed over by a `key_rotated` record signed by both,
and end on the last key, so that a log cut back to before a rotation is
refused; each decision must be signed by the key of the record that
vouches for it.

## Why lockhttp is different

(lea's side of this is lea#209: lea runs its gate in hub mode for the one
lockhttp lock of a workspace's up.json from `"lockhttp_gate": 1` on; with
an older lock up, or anything in up.json it cannot check, it keeps its
standalone gate and says why.)

lockhttp's hub mode is in the gate (`lockhttp gate --hub`, lockhttp#11),
not in its console, and the gate must sit in the network namespace of
lea's proxy to see the agents' requests. lock up therefore does not run a
gate: it runs the lockhttp console (it serves the policy, with no hub
network), creates the gate's own volume, makes the gate's instance key in
it as the gate's account (`lockhttp hub-key --home`), and registers that
key with the hub. lea runs the gate.
