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
| `$XDG_STATE_HOME/lockfamily/facades/` (`tty.key`, `deck.key`: private, `0600`; `locks.json`: the lock keys lock up pinned, the union of every workspace's `locks.d/<project>.json`; an instance two workspaces pin with different keys is left out, with a warning) | `lock up` (one directory per user, shared by workspaces) | `lock approve` (tty), lea's deck: they sign a reveal's ephemeral key and verify the lock's signed answer |
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
  "locks": {
    "crm": {"type": "locksql", "socket_volume": "lockfamily-1a2b3c4d_crm-run", "client_gid": "10000"},
    "web": {"type": "lockhttp", "socket_volume": "lockfamily-1a2b3c4d_web-run",
            "gate_home_volume": "lockfamily-1a2b3c4d_web-gate", "client_gid": "10020", "reveal": true}
  }
}
```

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
facade and refuses reveals; renewals work either way. The gate refuses the hub's addresses as targets,
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

The copy is read-only in the lock: what a console writes in its own
profile directory (locksql's PII rule sets in `.locksql/pii/`, edited at its
console) cannot be written there; edit them in the workspace and run lock up
again. A locksql console writes its first rule set at its first start, so lock
up refuses a `.locksql/` without one: start the console once with locksql's
own launcher (it writes `.locksql/pii/<set>.toml` after your review), then
lock up.

`lock add` pins only releases that run under lock up (hub mode on lockkit
v0.3.1): lockhub v0.1.1, locksql v0.10.0, lockmq v0.3.0, lockfile v0.4.0,
lockhttp v0.3.0 or later.

Locks resolve `host.docker.internal` to the host, as their launchers do
(their profile wizards name a local database or broker so). A TOML file of a
profile must be UTF-8 of at most 64 KiB: every line of it is in the review.

Not yet: Vault (`credentials = "vault"` needs `VAULT_ADDR` and the
`-vault` image variant, which lock up does not pass or pin), and lockfile's
shipped seccomp profile (lock up uses Docker's default).

## Why lockhttp is different

(lea's side of this, the gate in hub mode, is not in lea yet: until it is,
a lockhttp lock under lock up runs a console that only a gate you start
yourself reaches.)


lockhttp's hub mode is in the gate (`lockhttp gate --hub`, lockhttp#11),
not in its console, and the gate must sit in the network namespace of
lea's proxy to see the agents' requests. lock up therefore does not run a
gate: it runs the lockhttp console (it serves the policy, with no hub
network), creates the gate's own volume, makes the gate's instance key in
it as the gate's account (`lockhttp hub-key --home`), and registers that
key with the hub. lea runs the gate.
