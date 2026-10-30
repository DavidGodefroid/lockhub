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
| `$XDG_RUNTIME_DIR/lockhub/facade.sock` | the hub | `lock approve`, lea's deck |

`lock up` refuses a `.lockfamily/` that is a link, not the user's, or
writable by group or others, and keeps its own copy of up.json in its state
directory. It writes up.json through a fresh file renamed into place (a
planted link is replaced, never followed).

lea creates `.lockfamily/` (owned by the host user, 0755) before it mounts
it read-only in its agents' containers: no agent can change
lockfamily.yaml or up.json. A `lockfamily.yaml` at the workspace's root
(the layout before this page) is still read, with a warning: agents can
write there. Move it into `.lockfamily/`; the workspace keeps its project
and state.

## up.json (version 1)

```json
{
  "version": 1,
  "project": "lockfamily-1a2b3c4d",
  "workspace": "/home/me/projects",
  "hub_network": "lockfamily-1a2b3c4d_lockhub",
  "hub_url": "http://lockhub:8443",
  "hub_key": "<base64 Ed25519 public key>",
  "locks": {
    "crm": {"type": "locksql", "socket_volume": "lockfamily-1a2b3c4d_crm-run", "client_gid": "10000"},
    "web": {"type": "lockhttp", "socket_volume": "lockfamily-1a2b3c4d_web-run",
            "gate_home_volume": "lockfamily-1a2b3c4d_web-gate", "client_gid": "10020"}
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
--hub-plain-http --hub-key-file … --instance <name> --home … --hub-net
<the network's subnet>`. The gate refuses the hub's addresses as targets,
so an agent cannot reach the hub through it (invariant I2). No agent
container joins `hub_network`.

## Profiles: a reviewed copy

A lock's profile directory is in the workspace, which agents may write. lock
up never mounts it. It reads it once, following no link, taking only the
user's own regular files and directories that no one else can write (64 KiB
at most), shows its fingerprint in the review (`profile <type> <dir>
sha256:…`; a change is a change to confirm), and after the yes copies
exactly that archive into the volume `profile-<type>` (written by root,
read-only in the lock). A new copy recreates the lock's console.

## Consoles under compose

Every lock's console asks a human at its terminal: its policy on the first
start and after a loosening, the typed profile name of a production
profile, the credentials its profile does not take from Vault. lock up runs
each console with a terminal (`tty: true`, `stdin_open: true`) as its
image's console account, and prints `lock attach <instance>` for each; that
command shows the console's last lines (its pending question) and attaches
the terminal (detach: Ctrl-P Ctrl-Q). A console that restarts asks again:
attach again. Locks are pending (agents get no answer) until answered.

Profiles with `credentials = "vault"` or `"none"` ask nothing but the
policy.

## Why lockhttp is different

lockhttp's hub mode is in the gate (`lockhttp gate --hub`, lockhttp#11),
not in its console, and the gate must sit in the network namespace of
lea's proxy to see the agents' requests. lock up therefore does not run a
gate: it runs the lockhttp console (it serves the policy, with no hub
network), creates the gate's own volume, makes the gate's instance key in
it as the gate's account (`lockhttp hub-key --home`), and registers that
key with the hub. lea runs the gate.
