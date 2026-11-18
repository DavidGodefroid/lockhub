# lox live

`lox run` serves the hub's decisions to a human at a terminal. `lox live` is
its headless twin, for a host nobody sits at: a systemd service with no
terminal, that comes back by itself after a reboot. Same hub, same locks,
same decision engine (`internal/loxrun`), no human.

Its rule: **lox live approves nothing a written rule does not name.**
Everything a human decides today stays a human's. lox live takes the human
out of the start and of the routine, not of the sensitive decisions. It
fails closed: when it stops, nothing is decided and tickets wait at the hub.

```sh
lox run                 # at a terminal: review, apply, answer the consoles
lox live enrol          # at a terminal: enrol what is applied
lox live                # the service: no terminal, plain log lines
lox live status --json  # its health (exit 0: serving)
```

## What it does, and never does

| | lox live |
|---|---|
| A review (`Apply? [y/N]`) | never answered: a configuration that differs from the enrolment is not applied |
| Image upgrades | none: the pins stay; an upgrade is a maintenance (`lox run`, then enrol) |
| cosign | not run: the images were verified at the enrolment; one that was not is not started |
| A ticket a rule decides (the profile's auto rule is `auto`, or `deny`) | decided, as facade `live`, the rule named in the signed decision |
| Any other ticket: a write or DDL its rule asks, a first connection with no `connect = "auto"`, a grant, an unmask, a never-auto ticket, a typed name, typed values, a policy loosening, a ticket the hub wants a human for | left pending at the hub, for a human's facade: the paired phone, or `lox approve` in a terminal |
| **A write on production** (risk `prod-write`, or a write, DDL, lockmq get/publish/purge/delete, or any non-read action on a production ticket) | **never by a rule**, whatever the profile says (`write = "auto"` included): left to a human. The floor is the engine's, for every lock type, in `lox run` too. A production read, and a production profile's connect, follow their rule |
| A console's Vault token question, lock with `vault_token: cli` | answered with the host's Vault token, again each time the console asks (a restart, an expiry) |
| Any other console question: a password, a passphrase, a policy to review, a production profile's name, an SSH host key | never answered; the lock is reported `missing_secret`, `needs_enrolment` or `refused` |
| A ticket that does not verify under the pinned lock key | refused with the reason (as `lox run`), so its lock ends the plan |
| Reveal (clear values), renewal of an expired ticket | never: the hub refuses them to facade `live` |

The hub enforces its side whatever a client of the facade socket sends
under the name `live`: an approval without a rule is refused, and so is a
rule's approval of a never-auto ticket, of one that needs a typed name or
typed values, or of a version-1 ticket. The locks enforce theirs: a ticket
their own rule does not leave to the auto mode is signed never-auto, and a
`deny` is refused before any ticket.

## Enrolment

Two steps, the first by a human, once, and again after every change.

**1. At a terminal: `lox run`, then `lox live enrol`.** `lox run` as ever:
the review of the configuration, each lock's policy at its console, the
SSH host keys, each production profile's typed name. Then quit it and run

```sh
lox live enrol
```

It checks that what the files say is exactly what `lox run` applied (else:
`lox run` first), verifies every pinned image with cosign, shows the
fingerprint, asks the name of each production profile typed, then `Enrol
this workspace for lox live? [y/N]`. It writes
`$XDG_STATE_HOME/lockfamily/<project>/live-enrolment.json` (0600):

- `fingerprint`: the one the review uses (every line that can change what
  the hub or a lock accepts: images by digest, keys, routing, each profile's
  content, egress, auto rules, Vault);
- `images`: the pinned images cosign verified at that moment;
- `production`: the locks that serve a production profile, with the name
  typed.

**2. The service: `lox live`.** At each start (and after a reboot) it

1. makes the runtime directory again (`$XDG_RUNTIME_DIR/lockhub`, a tmpfs);
2. compares the current fingerprint with the enrolled one. Equal: it goes
   on with no question. Different, an image not verified at the enrolment,
   or no enrolment: **nothing is applied, started or stopped**; it logs
   why, its health says `needs_enrolment`, and it keeps running so that the
   status socket answers. It checks again when the enrolment file changes
   (`lox live enrol`), on `SIGHUP`, and every ten minutes;
3. brings the stack up as `lox run` does (same compose file, the hub
   created again on the new runtime directory), without upgrade and
   without cosign;
4. serves decisions.

A change of the company's managed file alone is applied without an
enrolment, as `lox run` applies it without a question: it is the admin's and
only tightens.

**Production profiles.** With the locks this lox ships (lockkit v0.20.0), a
console asks its production profile's name only when a policy review was
approved at that start, or when the policy in force loosens the one the name
was last typed for; with an unchanged policy it asks nothing and prints
`profile name typed at an earlier start`. So after the enrolment's `lox run`,
a restart of the console asks neither the name nor the policy, and lox live
types neither: there is nothing to answer. If a console does ask (its policy
was loosened in the files, or its state volume was lost), lox live does not
answer, reports the lock `needs_enrolment`, and a human answers at a terminal
(`lox run`), then enrols again. lox live never weakens that gate.

## Secrets

In live mode every secret comes from **Vault**:

- a lock with `vault: true` and `vault_token: cli` gets the host's Vault
  token, as with `lox run`: read with the Vault CLI (`vault print token`,
  else `~/.vault-token`), checked against the reviewed Vault address, CA and
  the profile's reviewed `vault_path`, typed at the console's terminal
  through Docker only, never through the hub nor a log;
- when the console asks again (it restarted, its token expired), lox live
  reads the token again and answers again. A connect ticket of a lock whose
  token expired is approved by its `connect = "auto"` rule with the token
  sealed to the lock's one-use key;
- a token the host cannot give, or one the lock refused, is not typed in a
  loop: the lock is `missing_secret`, and lox live tries again every 30
  seconds;
- a profile with `credentials = "ask"` is not served: `missing_secret`, said
  at start and by `lox live enrol`. Move it to Vault.

**AppRole.** lox live has no AppRole code: run **Vault Agent** beside it,
under the same Unix user, with an AppRole auto-auth and a file sink on
`~/.vault-token`. The agent logs in, renews, and logs in again when the
token expires; lox live reads what it wrote each time a console asks.

```hcl
# /etc/lox-live/vault-agent.hcl (the unit: User=lox-live,
# LoadCredential=secret-id:/etc/lox-live/secret-id)
vault { address = "https://vault.example.com:8200" }
auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/etc/lox-live/role-id"
      secret_id_file_path                 = "/run/credentials/vault-agent-lox-live.service/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" { config = { path = "/var/lib/lox-live/.vault-token", mode = 0600 } }
}
```

The role's policy needs `read` on each lock's `vault_path` and nothing else.

## Auto rules

lox live (and `lox run`) reads the per-profile auto rules of every lock that
has them, from the reviewed copy of its profile (`<type> profile rules
--json`, run in the lock's image with no network): locklog, lockssh,
**locksql** (`connect`, `read`, `write`, `ddl`; its `unmask` stays the
console's own never-auto) and **lockmq** (`connect`, `list`, `read`, `peek`,
`get`, `publish`, `purge`, `delete`). They are lines of the review, hence of
the fingerprint: loosening one needs `lox run` and a new enrolment.

For an unattended production profile, a typical setting:

```toml
[profiles.prod.auto]
connect = "auto"   # no question per session: lox live has nobody to ask
read    = "auto"
write   = "deny"   # refused at the lock, no ticket
ddl     = "deny"
```

`ask` leaves the ticket to a human's facade. The managed file's `[lox]
auto_max` and `production_auto_max` cap these rules as in `lox run`.

## A human's green light

A ticket lox live does not decide waits at the hub. A human decides it on an
existing facade: the paired phone (production included), `lox approve` in a
terminal on the host as lox live's user, or, off production, a chat facade.
`lox approve`, `lox tickets`, `lox withdraw` and `lox audit` work next to
lox live.

**`lox run` and lox live never serve one workspace together**: both would
race for every ticket, with different rules about who is asked. Each takes a
lock in the state directory (`serve.lock`, `flock`: it goes with its
process), and the second is refused:

```
lox run: lox live serves this workspace's decisions (lox live pid 4242): answer the tickets it leaves to a human with lox approve (or the phone), or stop it first (systemctl stop lox-live) to run lox run
lox live: lox run serves this workspace's decisions in a terminal: quit it (q q) before lox live starts
```

Maintenance (a new profile, a looser rule, an upgrade): `systemctl stop
lox-live`, `lox run` as its user (same `XDG_RUNTIME_DIR`), `lox live enrol`,
`systemctl start lox-live`.

## Audit

Every decision is signed by the hub and logged with its facade. lox live's
are `"facade":"live"` with the rule, `lox run`'s rule decisions `"tty"`: the
audit tells what a rule decided unattended from what was decided at a
terminal. `lox audit show ID` says `by the auto rule profile:read in lox
live`; `lox audit --json` carries `"facade":"live"`. lox live's sessions
(start, stop, each Vault token handed to a console) are in `runs.jsonl` as
user `lox live`, mode `LIVE`.

## The status socket

Another program (the DutyDesk daemon) must know whether the locks serve and
what became of a ticket, and must not be able to decide one. It runs under
**another Unix user**, has no access to the facade socket, and reads lox
live's status socket: HTTP/1.1, JSON, on a unix socket, mode `0660`, group
`--status-group`. Default path `$XDG_RUNTIME_DIR/lockhub/live-status.sock`;
that directory is `0700`, so for another user give `--status-socket` a
directory its group can enter (the unit below does).

| Request | Answer |
|---|---|
| `GET /v1/health` | `200 {"serving":bool,"locks":{"<instance>":"serving\|needs_enrolment\|missing_secret\|refused\|down"},"pending":<int>,"detail":"<short text>"}` |
| `GET /v1/tickets/{instance}/{id}` | `200 {"state":"pending\|approved\|denied\|expired\|withdrawn\|consumed"}`; unknown: `404`; the hub does not answer: `503` |
| `POST /v1/tickets/{instance}/{id}/withdraw` | `204`; not a pending ticket of a `dutydesk:` agent: `403`; unknown: `404` |

- `serving` is true only when lox live is enrolled and started, the hub
  answers it, and every lock of the workspace is `serving`. `pending` counts
  the tickets waiting at the hub. `detail` names the first thing in the way.
- A lock is `needs_enrolment` (nothing started for want of an enrolment, or
  its console asks a policy review or a production name), `missing_secret`
  (a password or passphrase a human types, a Vault token the host cannot
  give), `refused` (any other console question, such as an SSH host key),
  `down` (not started, stopped, not reached yet).
- A ticket whose lock was removed (`lock_removed` at the hub) reads
  `withdrawn`.
- A withdrawal is taken only for a ticket still pending whose requester's
  agent label starts with `dutydesk:`, read from the ticket its lock signed
  and lox live verified under the pinned lock key (an unverifiable ticket
  names nobody). It goes through the hub's withdrawal (the lock is told and
  frees its queue) and is audited: facade `live`, reason `withdrawn by uid
  <caller's uid> (status socket) in lox live`.
- **No route decides, reveals or renews a ticket.** Anything else is `404`
  or `405`.

`lox live status [--json] [--status-socket PATH]` prints the same health;
exit 0 when serving, 1 otherwise (lox live not running included).

## The service

`contrib/systemd/lox-live.service` is a system unit under a dedicated user:

- `User=lox-live`, with access to the container engine
  (`SupplementaryGroups=docker`; with a rootful engine that group is root on
  the host, as for any user of `lox run`). It owns the workspace and the
  state directory: `lox run` and `lox live enrol` are run as that user;
- `RuntimeDirectory=lox-live lox-live-status` with
  `XDG_RUNTIME_DIR=/run/lox-live`: systemd makes them again at each start
  (`/run` is wiped at reboot), lox live makes `lockhub/` (0700) in the first
  and the hub is created again on it;
- `Requires=`/`After=docker.service`, `After=network-online.target`: while
  the engine is not ready, the start fails, the health says `down`, and lox
  live tries again (15 s, doubling to 2 min);
- `Restart=on-failure`: `SIGTERM` ends it cleanly (exit 0), a crash brings
  it back; `ExecReload` sends `SIGHUP` (check the enrolment, start over);
- the status socket in `/run/lox-live-status` (group `lox-status`, of which
  the reader's user is a member), `--status-group lox-status`.

A user service works too (`systemctl --user`, `loginctl enable-linger`, the
user's own `/run/user/<uid>`), with the same command line.

Logs are plain lines on stdout (journald): the start, one line per ticket
(decided by which rule, or `left to a human's facade` and why), each
console question not answered, each withdrawal on the status socket. Never a
value in clear nor a secret.

## Security model

- **Run lox live under its own Unix user.** The hub's facade socket trusts
  its Unix user: any process of that user can decide tickets (except the
  classes `hub.mobile.require_device` reserves to a phone). Nothing else
  runs as lox live's user; agents, and the daemon that reads the status
  socket, run as others.
- lox live holds no key that a human's approval needs: the hub signs, and
  refuses facade `live` anything but a rule's decision, a denial and a
  withdrawal in `lox live`.
- What starts unattended is what a human reviewed and enrolled, to the
  digest. The enrolment file, the applied state and the rules lox live
  reads live in the host-only state directory (0700), never in the
  workspace, which agents can write.
- The host's Vault token is the service's standing secret: scope its policy
  to the locks' `vault_path`s, give the AppRole secret-id to Vault Agent
  through systemd credentials, and keep the token file `0600`.
- The status socket is read-only by construction; its one write (a
  withdrawal) only ends a ticket, never approves one, and only the caller's
  own agents' tickets.

## Requirements

- A hub image of the lockhub release that ships lox live or later: an older
  hub refuses facade `live`. lox live asks the hub (`GET /v1/hub`, `"live":
  true`) and, with an older one, says so and serves nothing: `lox run`
  upgrades it, then enrol.
- No lock-side change: lockkit's decisions name any facade, and its
  production-name confirmation already persists across restarts (v0.20.0).
