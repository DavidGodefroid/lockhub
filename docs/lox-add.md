# lox add

`lox add TYPE` sets one source up: its questions, the lock's profile, the
declaration in `lockfamily.yaml`, a short review, and the console started. Run
it from the same directory as `lox init`, once per source.

```sh
lox add locksql      # a database
lox add lockmq       # a RabbitMQ broker
lox add lockfile     # a file store: S3, SFTP or a local directory
lox add lockhttp     # the HTTP policy of lea's LockHTTP gate
lox add locklog      # this host's logs: files under /var/log, the journal, containers
lox add lockssh      # a server over SSH: allow-listed commands, others on a ticket
```

`lox add TYPE INSTANCE` (two arguments) is the older form: it only declares
the lock in `lockfamily.yaml`, pinned by digest, and runs nothing else (see
[Declaring only](#declaring-only)).

## What it does

`lox add`, both forms and every type, first refuses a workspace that is not
yours or that group or others can write (the workspace directory, its
`.lockfamily/` or a lock's `.<type>/`): others could replace a lock's
reviewed configuration. The message names the directory and the fix,
`chmod go-w <directory>`.

At a terminal, `lox add TYPE` runs these steps in order:

1. **The questions** (below). Ctrl-C here ends `lox add` with nothing written.
2. **`<lock> profile add`**, then **`<lock> init claude`** and the lock's
   **`doctor`**, from the project root. The lock's profile takes the lock's
   name. A profile already in the lock's config is kept as it is. The
   doctor's repairs and what still fails are shown; a failure of the doctor
   never stops `lox add` (the console is not running yet). The doctor runs
   with `--fix --yes` for locksql, lockmq, lockhttp and lockssh, without `--fix` for
   lockfile and locklog (their only repair wires your agents, which `init
   claude` did). locksql's `--fix` also
   wires your installed agents for your account: before it runs, `lox add`
   says `locksql doctor --fix also wires your installed agents for your
   account`.
3. **The declaration** in `.lockfamily/lockfamily.yaml`: the lock's image,
   pinned by digest and cosign-verified (the `-vault` image variant for a
   lock that takes its credentials from Vault), and, for locksql, lockmq,
   lockfile, locklog and lockssh when lea is on `PATH`, your uid in `allowed_uids`
   (lea's agents run as it). A `lockfamily.yaml` that does not exist yet is created with the
   hub alone.
4. **The start (what `lox run` does before it serves decisions), with the short review of this lock**: one block with its
   image, target, environment, credentials, production flag and profile
   sha256, then `Apply? [y/N]`. Other locks are not shown, and a change the
   block does not render is listed under it, so no change escapes the
   review. `--review` shows this lock's whole profile, line by line, and asks.
5. **The console's questions**, attached at your terminal (what `lox attach
   NAME` does): its policy on a first start and, for a lock whose
   credentials are `ask`, the password; for `vault`, the Vault token. Once
   the console serves, lox detaches by itself (`lock NAME serves: detached,
   its console keeps running`); Ctrl-P Ctrl-Q detaches sooner.

When a lea container runs for the project, `lox add` says `lea gets lock NAME
at its next start: lea stop, then lea`: lea mounts the locks' sockets when its
container starts, so `lea stop`, then `lea` brings the new lock in.

## Rollback

A failed step, an answer of `n` to the review or Ctrl-C before the console
started puts the lock's `config.toml` and `lockfamily.yaml` back byte for byte
(or removes them, and a directory made for them, if they did not exist) and
says:

```
nothing kept: .locksql/config.toml and .lockfamily/lockfamily.yaml are as before; lox add locksql offers the same answers again
```

(`interrupted: ` is put in front after a Ctrl-C.) The agent's files that
`init claude` wrote and the doctor's repairs are not undone. Once `lox run`
started the console, nothing is rolled back: if the console then stops, `lox
add` names the lock and says to check, for Vault, the address and token (`lox
vault set --address URL`, then `lox run`), else to run `lox run`, then `lox
attach NAME`. A detached console that still runs is not an error.

Exit status: 0 on success, 1 on a failure or a decline, 2 for a usage
error, 130 after Ctrl-C.

## Draft

The answers of a try that kept nothing are saved in
`$XDG_STATE_HOME/lockfamily/<project>/add-<type>.json` (mode 0600), and the
next `lox add TYPE` offers them as the defaults. A successful `lox add`
removes the draft. It never holds a secret: only answers some question
accepts are written, and a value that embeds a password never is. A draft is
not read with `--non-interactive`.

## The questions

Each question shows its default in brackets and says what an empty answer
means:

- `(required)`: a value is needed; the default, if any, is what Enter takes.
- `(optional: empty = MEANING)`: Enter leaves it out.
- `(optional: - = MEANING) [DEFAULT]`: the field has a default, which Enter
  takes; type `-` to choose the meaning instead.
- yes/no questions show their default as `[y/N]` or `[Y/n]`.

A refused answer is explained (the reason names the key, never the value
typed) and asked again. When the project's files name exactly one source of
this type, its values are the defaults of the questions; with several, they
are listed above the questions as `found: ...` hints.

### locksql

| Prompt | Notes |
|---|---|
| `Engine: postgres, mysql, mariadb or sqlite (required) [postgres]: ` | `--engine` |
| `Path (required): ` | sqlite only: an absolute path to a file; `--path` |
| `Host (required) [host.docker.internal]: ` | not sqlite; no port, no scheme; `--host` |
| `Port (required) [5432]: ` | `[3306]` for mysql and mariadb; `--port` |
| `User (optional: empty = the console asks for it at start with the password): ` | not sqlite; `--user` |
| `Database (optional: empty = the server's default database): ` | not sqlite; `--database` |
| `Production? (tickets flagged production; the profile name is typed at the console's start) [y/N] ` | `--production` |
| `Credentials: ask (typed, masked, at the console's start) or vault (required) [ask]: ` | not sqlite; `--credentials` |
| `Vault path (required) [database/creds/<name>]: ` | vault only; `<name>` is the suggested name, since Name is asked last: Enter keeps the path following the name you then type (or `--name`); `--vault-path` |
| `Vault address, such as https://vault.example.com:8200 (required): ` | vault, when `lockfamily.yaml` has no vault block yet; `--vault-address` |
| `Vault namespace (optional: empty = the root namespace): ` | same condition; names of letters, digits, `_ . -` separated by `/` (one trailing `/`, as Vault prints it, is dropped); `--vault-namespace` |
| `Vault CA file (optional: empty = the system's CA certificates): ` | same condition; `--vault-ca-file` |
| `Name (required) [db]: ` | the lock's and its profile's name; the default is the compose service, database or vhost the files name, made unique; `--name` |

TLS is never asked: transport security is the driver's. Without `--tls`
(`disable`, `prefer`, `require`, `verify-ca` or `verify-full`), the profile
has no `tls` key and the driver's default (`prefer`) applies; locksql prints a
`warning:` at the console's start when the connection is plaintext. A TLS mode
the project's files name is written as is. `tls_ca`, `tls_cert`, `tls_key`
and `tls_server_name` are set in locksql's profile file.

#### The files a locksql profile names

`tls_ca`, `tls_cert`, `tls_key` and, with `ssh.auth = "key"`, `ssh.key` name
files the console reads **inside its container**, as its account (uid 10001).
The rule is locksql's own, and the only one: a leading `~/` (or a lone `~`) is
the console account's home, `/home/locksql`, which is the lock's home volume
(`<project>_<name>-home`); any other path is taken as is (an absolute path is
in the lock's image, a relative one from the console's working directory, the
project). `~/db-ca.pem` is `/home/locksql/db-ca.pem` in the volume.

Before the review of `lox add` (and of every `lox run`), lox checks each of
these files in the lock's container, as the console account, and the review
shows a `file` row per problem (`warning: lock NAME: ...` lines under `--review`
or when nothing else changed):

- a file missing from the home volume, with the command that copies it there
  from the current directory, private (`umask 077`), as the console account:

  ```
  file         WARNING: tls_ca: /home/locksql/db-ca.pem (~/db-ca.pem) is not in the lock's home volume; copy it there: docker run --rm -i --network none --user 10001:10000 -v lockfamily-1234abcd_orders-home:/home/locksql --entrypoint /bin/sh ghcr.io/davidgodefroid/locksql@sha256:… -c 'umask 077 && mkdir -p /home/locksql && cat > /home/locksql/db-ca.pem' < db-ca.pem
  ```

  It is `locksql doctor`'s command, on the volume rather than the console
  (`docker exec`), since the console may not run yet. `lox add` then asks,
  once per missing file, before `Apply? [y/N]`: `Copy tls_ca into the lock's
  home as /home/locksql/db-ca.pem, from the host file (optional: empty = not
  now, with the command above): `. A host file named there (a regular file of
  at most 1 MiB, a link is not followed) is copied the same way once you
  answer `y`; an `n` copies nothing.
- a missing file outside the home: write it `~/NAME` and copy it there;
- a path that is not a regular file, or that the console account cannot read;
- `tls_key` or `ssh.key` readable by others (any of its mode's group or other
  bits): the command that runs `chmod 600` on it in the volume.

A present file the console can read (a private key at `0600`) says nothing.
A check that cannot run is a `file` warning too; it never stops the review,
and the console still checks every file at its start.

### lockmq

| Prompt | Notes |
|---|---|
| `Management URL (required) [http://host.docker.internal:15672]: ` | an http or https URL; `--url` |
| `User (optional: empty = the console asks for it at start with the password): ` | `--user` |
| `Vhost (optional: empty = all vhosts the user can see): ` | `--vhost` |
| `AMQP URL, such as amqp://<mgmt host>:5672 (optional: - = no stream reads) [amqp://<mgmt host>:5672]: ` | an amqp or amqps URL; the default is the management URL's host, `amqps://<host>:5671` for an https management URL (or the AMQP port the project's files name); `-` for no stream reads; `--amqp-url` |
| `Production? (tickets flagged production; the profile name is typed at the console's start) [y/N] ` | `--production` |
| `Credentials: ...`, then the Vault path and the vault block | as for locksql; the Vault path defaults to `rabbitmq/creds/<name>` |
| `Name (required) [mq]: ` | `--name` |

### lockfile

| Prompt | Notes |
|---|---|
| `Source: local, s3 or sftp (required) [s3]: ` | `--source` |
| `Bucket, a bucket name, not a URL (required): ` | s3; `--bucket` |
| `Endpoint, a URL with its scheme (optional: empty = AWS): ` | s3; `--endpoint` |
| `Region (required): ` | s3 with no endpoint; with an endpoint it reads `Region (optional: empty = the endpoint's default): `; `--region` |
| `Directory (required): ` | local: an absolute path; `--dir` |
| `Host (required): ` | sftp; `--host` |
| `Port (required) [22]: ` | sftp; `--port` |
| `User (required): ` | sftp; `--user` |
| `Auth: key or password (required) [key]: ` | sftp; with `password` the console asks for it at start; `--auth` |
| `Private key file, an absolute path (required): ` | sftp with `key`; a regular file that is yours; `--key` |
| `Known hosts file (required): ` | sftp; a host file, copied to `.lockfile/known_hosts`: the profile names `~/.config/lockfile/known_hosts`, where the console sees its profile's copy ([lox-run.md](lox-run.md#lockfile-its-sftp-files)); `--known-hosts` |
| `Base directory (optional: empty = the login directory): ` | sftp; `--base-dir` |
| `Production? (tickets flagged production; the profile name is typed at the console's start) [y/N] ` | `--production` |
| `Credentials: ...`, then the Vault path and the vault block | s3 and sftp only; the Vault path defaults to `secret/data/lockfile/<name>` |
| `Name (required) [files]: ` | `--name` |

### lockhttp

Only `Name (required) [web]: `. A lockhttp lock takes no credentials and no
`allowed_uids`: lea's gate reaches it, so lea must be installed.

### locklog

| Prompt | Flag, notes |
|---|---|
| `Log directories, comma-separated absolute paths (optional: empty = every log this host shows: files under /var/log, the journal, the containers): ` | `--only`: `locklog profile add --only` |
| `Production? (tickets flagged production; the profile name is typed at the console's start) [y/N] ` | `--production` |
| `Name (required) [logs]: ` | `--name` |

`locklog profile add --non-interactive` finds this host's logs itself (the
files under `/var/log`, the journal, the containers), from facts its launcher
gathers; it never takes a secret. A remote store (Loki, Elasticsearch,
OpenSearch) is written in `.locklog/config.toml` by hand (locklog's README).
`lox run` then derives the lock's mount plan and auto rules from the reviewed
copy and shows both ([lox-run.md](lox-run.md#locklog-the-mount-plan-and-the-containers-map)).
Local sources need Linux with a rootful Docker engine 19.03 or later.

### lockssh

| Prompt | Flag, notes |
|---|---|
| `SSH host, a name (host.docker.internal for this machine) (required): ` | `--host`: a name, no user, port or scheme; an IP address is refused (the lock's egress reaches names only) |
| `Port (required) [22]: ` | `--port` |
| `Login (required): ` | `--user`: the SSH login |
| `Auth: key or password (required) [key]: ` | `--auth` |
| `Private key file in the lock's home (~/ is its home; lox run offers to copy yours there) (required) [~/.ssh/id_ed25519]: ` | `--key`, with `auth` key: a path in the console's account, never your file's content |
| `Known hosts file in the lock's home (optional: empty = the console's own: a new host key is confirmed at the console): ` | `--known-hosts`: with one, a host key it does not hold is refused |
| `Allowed commands, separated by ;, such as uptime; df -h; systemctl status * (optional: empty = none yet (edit .lockssh/config.toml)): ` | `--allow "uptime; df -h"`: one `lockssh profile add --allow` per rule |
| `May the agent ask for other commands (each one approved on a ticket)? [y/N] ` | `--exec` |
| `Production? (tickets flagged production; the profile name is typed at the console's start) [y/N] ` | `--production` |
| `Credentials: none (an unencrypted key), ask (typed at the console's start) or vault (required) [none]: ` | `--credentials`: the key's passphrase; with `auth` password, `ask` or `vault` (the password) |
| `Vault path (required) [secret/data/lockssh/<name>]: ` | `--vault-path`, with `credentials` vault |
| `Name (required) [ssh]: ` | `--name` |

At a terminal, the hosts of your `~/.ssh/config` (a plain `Host` with its
`HostName`, `User` and `Port`; never one behind `ProxyJump` or
`ProxyCommand`, nor an IP address) are proposed. The key lives in the lock's
home volume, which only the console account reads: the review checks it
there and, before `Apply?`, offers to copy your key file into it (empty: not
now; the review's command does it later). `lox run` reads the profile's auto
rules and gives the lock an egress to its `host`:`port` only
([lox-run.md](lox-run.md#lockssh-one-ssh-host-per-profile)).

## Non-interactive

```sh
lox add locksql --non-interactive --host db.example.com --database shop --name shop-db
```

`--non-interactive` asks nothing: each question is answered by its flag, else
by its default; no draft and no detection are used. Where the source is is
never guessed: `--host` (or lockmq's `--url`) is required, and so is any other
question with no default (`--user` for sftp, `--bucket`, `--vault-address`
for the first lock with Vault, ...); the error says `usage: --NAME is required
(lox add TYPE --non-interactive)`. A flag that is no question for the answers
given is refused (`--NAME: not a question of lox add TYPE with these
answers`). A password has no flag: it is typed at the console's start.

It never starts anything: it declares the lock (steps 2 and 3 above) and ends
with

```
lock shop-db declared: run lox run at a terminal to review and start it
```

Without `--non-interactive`, a `lox add` that has no terminal on its input
stops, naming the flag. `--review` is for a terminal and cannot be combined
with `--non-interactive`.

## Flags

`--engine --host --port --user --database --tls --path --url --vhost
--amqp-url --source --bucket --endpoint --region --dir --auth --key
--known-hosts --base-dir --production --credentials --vault-path
--vault-address --vault-namespace --vault-ca-file --name` answer the question
of the same name (`--dir` is lockfile's directory; `lox add lockfile` refuses
`--path`; `--tls` answers no question, it sets locksql's TLS mode). The
others:

| Flag | Meaning |
|---|---|
| `--non-interactive` | ask nothing (above) |
| `--review` | the review of `lox run` shows this lock's whole profile and asks |
| `-v` | show cosign's and docker's own output (default: only when a step fails) |
| `--version vX.Y.Z` | the lock's release to pin (default: the latest) |
| `--file PATH` | the workspace's `lockfamily.yaml` |

`--instance` is not a `lox add` flag: it belongs to the locks' launchers. When
a project has two locks of one type, an agent on the host picks one with
`<lock> mcp --instance NAME` (see [lox-run.md](lox-run.md)).

## Vault, per lock

Each lock chooses its credentials: `ask` or `vault`. With `vault`, the lock
runs the `-vault` variant of its image and `lockfamily.yaml` marks it
`vault: true`; its profile names its own Vault path (`Vault path`). The Vault
address, namespace and CA file are shared by the locks of a workspace, in one
`vault:` block of `lockfamily.yaml`: the first lock with Vault asks for them,
the next ones do not.

No secret is ever written to disk, to `lockfamily.yaml`, to the draft or to a
command line. The Vault token is typed at the console's start, masked, under
`lox attach` (step 5), never at a `lox add` question.

To write or change the shared block by itself:

```sh
lox vault set --address https://vault.example.com:8200 [--namespace NS] [--ca-file PATH]
```

An omitted `--namespace` or `--ca-file` keeps the current value, and `""`
clears it. The same checks as in the questions apply, and the command repairs
a file whose vault block fails them. Nothing is started: run `lox run` to
review and apply it. A change of the CA restarts the locks with Vault.

## Removing a lock

```sh
lox remove NAME [--purge] [-v] [--file PATH]
```

It takes the lock out of `lockfamily.yaml`, shows `remove lock NAME (TYPE): its
console stops; ...`, and applies it as `lox run` starts, with the short review of that lock
(the change is confirmed at a terminal). `lock NAME removed` says it is done.
A `n`, a failure or Ctrl-C puts `lockfamily.yaml` back. The lock's profile
stays in its `config.toml`; `--purge` removes it once the lock is gone (refused
before anything changes when the lock names no profile or another lock serves
the same one).

## Declaring only

```sh
lox add locksql shop-db [--version vX.Y.Z | --image ghcr.io/davidgodefroid/locksql@sha256:<digest>] [--profile P] [--hub-image REF]
```

It writes the lock into `lockfamily.yaml` (pinned by digest to its latest
signed release, or the one given), and prints `<file>: lock shop-db (locksql)
declared; run lox run to review and start it`. No profile is written and
nothing is started. `--image`, `--hub-image` and `--profile` belong to this
form only, the question flags to the guided one.
