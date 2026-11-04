# lox add

`lox add TYPE` sets one source up: its questions, the lock's profile, the
declaration in `lockfamily.yaml`, a short review, and the console started. Run
it from the same directory as `lox init`, once per source.

```sh
lox add locksql      # a database
lox add lockmq       # a RabbitMQ broker
lox add lockfile     # a file store: S3, SFTP or a local directory
lox add lockhttp     # the HTTP policy of lea's LockHTTP gate
```

`lox add TYPE INSTANCE` (two arguments) is the older form: it only declares
the lock in `lockfamily.yaml`, pinned by digest, and runs nothing else (see
[Declaring only](#declaring-only)).

## What it does

At a terminal, `lox add TYPE` runs these steps in order:

1. **The questions** (below). Ctrl-C here ends `lox add` with nothing written.
2. **`<lock> profile add`**, then **`<lock> init claude`** and the lock's
   **`doctor`**, from the project root. The lock's profile takes the lock's
   name. A profile already in the lock's config is kept as it is. The
   doctor's repairs and what still fails are shown; a failure of the doctor
   never stops `lox add` (the console is not running yet). The doctor runs
   with `--fix --yes` for locksql, lockmq and lockhttp, without `--fix` for
   lockfile (its only repair wires your agents). locksql's `--fix` also
   wires your installed agents for your account: before it runs, `lox add`
   says `locksql doctor --fix also wires your installed agents for your
   account`.
3. **The declaration** in `.lockfamily/lockfamily.yaml`: the lock's image,
   pinned by digest and cosign-verified (the `-vault` image variant for a
   lock that takes its credentials from Vault), and, for locksql, lockmq and
   lockfile when lea is on `PATH`, your uid in `allowed_uids` (lea's agents
   run as it). A `lockfamily.yaml` that does not exist yet is created with the
   hub alone.
4. **`lox up`, with the short review of this lock**: one block with its
   image, target, environment, credentials, production flag and profile
   sha256, then `Apply? [y/N]`. Other locks are not shown, and a change the
   block does not render is listed under it, so no change escapes the
   review. `--review` shows this lock's whole profile, line by line, and asks.
5. **The console's questions**, attached at your terminal (what `lox attach
   NAME` does): its policy on a first start and, for a lock whose
   credentials are `ask`, the password; for `vault`, the Vault token. Detach
   with Ctrl-P Ctrl-Q once it says Listening.

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
`init claude` wrote and the doctor's repairs are not undone. Once `lox up`
started the console, nothing is rolled back: if the console then stops, `lox
add` names the lock and says to check, for Vault, the address and token (`lox
vault set --address URL`, then `lox up`), else to run `lox up`, then `lox
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
| `Production? (each approval needs the profile name typed) [y/N] ` | `--production` |
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

### lockmq

| Prompt | Notes |
|---|---|
| `Management URL (required) [http://host.docker.internal:15672]: ` | an http or https URL; `--url` |
| `User (optional: empty = the console asks for it at start with the password): ` | `--user` |
| `Vhost (optional: empty = all vhosts the user can see): ` | `--vhost` |
| `AMQP URL, such as amqp://<mgmt host>:5672 (optional: - = no stream reads) [amqp://<mgmt host>:5672]: ` | an amqp or amqps URL; the default is the management URL's host, `amqps://<host>:5671` for an https management URL (or the AMQP port the project's files name); `-` for no stream reads; `--amqp-url` |
| `Production? (each approval needs the profile name typed) [y/N] ` | `--production` |
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
| `Known hosts file (required): ` | sftp; `--known-hosts` |
| `Base directory (optional: empty = the login directory): ` | sftp; `--base-dir` |
| `Production? (each approval needs the profile name typed) [y/N] ` | `--production` |
| `Credentials: ...`, then the Vault path and the vault block | s3 and sftp only; the Vault path defaults to `secret/data/lockfile/<name>` |
| `Name (required) [files]: ` | `--name` |

### lockhttp

Only `Name (required) [web]: `. A lockhttp lock takes no credentials and no
`allowed_uids`: lea's gate reaches it, so lea must be installed.

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
lock shop-db declared: run lox up at a terminal to review and start it
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
| `--review` | the review of `lox up` shows this lock's whole profile and asks |
| `-v` | show cosign's and docker's own output (default: only when a step fails) |
| `--version vX.Y.Z` | the lock's release to pin (default: the latest) |
| `--file PATH` | the workspace's `lockfamily.yaml` |

`--instance` is not a `lox add` flag: it belongs to the locks' launchers. When
a project has two locks of one type, an agent on the host picks one with
`<lock> mcp --instance NAME` (see [lox-up.md](lox-up.md)).

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
a file whose vault block fails them. Nothing is started: run `lox up` to
review and apply it. A change of the CA restarts the locks with Vault.

## Removing a lock

```sh
lox remove NAME [--purge] [-v] [--file PATH]
```

It takes the lock out of `lockfamily.yaml`, shows `remove lock NAME (TYPE): its
console stops; ...`, and runs `lox up` with the short review of that lock
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
declared; run lox up to review and start it`. No profile is written and
nothing is started. `--image`, `--hub-image` and `--profile` belong to this
form only, the question flags to the guided one.
