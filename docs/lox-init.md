# lox init

`lox init` sets up the Lock Family in a project in one command:

```sh
cd ~/projects/shop
lox init
```

It finds what the project's files say about its data sources, proposes one
lock per source, runs each lock's launcher to write its profile and the agent
files, declares the locks in `.lockfamily/lockfamily.yaml`, runs `lox up`
(whose review you confirm, unchanged) and attaches to each console that
started so that you answer its questions there. It ends with:

```
Run `lea` (or `claude` + `lox approve`).
```

## Steps

1. **Prerequisites.** Docker must answer and cosign must be installed (`lox
   add` and `lox up` verify every image's signature); otherwise `lox init`
   prints the install command for your system and stops. lea and each lock's
   launcher (`locksql`, `lockmq`, `lockfile`, `lockhttp`) are looked up on
   `PATH`: the locks run without lea, lockhttp needs it, and a source whose
   launcher is missing is skipped with how to install it.
2. **Detection**, read only, project files only: `.env` and `.env.*`,
   `compose*.yaml` / `docker-compose*.yaml` (and `.yml`) at the project root,
   and `config/` (yaml, yml, toml, json, env, ini, conf, properties; three
   levels deep). No link is followed and no file over 256 KiB is read. It
   finds PostgreSQL, MySQL, MariaDB and RabbitMQ:
   - compose services by image, their published ports and their
     `POSTGRES_*`, `MYSQL_*`, `MARIADB_*` and `RABBITMQ_DEFAULT_*` user,
     database and vhost (`${VAR:-default}` resolved from `.env`);
   - `DATABASE_URL`-style URLs (`DATABASE_URL`, `*_DATABASE_URL`, `DB_URL`,
     `POSTGRES_URL`, `MYSQL_URL`, `RABBITMQ_URL`, `AMQP_URL`, ...) and host
     keys (`DB_HOST` with `DB_CONNECTION`, `PGHOST`, `POSTGRES_HOST`,
     `MYSQL_HOST`, `RABBITMQ_HOST`) in `.env`;
   - source URLs in `config/`.

   A source on this machine (a loopback host, or a compose service with a
   published port) is given to the lock as `host.docker.internal` at its
   published port: the console runs in a container, where `localhost` is
   itself (lockmq refuses a loopback `--url`). A compose service whose port
   is not published is shown with a note and skipped in auto mode: a
   console cannot reach the compose network.
3. **Mode.**
   - **Auto** (the default): one lock per detected source. It asks only the
     environment (dev or prod), where passwords come from (each console asks
     at its start, or Vault, with a Vault path per lock) and, for a
     database whose files say nothing about TLS, its TLS mode (proposed:
     `disable` for a database on this machine, `verify-full` otherwise and
     for production).
   - **Manual** (`--manual`, or `m`): a checklist of lea, locksql, lockmq,
     lockfile, lockhttp and locklog, with the locks lockfamily.yaml
     declares. A row that cannot be checked is greyed with the reason:
     lockfile is Linux only, lockhttp needs lea, a launcher is not
     installed, locklog is not available yet. Each lock checked is asked its
     target (a detected source offered first); a declared lock unchecked is
     removed from lockfamily.yaml (its profile stays in the lock's
     directory).
4. **Plan.** What `lox init` will run is shown, and nothing is written
   before your `y` (or `--yes`): detection never activates a lock by
   itself.
5. **Apply**, for each lock, from the project root:

   ```
   <lock> profile add --non-interactive --json --project ROOT --profile NAME [--production] [--credentials ask|vault --vault-path P] <target flags>
   <lock> init claude
   <lock> doctor --fix --yes --json   (lockfile: <lock> doctor --json)
   lox add <lock> NAME --profile NAME
   ```

   The doctor's repairs and what still fails are shown; a failure never
   stops `lox init` (before `lox up` the console is not running, so some
   checks fail or warn). See [The doctor](#the-doctor) for when it runs
   without `--fix`. A profile already in the lock's config (`exists`) is kept as it is. A lock
   whose verb fails is not declared; its error (or, with no JSON, its
   stderr) is shown and the others go on. Then `lox up` shows the change for
   your review, and each console that started (or restarted) is attached:
   it asks its policy on a first start and the password it does not read
   from Vault, masked. Detach with Ctrl-P Ctrl-Q once it says Listening.

When lea is found, each locksql, lockmq and lockfile lock gets your uid in
`allowed_uids` (lea's agents run as it; see [lox-up.md](lox-up.md)).

## The doctor

`lox init` runs each lock's `doctor --fix --yes --json` (lockkit GUIDE.md
§14), with these exceptions, which the plan states:

| Lock | `doctor --fix` | What it repairs |
|---|---|---|
| locksql | v0.13.1 or later, launcher and image | `.locksql/` as `lox up` reads it (yours, no group or other write); it also wires your installed agents for your account |
| lockmq | v0.6.1 or later, launcher and image | `.lockmq/` as `lox up` copies it |
| lockhttp | any release with the verbs (v0.7.0) | `chmod go-w` on the policy |
| lockfile | never | its only repair wires every installed agent for your account, which `lox up` does not need: run `lockfile doctor --fix` yourself for that |

locksql up to v0.13.0 and lockmq up to v0.6.0 gave the lock's directory to
the console account in `doctor --fix`, after which `lox up` refused to copy
the profile (it reads only your own files). `lox init` asks `<lock>
version` once per lock type (`<lock> launcher V (image REF)`, then the
image's `<lock> vV`): with a launcher or an image older than the fixed
release, or versions it cannot read, it runs `<lock> doctor --json`
instead and says to update the lock, then run `<lock> doctor --fix`. A
launcher run from a clone (`launcher dev`) is judged by its image.

## Secrets

`lox init` never asks for, reads or writes a secret:

- detection skips every key named like a secret (`*PASSWORD*`, `*_PASS`,
  `*SECRET*`, `*TOKEN*`, `*_KEY`, ...) before its value is kept, and keeps
  only the user name of a URL, never its password; its notes and warnings
  name files and keys, never values;
- `profile add` takes no secret (`--credentials ask|vault`), and a value
  typed in manual mode that embeds a password is refused without being
  echoed;
- the console asks for the password at its start, masked, under `lox
  attach`.

## Re-running

`lox init` starts from the existing `.lockfamily/lockfamily.yaml`: a source
whose lock is declared already (same type and profile) is kept and nothing
runs for it; a new source gets its lock. Changes still go through the `lox
up` review. A lock whose type's profile directory changed (a profile added
to `.locksql/config.toml`, say) is restarted by `lox up` and asks its
password again; `lox init` attaches to it.

## Non-interactive use

```sh
lox init --yes [--prod] [--credentials vault --vault-path INSTANCE=PATH ...] [--tls MODE] [--no-attach]
```

`--yes` runs auto mode with the flags and defaults. `lox up`'s review still
asks at the terminal: without one, `lox init` stops once lockfamily.yaml is
written and says to run `lox up`. `--manual` is interactive only.

## Known limitations

- Auto mode detects databases and RabbitMQ only: lockfile and lockhttp are
  set up in manual mode.
- One lock per type is set up per manual run; run `lox init` again for
  another.
