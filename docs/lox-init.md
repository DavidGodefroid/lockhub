# lox init

`lox init` starts the hub of a project. It asks nothing and sets no lock
up: each source is added afterwards, one at a time, with
[`lox add`](lox-add.md).

```sh
cd ~/projects        # with lea: its projects directory; with claude: the project
lox init
```

Where to run it: with lea, in lea's projects directory, not a project
inside it (lea reads `.lockfamily/up.json` only at the root of its projects
directory); with `claude` on the host, in the project or a parent (the
launchers walk up from the current directory to the nearest
`.lockfamily/up.json`). With lea there is nothing to run: on its first
start, when its projects directory has no `.lockfamily/up.json`, lea runs
`lox init` there itself.

It ends with:

```
Ready. Run `lea` (or `claude` + `lox approve`). Add a source: `lox add locksql|lockmq|lockfile|lockhttp|locklog|lockssh`.
```

## Flags

| Flag | Meaning |
|---|---|
| `--file PATH` | the workspace's `lockfamily.yaml` (default: `.lockfamily/lockfamily.yaml` of the current directory) |
| `--hub-image REF` | the hub's image for a new `lockfamily.yaml`, `ghcr.io/davidgodefroid/lockhub@sha256:<digest>` (default: the latest signed release's); an existing file keeps its hub image (`lox run --pin` changes it) |
| `--review` | `lox run` shows everything and asks, even for a hub with no lock (needs a terminal) |
| `-v` | show cosign's and docker's own output (default: only when a step fails) |

## Steps

1. **Prerequisites.** Docker must answer and cosign v2.5.0 or later must
   be installed (`lox add` and `lox run` verify every image's signature);
   otherwise `lox init` prints the install (or upgrade) command for your
   system and stops with nothing done. The screen shows cosign's version;
   `lox doctor` checks it too. Signatures are checked in both formats:
   the legacy one and the sigstore bundle format, in which cosign v3
   signs (lockfile's images). cosign v3 reads both; with cosign v2, lox
   retries a verify that finds no signature with `--new-bundle-format`
   (same identity and issuer), which cosign has since v2.5.0. lea and each lock's launcher (`locksql`, `lockmq`,
   `lockfile`, `lockhttp`, `locklog`, `lockssh`) are looked up on `PATH`: the locks run without
   lea, lockhttp needs it, and a missing launcher is listed with where to
   install it.
2. **Hints**, read only, project files only: `.env` and `.env.*`,
   `compose*.yaml` / `docker-compose*.yaml` (and `.yml`) at the project root,
   and `config/` (yaml, yml, toml, json, env, ini, conf, properties; three
   levels deep). No link is followed and no file over 256 KiB is read. It
   finds PostgreSQL, MySQL, MariaDB and RabbitMQ, the log stores locklog
   reads (a Loki, Elasticsearch or OpenSearch compose service, or a
   `LOKI_URL`, `LOKI_ADDR`, `ELASTICSEARCH_URL`, `ES_URL`, `OPENSEARCH_URL`...
   in `.env*`), and on Linux this host's own logs (`/var/log/journal`,
   `/run/log/journal`, `/var/log`), and prints one line for each with the
   files that name it (never a key's value) and the `lox add` that serves it
   (`lox add locklog` for the logs), and the SSH hosts of your
   `~/.ssh/config` lockssh can serve (a plain `Host` block, its `HostName`,
   `User` and `Port` only: no pattern, no host behind a bastion, no IP
   address; `lox add lockssh`). Detection skips every key named like a secret
   (`*PASSWORD*`, `*_PASS`, `*SECRET*`, `*TOKEN*`, `*_KEY`, ...) and keeps
   only the user name of a URL, never its password. A source on this machine
   is shown as `host.docker.internal` at its published port: the console
   runs in a container, where `localhost` is itself.
3. **The hub.** With no `lockfamily.yaml` yet, `lox init` writes one with the
   hub alone, pinned by digest to lockhub's latest signed release.
4. **The start (what `lox run` does before it serves decisions).** With no lock declared and none applied before, it asks no
   question: the hub alone cannot reach a credential. A hub that already
   runs, from a file that was there, with nothing changed since the last
   `lox run`, is left alone.

Nothing is written for a hint: detection never activates a lock by itself.
`lox add TYPE` offers a hint's values as the defaults of its questions.

## Re-running

`lox init` starts from the existing `.lockfamily/lockfamily.yaml`. Locks it
declares are kept as they are and listed; `lox run` reviews them like any
change. Without a terminal, `lox init` stops before the start when the file
declares locks (or when locks applied before would be removed) and says to
run `lox run` at a terminal. `--review` always runs the start and asks.

Decisions are served by `lox run`, in a terminal of its own outside the agent
([lox-run.md](lox-run.md)).

## Secrets

`lox init` never asks for, reads or writes a secret. Its notes and warnings
name files and keys, never values.
