# Getting started

The first run, with or without lea, where to run each command, and what
ships in a release.

## First run

```sh
brew trust davidgodefroid/tap
brew install davidgodefroid/tap/lockfamily   # lea, lox and the Locks' launchers
lea                                          # starts lea; it runs no lox command
```

Then, in lea's projects directory, run `lox init` — or go straight to
`lox add locksql` — and keep `lox run` open in a terminal of its own: it
serves the decisions. Later, one source at a time, in that directory:

```sh
lox add locksql      # or lockmq, lockfile, lockhttp, locklog
lea stop             # a lock added while lea runs reaches it at lea's next start
lea
```

Without lea (your agent on the host: claude, codex, gemini, …): `lox init` in the project, then
`lox add locksql`. Either way, keep `lox run` open in a terminal of its own:
it serves the decisions.

`lox init` asks nothing. It checks the prerequisites (Docker, cosign, lea,
the locks' launchers), lists the data sources the project's files name as
hints (`.env*`, `compose*.yaml`, `config/`: read only, never a secret),
writes a `lockfamily.yaml` with the hub alone and starts it, as `lox run` does. With no lock
declared yet, that first start asks no question (`--review` shows
everything and asks). It ends with a pointer to `lea` and to `lox add`.

`lox add TYPE` sets one source up, guided and applied at once: its
questions, the lock's `profile add`, `init claude` and `doctor`, the
declaration in `lockfamily.yaml`, a short review of that lock as it starts, and the
console's own questions at your terminal. A failure, a `n` or Ctrl-C keeps
nothing. Run it again for the next source; `lox remove NAME` takes one out.
See [lox-add.md](lox-add.md).

Where to run them: with lea, in lea's projects directory, not a project
inside it (lea reads `.lockfamily/up.json` only at the root of its projects
directory); with an agent on the host, in the project or a parent (the
launchers walk up from the current directory to the nearest
`.lockfamily/up.json`). A lock added while lea runs reaches it at lea's next
start: `lea stop`, then `lea`.

See [lox-init.md](lox-init.md) for `lox init`.

[lox-run.md](lox-run.md) is the contract between `lox run` and lea;
[design-notes.md](design-notes.md) records where the code
deliberately departs from the hub's design plan.

## What a release ships

Early development. This repository holds:

- `lockhub`: the hub server (`lockhub serve`), shipped as a cosign-signed image
  `ghcr.io/davidgodefroid/lockhub`, pinned by digest;
- `lox`: the host CLI (`lox run`, `lox approve`, `lox audit verify`, …),
  shipped in the same image and release, and as static archives
  (`lox_X.Y.Z_<os>_<arch>.tar.gz`, cosign-signed `checksums.txt`) that the
  Lock Family [install.sh](https://github.com/DavidGodefroid/lockfamily)
  installs into `~/.local/bin`. Each release tag also bumps the `lox` formula
  of the [Homebrew tap](https://github.com/DavidGodefroid/homebrew-tap):

  ```sh
  brew trust davidgodefroid/tap
  brew install davidgodefroid/tap/lox
  ```

  Homebrew asks you to trust a third-party tap once before it loads its
  formulas; trusting the whole tap also covers dependencies from it.

The ticket and decision formats live in
[lockkit](https://github.com/DavidGodefroid/lockkit) (`ticket` package), shared
with every Lock.
