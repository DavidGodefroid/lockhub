# lockhub

The approval hub of the [Lock Family](https://github.com/DavidGodefroid/lockfamily)
(locksql, lockmq, lockfile, lockhttp).

Each Lock keeps a human between an AI agent and a production system. With the
hub, a Lock no longer needs a human at its own terminal: it sends an approval
ticket (a masked screen of the request) to the hub, the human answers from a
facade (a terminal with `lock approve`, the lea deck, later chat and mobile
facades), and the hub signs the decision. The Lock executes only on a signed
decision bound to the exact plan that was approved.

The hub never runs a request, never sees its results, and never sees values in
clear.

In `lock approve`, `o` (or Ctrl-O then Enter, where the terminal passes it:
not on macOS, which keeps ^O) shows a ticket's clear values:
the terminal sends an ephemeral key signed by its facade key (which every lock
pins, written by `lock up`), the lock seals the clear screen to it and signs
the answer, and only the terminal opens it. The hub relays ciphertext, and
never offers this on Slack, Telegram or mobile. An expired ticket is listed for
re-approval (`r`, approve again): the lock asks again, and when nothing changed
in the plan since then (and it is not for production) the hub approves it in
that one step; otherwise the new ticket shows what changed and waits for `y`.

Threat model of the facade socket: whoever can open it is the host's human (one
user). The facade name a client sends for `decide` and `renew` is self-declared
by that same user; a reveal is bound by the facade's own signed key, which the
lock checks against the key it pinned.

## Status

Early development. This repository holds:

- `lockhub`: the hub server (`lockhub serve`), shipped as a cosign-signed image
  `ghcr.io/davidgodefroid/lockhub`, pinned by digest;
- `lock`: the host CLI (`lock up`, `lock approve`, `lock audit verify`, …),
  shipped in the same image and release, and as static archives
  (`lock_X.Y.Z_<os>_<arch>.tar.gz`, cosign-signed `checksums.txt`) that the
  Lock Family [install.sh](https://github.com/DavidGodefroid/lockfamily)
  installs into `~/.local/bin`.

The ticket and decision formats live in
[lockkit](https://github.com/DavidGodefroid/lockkit) (`ticket` package), shared
with every Lock.

## Build

```sh
go test ./...
docker build -t lockhub .
docker run --rm --read-only --cap-drop ALL lockhub version
```

## License

Apache-2.0, see [LICENSE](LICENSE).
