# lockhub

The approval hub of the [Lock Family](https://github.com/DavidGodefroid/lockfamily)
(locksql, lockmq, lockfile, lockhttp).

Each Lock keeps a human between an AI agent and a production system. With the
hub, a Lock no longer needs a human at its own terminal: it sends an approval
ticket (a masked screen of the request) to the hub, the human answers from a
facade (a terminal with `lock approve`, the lea deck, Slack, Telegram or a
paired phone), and the hub signs the decision. The Lock executes only on a signed
decision bound to the exact plan that was approved.

The hub never runs a request, never sees its results, and never sees values in
clear.

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

## Mobile facade

A phone can approve tickets through an installable web app the hub serves.
Each decision taken on the phone is signed by the phone itself (a WebAuthn
credential, user verification required) over the decision and the lock's own
signed ticket, and every lock checks that signature against the phones it
pins: the hub's key alone cannot make a decision pass for one taken on the
phone. With `seal_clear`, each lock also seals its clear screen to the
paired phones (X25519, AES-256-GCM): the hub relays ciphertext only.

```yaml
hub:
  facades: [tty, deck, mobile]
  mobile:
    origin: https://hub.example.ts.net   # what the phone opens
    port: 8444                           # host loopback port (default)
    seal_clear: true                     # clear values, end to end to the phone
    require_device: [prod-write]         # locks refuse other approvals of these
```

**Exposure.** `lock up` publishes the mobile listener on `127.0.0.1:8444`
only. The phone reaches it through a TLS reverse proxy or tunnel that you run
on the host and that forwards `origin` to that port: Tailscale Serve
(`tailscale serve --bg --https=443 http://127.0.0.1:8444`), Caddy, cloudflared,
… WebAuthn needs https, and the origin's host is the WebAuthn relying party.
The listener serves the web app and `/m/v1` only: never the lock API, never
the facade socket. The hub trusts no forwarded header; the origin comes from
`lockfamily.yaml`.

**Pairing.** `lock mobile pair --name phone` prints a one-time code (5 min,
wrong codes cancel it). Open the origin on the phone, enter the code,
register; then compare the fingerprint the phone shows (computed from its own
keys) with the one at the terminal and answer `y`. Run `lock up` to pin the
phone at the locks: `lock up` reviews the device like any key. `lock mobile
list`, `lock mobile revoke NAME`.

**Routing.** The phone answers every risk class but `unlock` (no facade types
secrets yet); production tickets ask for the instance name; `hub.routing`
narrows it per instance.

**Limits.** The web app's code comes from the hub. A hub that serves
malicious code could ask you to verify yourself for another pending ticket of
the same lock than the one it shows, and could read the clear values sealed to
the phone while they are on screen. Locks still refuse anything not signed by
the phone over a ticket they signed themselves. A synced passkey also lives in
your platform account. Notifications: none yet; keep the app open (it
long-polls).

## Build

```sh
go test ./...
docker build -t lockhub .
docker run --rm --read-only --cap-drop ALL lockhub version
```

## License

Apache-2.0, see [LICENSE](LICENSE).
