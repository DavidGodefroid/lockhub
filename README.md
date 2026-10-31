# lockhub

The approval hub of the [Lock Family](https://github.com/DavidGodefroid/lockfamily)
(locksql, lockmq, lockfile, lockhttp).

Each Lock keeps a human between an AI agent and a production system. With the
hub, a Lock no longer needs a human at its own terminal: it sends an approval
ticket (a masked screen of the request) to the hub, the human answers from a
facade (a terminal with `lox approve`, the lea deck, Slack, Telegram or a
paired phone), and the hub signs the decision. The Lock executes only on a signed
decision bound to the exact plan that was approved.

The hub never runs a request, never sees its results, and never sees values in
clear.

Chat facades (Slack, Telegram) show masked screens only and answer only non-
production reads and writes; production tickets and policy loosening are
answered in the terminal, the deck or a paired phone, unlocks in the terminal
or the deck (`hub.Decide`, `internal/route`). Approving a production ticket
needs its instance name typed, in the terminal, the deck and on the phone
alike (the hub checks it). A
workspace's `lockfamily.yaml` can narrow this routing, never widen it.

In `lox approve`, `o` (or Ctrl-O then Enter, where the terminal passes it:
not on macOS, which keeps ^O) shows a ticket's clear values:
the terminal sends an ephemeral key signed by its facade key (which every lock
pins, written by `lox up`), the lock seals the clear screen to it and signs
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
- `lox`: the host CLI (`lox up`, `lox approve`, `lox audit verify`, …),
  shipped in the same image and release, and as static archives
  (`lox_X.Y.Z_<os>_<arch>.tar.gz`, cosign-signed `checksums.txt`) that the
  Lock Family [install.sh](https://github.com/DavidGodefroid/lockfamily)
  installs into `~/.local/bin`.

The ticket and decision formats live in
[lockkit](https://github.com/DavidGodefroid/lockkit) (`ticket` package), shared
with every Lock.

[docs/lox-up.md](docs/lox-up.md) is the contract between `lox up` and lea;
[docs/design-notes.md](docs/design-notes.md) records where the code
deliberately departs from the hub's design plan.

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
locks:
  crm-prod:
    type: locksql
    image: ghcr.io/davidgodefroid/locksql@sha256:…
    devices: true                        # pins the paired phones (lockkit ≥ v0.4.0)
    reveal: true                         # Ctrl-O reveals on tty/deck (lockkit ≥ v0.5.0)
```

A lock without `devices: true` pins no phone: `lox up` routes it away from
mobile, and `seal_clear` and `require_device` do not apply to it (it takes the
hub's approvals from the other facades as before). The review names what each
lock does. Its image must take `--devices-file` (lockkit v0.4.0 or later).
For a lockhttp lock, lea's gate pins the devices, which `lox up` hands it in
`.lockfamily/up.json` (lockhttp v0.4.0 or later, lea v0.3.0 or later); lea
runs its standalone gate instead, and says why, when it cannot.
Likewise `reveal: true` pins the terminal's and the deck's facade keys in the
lock (`--facade-keys-file`, lockkit v0.5.0 or later), so `o`/Ctrl-O in `lox
approve` or lea's deck can show its clear screen; without it the lock refuses
reveals.

**Exposure.** `lox up` publishes the mobile listener on `127.0.0.1:8444`
only. The phone reaches it through a TLS reverse proxy or tunnel that you run
on the host and that forwards `origin` to that port: Tailscale Serve
(`tailscale serve --bg --https=443 http://127.0.0.1:8444`), Caddy, cloudflared,
… WebAuthn needs https, and the origin's host is the WebAuthn relying party.
The listener serves the web app and `/m/v1` only: never the lock API, never
the facade socket. The hub trusts no forwarded header; the origin comes from
`lockfamily.yaml`. The hub joins its own `mobile-hub` network for that port
(a bridge, so the hub container has a route out there; the lock API stays on
the internal `lockhub` network, which agents never join).

**Pairing.** `lox mobile pair --name phone` prints a one-time code (5 min,
wrong codes cancel it). Open the origin on the phone, enter the code,
register; then compare the fingerprint the phone shows (computed from its own
keys) with the one at the terminal and answer `y`. Run `lox up` to pin the
phone at the locks: `lox up` reviews the device like any key and recreates
the locks with it. `lox mobile list`, `lox mobile revoke NAME` (then `lox
up`). The confirmation is only as strong as the facade socket: whoever can
open it (your host account, never an agent container) can confirm a device.
`require_device` needs a paired device: `lox up` refuses it otherwise, so
revoking the last phone leaves the locks pinning it (the hub refuses it) until
you remove `require_device` and run `lox up`. `lox mobile pair` checks the
phone's origin against the one the last `lox up` applied.

**Routing.** The phone answers every risk class but `unlock` (no facade types
secrets yet); production tickets ask for the instance name; `hub.routing`
narrows it per instance.

**Limits.** The web app's code comes from the hub. A hub that serves
malicious code could ask you to verify yourself for another pending ticket of
the same lock than the one it shows, and could read the clear values sealed to
the phone while they are on screen. Locks still refuse anything not signed by
the phone over a ticket they signed themselves. A synced passkey also lives in
your platform account.

**Notifications.** Off by default: the app long-polls the queue while it is
open. With `hub.mobile.push: true`, the hub wakes the paired phones with Web
Push when a ticket they may answer (the same routing as the queue) becomes
pending: tap "Enable notifications" in the app, allow notifications, and the
browser's push subscription is recorded for that device (at most 4 per device;
dropped by `lox mobile revoke`, or when the push service answers 404/410).
Pushes carry no payload: the service worker shows "A Lock approval is pending"
and the app reads the ticket from the hub as usual. The hub signs each push
with VAPID (RFC 8292; its P-256 key `vapid.key` is created once in the hub's
data directory, 0600) and POSTs only to the known push services
(`fcm.googleapis.com`, `updates.push.services.mozilla.com`, `*.push.apple.com`,
`wns2-*.notify.windows.com`, https on the default port, public addresses only
(no private, loopback, CGNAT, NAT64 or other special-purpose ranges), no
redirects), at most one round per 30 s (`Topic` coalesces pushes queued for an
offline phone, `TTL` 30 min). The hub logs only the push service's host, never
an endpoint. `lox up` reviews the change and gives the hub its `egress-hub`
network for it. That network gives the hub general outbound access, as with
the chat facades: the restriction to the push services above is enforced by
the hub's code, not by the network. Signing out of the app keeps the device's
push subscription (it belongs to the device, not to the session): tap "Disable
notifications" before signing out to stop them on that phone, or revoke the
device. What remains exposed: the push service (Google, Mozilla, Apple,
Microsoft) learns when a ticket waits and which subscription is woken, though
nothing of the ticket.

```yaml
hub:
  mobile:
    origin: https://hub.example.ts.net
    push: true
```

## Build

```sh
go test ./...
docker build -t lockhub .
docker run --rm --read-only --cap-drop ALL lockhub version
```

## License

Apache-2.0, see [LICENSE](LICENSE).
