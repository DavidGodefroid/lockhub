# Networks and address pools

`lox run` gives a workspace several Docker networks: the hub's own
(`lockhub`, internal), the hub's route out when a chat facade or mobile push
needs one (`egress-hub`), the mobile listener's (`mobile-hub`), and per lock:

| lock | networks |
|---|---|
| with an allowlist (a database, a broker, a remote file store, …) | `locknet-<name>` (internal), `gwlink-<name>` (internal, between its gateway's two halves), `out-<name>` (the gateway's route out) |
| with no endpoint (lockfile local, locklog with local sources) | `locknet-<name>` (internal), or the hub's alone |
| lockhttp | `egress-<name>` (its own policy's route out) |
| with `networks: [shop]` (lockhub#194) | besides the above, its gateway's third half `gwnet-<name>` joins the existing network `shop` (declared `external`, never created nor removed); `out-<name>` only when an endpoint is reached through it |

[lox-run.md](lox-run.md#egress-each-lock-reaches-its-reviewed-endpoints-only)
says why each one exists, and
[lox-run.md](lox-run.md#a-database-on-a-docker-network-networks) what
`networks` joins, which endpoints go through it (dotless host names) and its
limits. A joined network keeps its own subnet: the pool below is not used
for it.

## Each network's own small subnet

Left to itself, Docker takes every new network's subnet from its **default
address pools**, a whole /16 or /20 each. A stock daemon has 31 of them
(`172.17.0.0/16` to `172.31.0.0/16`, then `192.168.0.0/16` in /20s). A
workspace of six locks used 15 before lockhub#175; a second workspace, lea
and a few compose projects later, Docker refused every new network:

```
Error response from daemon: all predefined address pools have been fully subnetted
```

So `lox run` sets each network's subnet in the compose file (`ipam.config`)
from a range of its own, the workspace's **pool**: a `/24` for `lockhub` (the
hub, every lock and lea's gates) and a `/28` for every other network (two or
three containers each). The default pool is `10.123.0.0/16`: room for about
100 workspaces of ten locks, and none of Docker's default address pools is
touched.

Before each run, `lox run` reads the subnets of every network the engine has
(`docker network inspect`): a network of the workspace keeps its subnet while
it is still free and of the right size, so nothing is recreated; a new one
takes the pool's first free block. Two workspaces never overlap: each one's
networks are taken subnets for the other. A workspace made before lox set
subnets moves its networks into the pool on its first `lox run` (compose
recreates them, and the containers on them).

If the pool collides with a network of yours (a VPN or a LAN on
`10.123.0.0/16`: the locks could not reach its hosts), pick another private
range in `lockfamily.yaml`:

```yaml
network:
  pool: 10.200.0.0/16     # private IPv4, /8 to /24
```

The review shows `network pool 10.200.0.0/16`; the next `lox run` moves the
networks.

## When the engine refuses a network

Another program may take a subnet between `lox run`'s read and compose's
create, or a pool may be full. `lox run` then stops with:

```
the engine refused a network of this workspace for its addresses (...): nothing new was started; lox run again picks free subnets, ...
```

It removes the networks of the workspace that compose made before it stopped
and no container uses, and applies nothing: the next `lox run` reviews the
same change again. A pool with no free block left says so before anything
starts (`no free subnet left in the network pool`): remove unused networks
(`docker network prune`) or set a larger `network.pool`.

## lox doctor

`lox doctor` checks both ranges:

```
ok   networks: pool 10.123.0.0/16 holds a subnet for each network the workspace may need (27)
warn networks: the engine's default address pools have 2 of 31 subnets free: lea and other compose projects soon fail with ...
```

The first line warns when the next `lox run` could not place its networks.
The second counts the free subnets of the engine's default address pools
(the ones `default-address-pools` in `/etc/docker/daemon.json` sets, or
Docker's own), which lea (`lea-internal-<id>`, `lea-egress`) and your other
compose projects still take theirs from; it warns below 4. Podman has pools
of its own: the second line is left out.

## default-address-pools

To give Docker room for many more networks, split a large private range into
small subnets, in `/etc/docker/daemon.json`:

```json
{
  "default-address-pools": [
    {"base": "10.200.0.0/16", "size": 24}
  ]
}
```

That is 256 networks of 254 addresses. Pick a range that no network of yours
and no `network.pool` uses, then restart Docker (`sudo systemctl restart
docker`): it stops every container, and the networks that exist keep their
subnets; only new ones take the new pools. Docker Desktop: Settings, Docker
Engine, the same JSON.
