#!/bin/sh
# Two workspaces on one runner (lockhub#172), end to end. They share the
# facade socket, $XDG_RUNTIME_DIR/lockhub/facade.sock: workspace A's hub
# serves it. Workspace B's lox run and lox up refuse to start, naming A
# (B's hub is never started, so it never loops on a socket it cannot
# serve), B's lox doctor reports it, and B's lox run --no-start never
# lists A's tickets. A's own lox run serves its hub. With its own
# XDG_RUNTIME_DIR, B runs beside A, each hub on its own socket.
#
#   ci/e2e/two-workspaces.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
top=$(realpath "$(mktemp -d)")
wsA=$top/a/projects
wsB=$top/b/projects
mkdir -p "$wsA" "$wsB"
down() {
	[ -f "$1/.lockfamily/up.json" ] || return 0
	p=$(ws_project "$1")
	docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
}
cleanup() {
	down "$wsA"
	down "$wsB"
}
trap cleanup EXIT INT TERM

# setup WS: a workspace with one lockfile lock and this commit's hub.
setup() {
	cd "$1"
	"$lox" add lockfile docs
	local_hub .lockfamily/lockfamily.yaml
	mkdir -p .lockfile && chmod 0700 .lockfile
	printf '[profiles.default]\nsource = "s3"\nbucket = "e2e-documents"\nregion = "eu-west-1"\ncredentials = "ask"\n' >.lockfile/config.toml
	chmod 0600 .lockfile/config.toml
}
# project WS: the compose project lox gives WS (before up.json exists).
project() { printf 'lockfamily-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-8)"; }

say "workspace A: lox up, its hub serves the shared facade socket"
setup "$wsA"
tty 'y\n' "$lox" up >"$top/upA.out" 2>&1 || { cat "$top/upA.out"; die "lox up (A) failed"; }
grep -q "up: project " "$top/upA.out" || { cat "$top/upA.out"; die "lox up (A) did not finish"; }
pA=$(ws_project "$wsA")
hub_is_local "$pA"
sock=$XDG_RUNTIME_DIR/lockhub/facade.sock
for i in $(seq 1 30); do [ -S "$sock" ] && break; sleep 1; done
[ -S "$sock" ] || die "A's hub does not serve $sock"

say "workspace B: lox add, then lox run refuses A's hub, naming A"
setup "$wsB"
pB=$(project "$wsB")
[ "$pB" != "$pA" ] || die "A and B share a compose project"
want="the facade socket $sock is served by the hub of workspace $wsA ($pA); stop it, or run this workspace with its own XDG_RUNTIME_DIR"
cd "$wsB"
python3 "$here/expect.py" 120 "$want" "" -- "$lox" run >"$top/runB.raw" 2>&1 || true
tr -d '\r' <"$top/runB.raw" >"$top/runB.out"
cat "$top/runB.out"
grep -qxF "lox run: $want" "$top/runB.out" || die "B's lox run does not refuse A's hub"
grep -q "hub up" "$top/runB.out" && die "B's lox run says hub up on A's hub"
grep -q "up: project " "$top/runB.out" && die "B's lox run started B's hub"

say "workspace B: lox up refuses too"
tty 'y\n' "$lox" up >"$top/upB.raw" 2>&1 && die "B's lox up started beside A's hub on the shared socket"
tr -d '\r' <"$top/upB.raw" >"$top/upB.out"
cat "$top/upB.out"
grep -qxF "lox up: $want" "$top/upB.out" || die "B's lox up does not refuse A's hub"
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$pB")" ] || die "B's hub was started (it would loop on a socket it cannot serve)"

say "lox doctor: B reports A's hub on the socket, A finds its own"
cd "$wsB"
"$lox" doctor >"$top/doctorB.out" 2>&1 && die "B's lox doctor passes with A's hub on the socket"
cat "$top/doctorB.out"
grep -qF "FAIL $want" "$top/doctorB.out" || die "B's lox doctor does not name A's hub"
grep -qF "hub answers on the facade socket" "$top/doctorB.out" && die "B's lox doctor reads A's queue"
cd "$wsA"
"$lox" doctor >"$top/doctorA.out" 2>&1 || true
grep -qF "ok   the hub on the facade socket is this workspace's" "$top/doctorA.out" || { cat "$top/doctorA.out"; die "A's lox doctor does not find its own hub"; }

say "lox run --no-start: B refuses A's hub, A serves it"
cd "$wsB"
python3 "$here/expect.py" 120 "$want" "" -- "$lox" run --no-start >"$top/nostartB.raw" 2>&1 || true
tr -d '\r' <"$top/nostartB.raw" >"$top/nostartB.out"
grep -qF "lox run: $want" "$top/nostartB.out" || { cat "$top/nostartB.out"; die "B's lox run --no-start serves A's hub"; }
cd "$wsA"
python3 "$here/expect.py" 120 "hub up" "<pause>qq" -- "$lox" run --no-start >"$top/nostartA.raw" 2>&1 || { tr -d '\r' <"$top/nostartA.raw"; die "A's lox run --no-start failed"; }
tr -d '\r' <"$top/nostartA.raw" | grep -qF "is served by" && die "A's lox run refuses its own hub"

say "B with its own XDG_RUNTIME_DIR: both hubs up, each on its own socket"
runB=$top/runB
mkdir -p "$runB" && chmod 700 "$runB"
cd "$wsB"
tty 'y\n' env XDG_RUNTIME_DIR="$runB" "$lox" up >"$top/upB2.out" 2>&1 || { cat "$top/upB2.out"; die "lox up (B, own runtime dir) failed"; }
grep -q "up: project $pB" "$top/upB2.out" || { cat "$top/upB2.out"; die "lox up (B) did not finish"; }
hub_is_local "$pB"
for i in $(seq 1 30); do [ -S "$runB/lockhub/facade.sock" ] && break; sleep 1; done
XDG_RUNTIME_DIR=$runB "$lox" doctor >"$top/doctorB2.out" 2>&1 || true
grep -qF "ok   the hub on the facade socket is this workspace's" "$top/doctorB2.out" || { cat "$top/doctorB2.out"; die "B's lox doctor does not find its own hub on its own socket"; }
cd "$wsA"
"$lox" doctor >"$top/doctorA2.out" 2>&1 || true
grep -qF "ok   the hub on the facade socket is this workspace's" "$top/doctorA2.out" || { cat "$top/doctorA2.out"; die "A's hub lost the shared socket"; }

say "PASS: a second workspace never serves the first one's hub"
