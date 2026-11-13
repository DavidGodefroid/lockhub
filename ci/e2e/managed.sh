#!/bin/sh
# The company's managed file under lox run (lockhub#179), end to end, with
# the released locksql and lockmq images lox add pins and this commit's
# hub. sudo places a root-owned /etc/lockfamily/managed.toml (removed at
# the end):
#  1. [locksql.bounds] tier = "write", no [lockmq] section; the workspace's
#     locksql profile is at tier = "ddl": lox up says locksql is not
#     started, citing the bound (locksql managed check, in its image), and
#     lockmq starts with the managed file mounted read-only at
#     /etc/lockfamily (the host's bytes; a write fails).
#  2. [lox] egress allows *.allowed.internal:5432 and the lockmq endpoint;
#     the locksql profile names db.other.internal:5432: locksql is not
#     started, citing lox.egress.
#  3. [lox] allow_no_upgrade = false: lox run --no-upgrade exits 3 before
#     it starts anything.
#
#   ci/e2e/managed.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
mdir=/etc/lockfamily
[ -e "$mdir" ] && die "$mdir exists on this runner: the script only removes what it creates"
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	sudo rm -rf "$mdir"
}
trap cleanup EXIT INT TERM

# managed BODY: the machine's managed file, root's, 0644, in a root-owned
# 0755 directory.
managed() {
	sudo install -d -o root -g root -m 0755 "$mdir"
	printf '%s' "$1" | sudo tee "$mdir/managed.toml" >/dev/null
	sudo chown root:root "$mdir/managed.toml"
	sudo chmod 0644 "$mdir/managed.toml"
}
# up OUT: lox up at a terminal, its review answered yes.
up() {
	tty 'y\n' "$lox" up >"$1.raw" 2>&1 || { cat "$1.raw"; die "lox up failed"; }
	tr -d '\r' <"$1.raw" >"$1"
	cat "$1"
	grep -q "up: project " "$1" || die "lox up did not finish"
}

say "lox add locksql crm, lox add lockmq events: pinned to their latest signed releases"
"$lox" add locksql crm
"$lox" add lockmq events
local_hub .lockfamily/lockfamily.yaml
cat .lockfamily/lockfamily.yaml
mkdir -p .locksql .lockmq
printf '[profiles.p]\nengine = "postgres"\nhost = "db.allowed.internal"\nport = 5432\nuser = "ro"\ndatabase = "app"\ntls = "disable"\ntier = "ddl"\n' >.locksql/config.toml
printf '[profiles.e]\nurl = "http://mq.e2e.internal:15672"\nvhosts = ["e2e"]\nuser = "mqro"\ntier = "read"\n' >.lockmq/config.toml
chmod 0644 .locksql/config.toml .lockmq/config.toml

say "1. [locksql.bounds] tier = write: locksql not started, lockmq started"
managed 'version = 1
organisation = "E2E Corp"

[locksql.bounds]
tier = "write"
'
"$lox" managed show | tee show.out
grep -qx "organisation: E2E Corp" show.out || die "lox managed show does not read the file"
up up1.out
hub_cosigned up1.out
grep -qF "lock crm: not started: blocked by company policy: locksql.bounds.tier = write (profile p: tier = ddl)" up1.out ||
	die "locksql is not refused with the bound"
grep -qF "lock events: started" up1.out || die "lockmq did not start"
grep -qF "lock crm: started" up1.out && die "locksql started"
grep -q "^managed: E2E Corp sha256:" up1.out || die "no managed line in the review"
p=$(ws_project "$ws")
hub_is_local "$p"

say "the lockmq console reads the host's managed file, read-only"
c="$p-lock-events-1"
for i in $(seq 1 30); do [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && break; sleep 1; done
[ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] || die "$c is not running"
want=$(sudo sha256sum "$mdir/managed.toml" | cut -d' ' -f1)
got=$(docker exec "$c" sha256sum /etc/lockfamily/managed.toml | cut -d' ' -f1)
[ "$got" = "$want" ] || die "the container's managed.toml ($got) is not the host's ($want)"
docker exec "$c" sh -c 'echo x >>/etc/lockfamily/managed.toml' 2>/dev/null && die "the container wrote its managed.toml"
docker exec -u 0 "$c" sh -c 'echo x >>/etc/lockfamily/managed.toml' 2>/dev/null && die "root in the container wrote its managed.toml"
docker inspect "$p-lock-crm-1" >/dev/null 2>&1 && die "a container of the refused locksql exists"
jq -e '.crm | startswith("blocked by company policy: locksql.bounds.tier")' "$XDG_STATE_HOME/lockfamily/$p/not-started.json" >/dev/null ||
	die "not-started.json does not keep the reason"

say "2. [lox] egress: locksql on db.other.internal:5432 is not started"
sed -i 's/db.allowed.internal/db.other.internal/' .locksql/config.toml
managed 'version = 1
organisation = "E2E Corp"

[lox]
egress = ["*.allowed.internal:5432", "mq.e2e.internal:15672"]
'
up up2.out
grep -qF "lock crm: not started: blocked by company policy: lox.egress does not allow db.other.internal:5432 (lock crm)" up2.out ||
	die "locksql is not refused by lox.egress"
grep -qF "lock events: started" up2.out || die "lockmq did not start under the egress allowlist"

say "3. allow_no_upgrade = false: lox run --no-upgrade exits 3 before anything"
managed 'version = 1

[lox]
allow_no_upgrade = false
'
rc=0
"$lox" run --no-upgrade </dev/null >run.out 2>&1 || rc=$?
cat run.out
[ "$rc" = 3 ] || die "lox run --no-upgrade exited $rc, want 3"
grep -qF "lox run: --no-upgrade: blocked by company policy: lox.allow_no_upgrade = false" run.out || die "no refusal line"
grep -q "image verified" run.out && die "lox run went on after the refusal"

say "PASS: lox run applies the company's managed file"
