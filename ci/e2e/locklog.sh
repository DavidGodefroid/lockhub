#!/bin/sh
# locklog's mount plan under lox run (lockhub#86, H-LL2a), end to end: a
# workspace with two locklog locks (locklog's latest signed release, as lox
# add pins it) and this commit's hub. One lock reads a file source under
# /var/log, the other a docker source (a docker source never shares a
# console with file sources). lox run derives each plan in locklog's image
# (locklog mounts, on the reviewed copy), checks it on this host, shows it
# in the review and mounts exactly that: each directory read-only and
# non-recursive at its own path, the groups the files need, the device and
# inode the console checks (both consoles start: their own CheckMounts
# accepts what lox run passed). The docker lock gets the containers map in
# lox run's state, bound read-only at /run/locklog-map; lox doctor says it
# is stale once a container its globs name appears, and lox refresh
# rewrites it.
#
# Networks and routing (lockhub#87, H-LL2b): the two local-source consoles
# are on the hub's network alone (no route out, no LOCKLOG_NETWORK); a
# third lock, with a remote (Loki) source, is on its own locknet behind its
# gateway, which no other lock joins, and LOCKLOG_NETWORK names it. The
# locklog locks are routed to the local facades only, and lox doctor finds
# the routing lox run wrote. A lock whose plan.json is gone (a workspace
# from before the mount plans) is a warning that says to run lox run.
#
#   ci/e2e/locklog.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
logs=/var/log/lockhub-$E2E_ID
web=$E2E_ID-web
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	docker rm -f "$web-1" "$web-2" >/dev/null 2>&1 || true
	sudo rm -rf "$logs"
}
trap cleanup EXIT INT TERM

say "host logs: a directory of group adm (0750, a 0640 file), a container of json-file logs"
sudo mkdir -p "$logs/app"
printf 'e2e line one\ne2e line two\n' | sudo tee "$logs/app/app.log" >/dev/null
sudo chown root:adm "$logs/app" "$logs/app/app.log"
sudo chmod 0750 "$logs/app"
sudo chmod 0640 "$logs/app/app.log"
adm=$(getent group adm | cut -d: -f3)
[ -n "$adm" ] || die "no group adm on this host"
docker run -d --name "$web-1" --log-driver json-file --log-opt max-size=1m --log-opt max-file=3 --log-opt compress=true alpine:3.22 sleep 900 >/dev/null
id1=$(docker inspect -f '{{.Id}}' "$web-1")

say "lox add locklog logs and ctrs: pinned to locklog's latest signed release"
"$lox" add locklog logs --profile files
"$lox" add locklog ctrs --profile ctr
"$lox" add locklog rem --profile rem
local_hub .lockfamily/lockfamily.yaml
cat .lockfamily/lockfamily.yaml
mkdir -p .locklog && chmod 0700 .locklog
cat >.locklog/config.toml <<EOF
version = 1

[profiles.files]
production = false

[profiles.files.sources.app]
kind = "file"
paths = ["$logs/app/*.log"]
format = "plain"

[profiles.ctr]
production = false

[profiles.ctr.sources.web]
kind = "docker"
containers = ["$web-*"]
format = "json"

[profiles.rem]
production = false

[profiles.rem.sources.loki]
kind = "loki"
url = "http://loki.invalid:3100"
auth = "none"
selector = { app = "e2e" }
EOF
chmod 0600 .locklog/config.toml

say "lox run: the review shows every derived line"
python3 "$here/expect.py" 600 'Apply? [y/N]' 'y\n' "up: project " "<pause>qq" -- "$lox" run >run.raw 2>&1 || { tr -d '\r' <run.raw; die "lox run failed"; }
tr -d '\r' <run.raw >run.out
sed -n '1,/^up: project /p' run.out
hub_cosigned run.out
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
hub_is_local "$p"
root=$(docker info -f '{{.DockerRootDir}}')/containers
mapdir=$state/locklog/ctrs/map
for want in \
	"lock logs mount plan of profile files (production false), from locklog mounts on the reviewed copy" \
	"lock logs plan file $logs/app $logs/app/*.log" \
	"lock logs bind $logs/app (read-only, non-recursive)" \
	"lock logs groups $adm" \
	"lock ctrs mount plan of profile ctr (production false)" \
	"lock ctrs plan docker $web-*" \
	"lock ctrs bind $root (read-only, non-recursive; the Docker containers root, group 0 for it only" \
	"lock ctrs groups 0" \
	"lock ctrs containers map $mapdir at /run/locklog-map (read-only)" \
	"lock logs network lockhub only (local sources: no route out)" \
	"lock ctrs network lockhub only (local sources: no route out)" \
	"lock rem plan remote" \
	"lock rem network lockhub and ${p}_locknet-rem, its own, which no agent joins" \
	"only loki.invalid:3100" \
	"local log sources only: the console is on the hub's network alone, with no route out" \
	"lock logs routed only to tty,deck,mobile (locklog's default: no chat facade)"; do
	grep -qF "$want" run.out || die "the review lacks: $want"
done

say "docker inspect: binds read-only and non-recursive, groups, environment, label"
# insp CONTAINER: its mounts, groups, environment and labels, as JSON.
insp() { docker inspect -f '{"mounts":{{json .Mounts}},"host":{{json .HostConfig.Mounts}},"groups":{{json .HostConfig.GroupAdd}},"env":{{json .Config.Env}},"labels":{{json .Config.Labels}}}' "$1"; }
insp "$p-lock-logs-1" >logs.json
insp "$p-lock-ctrs-1" >ctrs.json
jq -e --arg d "$logs/app" '[.host[] | select(.Type == "bind" and .Source == $d and .Target == $d and .ReadOnly and .BindOptions.NonRecursive)] | length == 1' logs.json >/dev/null ||
	{ cat logs.json; die "lock-logs: $logs/app is not bound read-only and non-recursive at its own path"; }
jq -e --arg g "$adm" '.groups == [$g]' logs.json >/dev/null || { cat logs.json; die "lock-logs: group_add is not [adm]"; }
jq -e --arg d "$logs/app" '.env | any(startswith("LOCKLOG_EXPECT_ROOTS=") and contains(" " + $d + ";"))' logs.json >/dev/null || { cat logs.json; die "lock-logs: LOCKLOG_EXPECT_ROOTS lacks $logs/app"; }
jq -e --arg r "$root" '[.host[] | select(.Type == "bind" and .Source == $r and .Target == $r and .ReadOnly and .BindOptions.NonRecursive)] | length == 1' ctrs.json >/dev/null ||
	{ cat ctrs.json; die "lock-ctrs: the containers root is not bound read-only and non-recursive"; }
jq -e --arg m "$mapdir" '[.mounts[] | select(.Source == $m and .Destination == "/run/locklog-map" and (.RW | not))] | length == 1' ctrs.json >/dev/null ||
	{ cat ctrs.json; die "lock-ctrs: the map directory is not bound read-only at /run/locklog-map"; }
jq -e '.groups == ["0"]' ctrs.json >/dev/null || { cat ctrs.json; die "lock-ctrs: group_add is not [0]"; }
jq -e --arg r "$root" '.env | index("LOCKLOG_DOCKER_ROOT=" + $r) != null' ctrs.json >/dev/null || { cat ctrs.json; die "lock-ctrs: LOCKLOG_DOCKER_ROOT is not $root"; }
for f in logs.json ctrs.json; do
	jq -e '.labels["locklog.console"] == "1"' "$f" >/dev/null || die "$f: no locklog.console label"
	jq -e '.env | any(test("^LOCKLOG_EXPECT_DIR=[0-9]+:[0-9]+$"))' "$f" >/dev/null || die "$f: no LOCKLOG_EXPECT_DIR"
	jq -e '.env | index("LOCKLOG_PII_DIR=/home/locklog/pii-rules") != null' "$f" >/dev/null || die "$f: no LOCKLOG_PII_DIR"
done
jq -e '[.mounts[] | select(.Destination == "/run/locklog-map")] | length == 0' logs.json >/dev/null || die "lock-logs (no docker source) has a map"

say "networks: local sources on the hub's network alone, a remote source on its own"
# nets CONTAINER: the networks it joins, sorted.
nets() { docker inspect -f '{{json .NetworkSettings.Networks}}' "$1" | jq -c 'keys'; }
for c in logs ctrs; do
	[ "$(nets "$p-lock-$c-1")" = "[\"${p}_lockhub\"]" ] || die "lock-$c: networks $(nets "$p-lock-$c-1"), not the hub's alone"
	jq -e '.env | any(startswith("LOCKLOG_NETWORK=")) | not' "$c.json" >/dev/null || die "lock-$c: LOCKLOG_NETWORK set with local sources only"
	docker network inspect "${p}_locknet-$c" >/dev/null 2>&1 && die "${p}_locknet-$c exists for a lock with local sources only"
	docker inspect "$p-gw-$c-1" >/dev/null 2>&1 && die "a gateway for lock-$c (local sources only)"
done
[ "$(nets "$p-lock-rem-1")" = "[\"${p}_lockhub\",\"${p}_locknet-rem\"]" ] || die "lock-rem: networks $(nets "$p-lock-rem-1")"
insp "$p-lock-rem-1" >rem.json
jq -e --arg n "${p}_locknet-rem" '.env | index("LOCKLOG_NETWORK=" + $n) != null' rem.json >/dev/null || { cat rem.json; die "lock-rem: LOCKLOG_NETWORK is not ${p}_locknet-rem"; }
[ "$(docker network inspect -f '{{.Internal}}' "${p}_locknet-rem")" = true ] || die "${p}_locknet-rem is not internal"
joined=$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "${p}_locknet-rem" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ')
[ "$joined" = "$p-gw-rem-1 $p-lock-rem-1 " ] || die "${p}_locknet-rem is joined by: $joined"

say "routing: the locklog locks answered on the local facades only, as lox doctor checks"
for c in logs ctrs rem; do
	jq -e --arg c "$c" '.only[$c] | (. != null) and all(. == "tty" or . == "deck" or . == "mobile")' "$state/hub/routing.json" >/dev/null ||
		{ cat "$state/hub/routing.json"; die "routing.json: lock $c is not routed to the local facades only"; }
done

say "the consoles start: their mount check accepts what lox run passed"
sleep 5
for c in "$p-lock-logs-1" "$p-lock-ctrs-1" "$p-lock-rem-1"; do
	[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$c")" = "true 0" ] ||
		{ docker inspect -f '{{json .State}} restarts {{.RestartCount}}' "$c"; die "$c does not stay up (its mount check refused?)"; }
done

say "the containers map: names and ids only, read by the console"
# v1 is written before the consoles start (each reads one at its start),
# v2 once compose created them: their ids are excluded ("x" lines).
for v in 1 2; do
	[ -f "$mapdir/map.v$v" ] || { ls -la "$mapdir"; die "no $mapdir/map.v$v"; }
	echo "map.v$v:"
	cat "$mapdir/map.v$v"
done
[ ! -e "$mapdir/map.v3" ] || die "lox run wrote more than two versions"
grep -qxF "c $id1 $web-1 3 1" "$mapdir/map.v1" || die "map.v1 does not map $web-1 (max-file 3, compressed)"
grep -qxF "c $id1 $web-1 3 1" "$mapdir/map.v2" || die "map.v2 does not map $web-1"
for c in "$p-lock-logs-1" "$p-lock-ctrs-1"; do
	grep -qxF "x $(docker inspect -f '{{.Id}}' "$c")" "$mapdir/map.v2" || die "map.v2 does not exclude the console $c"
done
docker exec "$p-lock-ctrs-1" cat /run/locklog-map/map.v2 | cmp - "$mapdir/map.v2" || die "the console does not read map.v2"
"$lox" doctor >doctor1.out 2>&1 || true
grep -F "lock ctrs containers map: map.v2 current: 1 mapped" doctor1.out || { cat doctor1.out; die "lox doctor does not say map.v2 is current"; }
grep -F "changed since the last lox run" doctor1.out && die "lox doctor takes the mount plans for a change of lockfamily.yaml"
grep -F "hub routing" doctor1.out | grep -F "differs" && die "lox doctor: a false routing mismatch"
grep -qF "hub routing: facades" doctor1.out || { cat doctor1.out; die "lox doctor does not find the routing lox run wrote"; }

say "a new container its glob names: lox doctor says the map is stale, lox refresh rewrites it"
docker run -d --name "$web-2" --log-driver json-file alpine:3.22 sleep 900 >/dev/null
id2=$(docker inspect -f '{{.Id}}' "$web-2")
"$lox" doctor >doctor2.out 2>&1 || true
grep -F "warn lock ctrs containers map: map.v2 is stale" doctor2.out || { cat doctor2.out; die "lox doctor does not say map.v2 is stale"; }
"$lox" refresh ctrs >refresh.out 2>&1 || { cat refresh.out; die "lox refresh ctrs failed"; }
cat refresh.out
grep -qF "containers map v3 of ctrs" refresh.out || die "lox refresh did not write v3"
grep -qxF "c $id2 $web-2 1 0" "$mapdir/map.v3" || { cat "$mapdir/map.v3"; die "map.v3 does not map $web-2"; }
[ ! -e "$mapdir/map.v1" ] || die "map.v1 kept: only the last two versions are"
docker exec "$p-lock-ctrs-1" cat /run/locklog-map/map.v3 | cmp - "$mapdir/map.v3" || die "the console does not see map.v3"
"$lox" doctor >doctor3.out 2>&1 || true
grep -F "lock ctrs containers map: map.v3 current: 2 mapped" doctor3.out || { cat doctor3.out; die "lox doctor does not say map.v3 is current"; }
rc=0
"$lox" refresh logs >refresh-logs.out 2>&1 || rc=$?
[ "$rc" = 1 ] && grep -qF "has no docker source" refresh-logs.out || { cat refresh-logs.out; die "lox refresh of a lock with no docker source: exit $rc"; }

say "a lock with no applied plan (a workspace from before the mount plans): a warning, not a failure"
mv "$state/locklog/logs/plan.json" "$state/locklog/logs/plan.json.bak"
"$lox" doctor >doctor4.out 2>&1 || true
grep -F "warn lock logs mount plan: none applied yet" doctor4.out | grep -qF "run lox run" || { cat doctor4.out; die "lox doctor does not warn about the missing plan"; }
grep -E "^FAIL .*lock logs" doctor4.out && die "lox doctor fails a lock with no applied plan"
mv "$state/locklog/logs/plan.json.bak" "$state/locklog/logs/plan.json"

say "PASS: lox run mounts locklog's plan, the containers map and lox refresh; networks and routing"
