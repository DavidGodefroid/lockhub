#!/bin/sh
# lockfile's seccomp profile under lox run (lockhub#45), end to end: a
# workspace with one lockfile lock (its latest signed release, as lox add
# pins it) and this commit's hub; lox up reviews the profile's digest,
# writes lox's copy of lockfile's shipped seccomp.json in its state
# directory, and compose creates the console under it: docker inspect shows
# exactly that profile (never Docker's default, never unconfined), the
# console's process runs under a seccomp filter, and lockfile's own doctor
# says the plugin sandbox works under it. The hub keeps Docker's default.
#
#   ci/e2e/seccomp.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT TERM

say "lox add lockfile docs: pinned to its latest signed release"
"$lox" add lockfile docs
local_hub .lockfamily/lockfamily.yaml
cat .lockfamily/lockfamily.yaml

say "the lock's profile: an S3 bucket, credentials typed at the console's start"
mkdir -p .lockfile && chmod 0700 .lockfile
printf '[profiles.default]\nsource = "s3"\nbucket = "e2e-documents"\nregion = "eu-west-1"\ncredentials = "ask"\n' >.lockfile/config.toml
chmod 0600 .lockfile/config.toml

say "lox up (review at a terminal)"
tty 'y\n' "$lox" up >up.out 2>&1 || { cat up.out; die "lox up failed"; }
cat up.out
grep -q "up: project " up.out || die "lox up did not finish"
want_sum=$(sha256sum "$repo/internal/family/lockfile-seccomp.json" | cut -d' ' -f1)
tr -d '\r' <up.out | grep -qF "lock docs seccomp lockfile's shipped profile sha256:$want_sum" ||
	die "the review does not show lockfile's seccomp profile (sha256:$want_sum)"
hub_cosigned up.out
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
hub_is_local "$p"

say "lox run's copy is lockfile's seccomp.json, byte for byte"
[ -f "$state/lockfile-seccomp.json" ] || die "no $state/lockfile-seccomp.json"
cmp "$state/lockfile-seccomp.json" "$repo/internal/family/lockfile-seccomp.json" || die "the state copy is not the embedded profile"
block() { sed -n "/^  $1:\$/,/^  [a-z]/p" "$2"; }
block lock-docs "$state/compose.yaml" | grep -qF "\"seccomp=$state/lockfile-seccomp.json\"" || die "lock-docs is not under the profile in the applied compose"
grep -q unconfined "$state/compose.yaml" && die "unconfined in the applied compose"

say "docker inspect: the console's container runs under that profile"
c="$p-lock-docs-1"
for i in $(seq 1 30); do [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && break; sleep 1; done
[ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] || { docker logs "$c" 2>&1 | tail -20 || true; die "$c is not running"; }
docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$c" >secopt.json
jq -e 'index("no-new-privileges:true") != null' secopt.json >/dev/null || die "$c lost no-new-privileges"
[ "$(jq '[.[] | select(startswith("seccomp="))] | length' secopt.json)" = 1 ] || { cat secopt.json; die "$c has not exactly one seccomp profile"; }
jq -r '.[] | select(startswith("seccomp=")) | sub("^seccomp="; "")' secopt.json | jq -S -c . >got.json ||
	die "$c's seccomp option is not a JSON profile (unconfined, or a path)"
jq -S -c . "$repo/internal/family/lockfile-seccomp.json" >want.json
cmp got.json want.json || die "$c runs a seccomp profile other than lockfile's"
docker exec "$c" cat /proc/1/status >status.txt
grep -Eq '^Seccomp:[[:space:]]+2$' status.txt || { grep Seccomp status.txt || true; die "the console's process is not under a seccomp filter"; }
# The hub is not a lockfile console: Docker's default (no seccomp= option).
docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$p-lockhub-1" | jq -e '[.[] | select(startswith("seccomp="))] | length == 0' >/dev/null ||
	die "the hub runs under lockfile's profile"

say "lockfile doctor, under the lock's service: the plugin sandbox works under the profile"
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" run --rm -T --no-deps lock-docs doctor >doctor.out 2>&1 || true
cat doctor.out
grep -Eq '^ok +sandbox +Landlock ABI [0-9]+, seccomp' doctor.out || die "lockfile doctor: the sandbox does not work under the profile"

say "PASS: lockfile's console runs under its shipped seccomp profile"
