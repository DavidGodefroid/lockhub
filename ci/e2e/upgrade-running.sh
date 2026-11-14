#!/bin/sh
# lox run of this commit over a stack an earlier lox made and left up
# (lockhub#199), end to end, with real releases, cosign and Docker: the
# released lox OLD (default v0.10.1, whose networks have no subnet of
# their own) starts a workspace on its hub and lockhttp lock, then this
# commit's lox run, as after `brew upgrade lox`:
#
#  1. the stack up (hub, lock, gateway): lox run takes it down in one
#     line, asks nothing more than the usual review, and applies; the
#     volumes, the hub key and the hub's database are the same ones;
#  2. the hub exited, the lock running (the state after a reboot): same;
#  3. the Docker daemon restarted: no container of the workspaces runs
#     until lox run;
#  4. lox down: containers and networks gone, volumes kept; again: no-op.
#
#   ci/e2e/upgrade-running.sh OUTDIR [OLD]
#
# CI only for step 3 (it restarts dockerd with sudo).
. "$(dirname "$0")/lib.sh"
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../.." && pwd)
out=$1
old=${2:-v0.10.1}
umask 022
mkdir -p "$out"
command -v cosign >/dev/null || die "no cosign in PATH"
auth=""
[ -z "${GITHUB_TOKEN:-}" ] || auth="Authorization: Bearer $GITHUB_TOKEN"
releases() {
	curl -fsS ${auth:+-H "$auth"} "https://api.github.com/repos/DavidGodefroid/$1/releases?per_page=100" |
		jq -r '.[] | select(.draft | not) | .tag_name' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV
}
digest() {
	docker buildx imagetools inspect "ghcr.io/davidgodefroid/$1:${2#v}" --format '{{json .Manifest.Digest}}' | tr -d '"'
}

hub_new=$(releases lockhub | head -1)
[ -n "$hub_new" ] || die "no lockhub release found"
# The lockhttp release lox OLD shipped with, and its hub.
lock_old=$(curl -fsS "https://raw.githubusercontent.com/DavidGodefroid/lockhub/$old/internal/family/upgrade.go" | sed -n 's/^	"lockhttp": *"\(v[^"]*\)",$/\1/p')
[ -n "$lock_old" ] || die "no lockhttp release in lox $old's upgrade.go"
hub_old_ref=ghcr.io/davidgodefroid/lockhub@$(digest lockhub "$old")
hub_new_ref=ghcr.io/davidgodefroid/lockhub@$(digest lockhub "$hub_new")
echo "lox $old (hub $old, lockhttp $lock_old) → lox ${hub_new#v} of this commit"

say "lox $old (released) and lox ${hub_new#v} (this commit)"
arch=$(uname -m)
case $arch in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
tgz=lox_${old#v}_linux_$arch.tar.gz
mkdir -p "$out/old"
curl -fsSL -o "$out/old/$tgz" "https://github.com/DavidGodefroid/lockhub/releases/download/$old/$tgz"
curl -fsSL -o "$out/old/checksums.txt" "https://github.com/DavidGodefroid/lockhub/releases/download/$old/checksums.txt"
(cd "$out/old" && grep " $tgz\$" checksums.txt | sha256sum -c -) || die "$tgz does not match the release's checksums"
tar -xzf "$out/old/$tgz" -C "$out/old" lox
oldlox=$out/old/lox
"$oldlox" version | grep -qx "lox ${old#v}" || die "the old lox is not ${old#v}"
(cd "$src" && CGO_ENABLED=0 go build -ldflags "-X main.version=${hub_new#v}" -o "$out/lox" ./cmd/lox)
lox=$out/lox

projects=""
cleanup() {
	for p in $projects; do
		docker ps -aq --filter "label=com.docker.compose.project=$p" | xargs -r docker rm -f >/dev/null 2>&1 || true
		docker network ls -q --filter "label=com.docker.compose.project=$p" | xargs -r docker network rm >/dev/null 2>&1 || true
		docker volume ls -q --filter "label=com.docker.compose.project=$p" | xargs -r docker volume rm >/dev/null 2>&1 || true
	done
}
trap cleanup EXIT INT TERM

# oldstack DIR: a workspace in DIR that lox OLD started; $p its project.
oldstack() {
	mkdir -p "$1"
	cd "$1"
	"$oldlox" add lockhttp first --version "$lock_old" --hub-image "$hub_old_ref" >add.out 2>&1 || { cat add.out; die "lox $old add failed"; }
	mkdir -p .lockhttp
	printf '[profiles.default]\nmode = "enforce"\nheuristics = "off"\nbuffer_limit = "1MiB"\nhold = "60s"\nconnect_grant = "1m"\ntrusted = []\nsplice = []\ndeny = []\n' >.lockhttp/config.toml
	tty 'y\n' "$oldlox" up >up.out 2>&1 || { cat up.out; die "lox $old up failed"; }
	grep -q "up: project " up.out || { cat up.out; die "lox $old up did not finish"; }
	p=$(ws_project "$1")
	projects="$projects $p"
	state="$XDG_STATE_HOME/lockfamily/$p"
	# What lox OLD made: networks with the engine's subnets, the old
	# restart policy.
	docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}' "${p}_lockhub"
	docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' "$p-lockhub-1" "$p-lock-first-1"
}
# kept: the volumes (name, creation), the hub's keys and the identity of
# its database: what a reconcile must not touch.
kept() {
	docker volume ls -q --filter "label=com.docker.compose.project=$p" | sort | xargs -r docker volume inspect -f '{{.Name}} {{.CreatedAt}}'
	docker run --rm -v "${p}_hubkey:/v:ro" alpine:3.22 sh -c 'cd /v && find . -type f | sort | xargs -r sha256sum'
	(cd "$state" && sha256sum hub.pub && find hub -name '*.key' -type f | sort | xargs -r sha256sum && ls -i hub/hub.db)
}
# run NAME: this commit's lox run at a terminal (the review answered if
# one is asked), quit once it serves decisions; output in NAME.out.
run() {
	python3 "$here/expect.py" 600 "<opt>Apply? [y/N]" 'y\n' "up: project " "<pause>qq" -- "$lox" run >"$1.raw" 2>&1 || { tr -d '\r' <"$1.raw"; die "lox run ($1) failed"; }
	tr -d '\r' <"$1.raw" >"$1.out"
	sed -n '1,/^up: project /p' "$1.out"
	grep -q "has active endpoints" "$1.out" && die "lox run ($1): a network was still in use"
	return 0
}
# upgraded NAME: lox run (output NAME.out) took the previous stack down in
# one line and runs the new hub, under a restart policy of none.
upgraded() {
	grep -qxF "previous stack stopped (lockhub $old → $hub_new)" "$1.out" || die "lox run ($1): no \"previous stack stopped (lockhub $old → $hub_new)\" line"
	[ "$(docker inspect -f '{{.Config.Image}}' "$p-lockhub-1")" = "$hub_new_ref" ] || die "the hub does not run $hub_new_ref"
	for c in lockhub lock-first; do
		[ "$(docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' "$p-$c-1")" = "true no" ] ||
			die "$c: $(docker inspect -f '{{.State.Status}} {{.HostConfig.RestartPolicy.Name}}' "$p-$c-1"), not running under restart no"
	done
	[ -n "$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${p}_lockhub" | grep '^10\.123\.')" ] || die "the hub's network has no subnet of the workspace's pool"
}

root=$(mktemp -d)

say "1. lox $old's stack up: lox run of this commit"
oldstack "$root/up/projects"
pa=$p
kept >before.kept
run upgraded
upgraded upgraded
kept >after.kept
diff before.kept after.kept || die "a volume, the hub key or the hub's database changed"

say "2. lox $old's stack, the hub exited, the lock running (after a reboot)"
oldstack "$root/reboot/projects"
pb=$p
docker stop "$p-lockhub-1" >/dev/null
[ "$(docker inspect -f '{{.State.Running}}' "$p-lock-first-1")" = true ] || die "the lock does not run"
kept >before.kept
run reboot
upgraded reboot
kept >after.kept
diff before.kept after.kept || die "a volume, the hub key or the hub's database changed"

say "3. the Docker daemon restarts: nothing of the workspaces runs until lox run"
sudo systemctl restart docker
i=0
until docker info >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -le 60 ] || die "dockerd did not come back"
	sleep 1
done
sleep 5
for q in $pa $pb; do
	running=$(docker ps -q --filter "label=com.docker.compose.project=$q")
	[ -z "$running" ] || { docker ps --filter "label=com.docker.compose.project=$q"; die "a container of $q runs after the daemon restarted"; }
done
cd "$root/up/projects"
p=$pa
state="$XDG_STATE_HOME/lockfamily/$p"
run restarted
[ "$(docker inspect -f '{{.State.Running}}' "$p-lockhub-1")" = true ] || die "lox run did not start the hub again"

say "4. lox down: containers and networks gone, volumes kept; idempotent"
vols=$(docker volume ls -q --filter "label=com.docker.compose.project=$p" | sort)
"$lox" down >down.out 2>&1 || { cat down.out; die "lox down failed"; }
cat down.out
grep -q "^lox down: stopped " down.out || die "lox down stopped nothing"
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$p")" ] || die "a container is left after lox down"
[ -z "$(docker network ls -q --filter "label=com.docker.compose.project=$p")" ] || die "a network is left after lox down"
[ "$(docker volume ls -q --filter "label=com.docker.compose.project=$p" | sort)" = "$vols" ] || die "lox down removed a volume"
"$lox" down >down2.out 2>&1 || { cat down2.out; die "lox down (again) failed"; }
grep -q "nothing runs for this workspace" down2.out || { cat down2.out; die "lox down again did something"; }
echo "upgrade over a running stack: OK"
