# Helpers of the lock up end-to-end scripts (sourced). The scripts remove
# only what they create: their compose project, gate and network.
set -eu
E2E_ID=${E2E_ID:-e2e$$}
say() { printf '\n=== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# tty INPUT CMD...: runs CMD at a pseudo-terminal (lock up, approve and
# attach refuse a pipe), INPUT typed in. Output goes to stdout.
tty() {
	in=$1
	shift
	printf '%b' "$in" | script -qefc "$*" /dev/null
}
# ws_project WS: the compose project of the workspace WS.
ws_project() { jq -r .project "$1/.lockfamily/up.json"; }
# local_hub FILE: the hub of FILE (a lockfamily.yaml) becomes this
# commit's build (E2E_HUB_IMAGE, from local-hub.sh): the released hub
# lock add pins would not test this commit.
local_hub() {
	[ -n "${E2E_HUB_IMAGE:-}" ] || die "E2E_HUB_IMAGE is not set (ci/e2e/local-hub.sh)"
	sed -i "s#^  image: ghcr.io/davidgodefroid/lockhub@sha256:[0-9a-f]*\$#  image: $E2E_HUB_IMAGE#" "$1"
	grep -qx "  image: $E2E_HUB_IMAGE" "$1" || die "the hub image of $1 is not this commit's build"
}
# hub_is_local PROJECT: the running hub is this commit's build.
hub_is_local() {
	got=$(docker inspect -f '{{.Config.Image}}' "$1-lockhub-1")
	[ "$got" = "$E2E_HUB_IMAGE" ] || die "the hub runs $got, not this commit's build $E2E_HUB_IMAGE"
}
