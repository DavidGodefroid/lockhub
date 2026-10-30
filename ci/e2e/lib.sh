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
# lock add pins would not test this commit. The released ref is kept for
# the cosign shim: lock up's check of the hub's signer identity runs, with
# lock up's own flags, on that release.
local_hub() {
	[ -n "${E2E_HUB_IMAGE:-}" ] || die "E2E_HUB_IMAGE is not set (ci/e2e/local-hub.sh)"
	[ -n "${E2E_COSIGN_SHIM:-}" ] || die "E2E_COSIGN_SHIM is not set (ci/e2e/local-hub.sh)"
	rel=$(sed -n 's#^  image: \(ghcr.io/davidgodefroid/lockhub@sha256:[0-9a-f]\{64\}\)$#\1#p' "$1")
	[ -n "$rel" ] && [ "$(printf '%s\n' "$rel" | wc -l)" = 1 ] || die "$1 does not pin exactly one released hub"
	printf '%s\n' "$rel" >"$E2E_COSIGN_SHIM/released"
	sed -i "s#^  image: ghcr.io/davidgodefroid/lockhub@sha256:[0-9a-f]*\$#  image: $E2E_HUB_IMAGE#" "$1"
	grep -qxF "  image: $E2E_HUB_IMAGE" "$1" || die "the hub image of $1 is not this commit's build"
}
# hub_is_local PROJECT: the running hub is this commit's build: the image
# the container actually runs, not only the name compose was given.
hub_is_local() {
	got=$(docker inspect -f '{{.Image}}' "$1-lockhub-1") || die "no hub container $1-lockhub-1"
	want=$(docker image inspect -f '{{.Id}}' "$E2E_HUB_IMAGE") || die "$E2E_HUB_IMAGE does not resolve"
	[ "$got" = "$want" ] || die "the hub runs image $got, not this commit's build $want ($E2E_HUB_IMAGE)"
}
# hub_cosigned OUT: lock up (output OUT) asked cosign about this commit's
# hub, and the shim had the released hub verified with lock up's flags.
hub_cosigned() {
	grep -qF "e2e: $E2E_HUB_IMAGE is this commit's hub build: cosign verifies the released hub $(cat "$E2E_COSIGN_SHIM/released") with lock up's flags" "$1" ||
		die "lock up did not check the hub's signer identity (no cosign shim line in $1)"
}
