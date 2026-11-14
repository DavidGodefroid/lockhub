# Helpers of the lox up end-to-end scripts (sourced). The scripts remove
# only what they create: their compose project, gate and network.
set -eu
E2E_ID=${E2E_ID:-e2e$$}
say() { printf '\n=== %s\n' "$*"; }
die() {
	printf 'FAIL: %s\n' "$*" >&2
	# DEBUG lockhub#199 (temporary): the failure and the containers' state as annotations.
	printf '::error::FAIL: %s\n' "$*"
	docker ps -a --format '{{.Names}} {{.Status}} {{.Image}}' 2>/dev/null | tail -20 | sed 's/^/::error::ps: /'
	for f in *.out; do [ -f "$f" ] && tail -15 "$f" | tr -d '\r' | sed "s/^/::error::$f: /"; done 2>/dev/null
	exit 1
}
# tty INPUT CMD...: runs CMD at a pseudo-terminal (lox up, approve and
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
# lox add pins would not test this commit. The released ref is kept for
# the cosign shim: lox up's check of the hub's signer identity runs, with
# lox up's own flags, on that release.
# Outside CI: export E2E_HUB_IMAGE and E2E_COSIGN_SHIM as ci/e2e/ci-hub.sh
# does, with SHIM_DIR first in PATH.
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
# hub_cosigned OUT: lox up (output OUT) asked cosign about this commit's
# hub, and the shim had the released hub verified with lox up's flags.
# lox up shows cosign's output only with -v or on failure, so the shim
# also logs its line to SHIM_DIR/log; each check empties the log, so the
# next one needs a new verify.
hub_cosigned() {
	# OUT comes from a terminal: its lines end in \r\n.
	tr -d '\r' <"$1" | grep -qx "hub image verified" || die "lox up did not verify the hub image (no \"hub image verified\" in $1)"
	grep -qF "e2e: $E2E_HUB_IMAGE is this commit's hub build: cosign verifies the released hub $(cat "$E2E_COSIGN_SHIM/released") with lox up's flags" "$E2E_COSIGN_SHIM/log" ||
		die "lox up did not check the hub's signer identity (no cosign shim line in $E2E_COSIGN_SHIM/log)"
	: >"$E2E_COSIGN_SHIM/log"
}
# reaches CONTAINER HOST PORT: a TCP connect from inside CONTAINER's own
# network namespace (its interfaces, routes, DNS and /etc/hosts: what the
# lock's console itself would reach), by a throwaway alpine sharing it.
reaches() {
	docker run --rm --network "container:$1" alpine:3.22 nc -z -w 5 "$2" "$3" >/dev/null 2>&1
}
# egress_only CONTAINER HOST PORT...: CONTAINER reaches each HOST PORT given
# (the endpoints of its reviewed profile) and none of lockhub#123's
# forbidden destinations: another port of this machine (DECOY_PORT, which
# answers from an ordinary container), the internet, the cloud metadata
# address, a name outside the allowlist.
egress_only() {
	eg_c=$1
	shift
	while [ $# -ge 2 ]; do
		reaches "$eg_c" "$1" "$2" || die "$eg_c does not reach $1:$2, an endpoint of its reviewed profile"
		echo "egress: $eg_c reaches $1:$2 (allowed)"
		shift 2
	done
	for eg_t in "host.docker.internal $DECOY_PORT" "$DECOY_IP 8080" "1.1.1.1 443" "169.254.169.254 80" "example.com 443"; do
		# shellcheck disable=SC2086
		reaches "$eg_c" $eg_t && die "$eg_c reached $eg_t, outside its reviewed profile"
		echo "egress: $eg_c cannot reach $eg_t (refused)"
	done
}
# decoy_start NAME: a container answering on 8080, published on DECOY_PORT
# of this machine, and the positive controls: an ordinary container
# reaches it by host.docker.internal and by its address, and the internet
# (so that the refusals of egress_only prove the lock's egress, not a
# dead network).
decoy_start() {
	DECOY_PORT=${DECOY_PORT:-58124}
	docker run -d --name "$1" -p "$DECOY_PORT:8080" alpine:3.22 nc -lk -p 8080 -e cat >/dev/null
	DECOY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1")
	eg_ok=""
	for eg_i in $(seq 1 20); do
		docker run --rm --add-host host.docker.internal:host-gateway alpine:3.22 nc -z -w 5 host.docker.internal "$DECOY_PORT" && { eg_ok=1; break; }
		sleep 1
	done
	[ -n "$eg_ok" ] || die "control: an ordinary container does not reach the decoy on host.docker.internal:$DECOY_PORT"
	docker run --rm alpine:3.22 nc -z -w 5 "$DECOY_IP" 8080 || die "control: an ordinary container does not reach the decoy at $DECOY_IP:8080"
	docker run --rm alpine:3.22 nc -z -w 5 1.1.1.1 443 || die "control: an ordinary container does not reach 1.1.1.1:443"
	docker run --rm alpine:3.22 nc -z -w 5 example.com 443 || die "control: an ordinary container does not reach example.com:443"
}
