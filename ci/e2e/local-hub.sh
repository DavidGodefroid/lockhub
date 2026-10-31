#!/bin/sh
# Builds this commit's hub image for lox up: phases 2 and 5 must run the
# hub of the commit under test, not the latest release that lox add pins.
# lox up takes only ghcr.io/davidgodefroid/lockhub@sha256:<digest>: with
# Docker's containerd image store, a local build answers to its own digest
# under that name (nothing is pushed). lox up also cosign-verifies every
# image: a cosign shim, first in PATH, takes lox up's verify of exactly
# this ref and runs the real cosign, with lox up's flags, on the released
# hub that lox add pinned (SHIM_DIR/released, written by lib.sh's
# local_hub): lox up's hub signer identity is still checked against a
# real release. Anything else goes to the real cosign unchanged.
#
#   ci/e2e/local-hub.sh SHIM_DIR    (prints the ref)
set -eu
shim=$1
docker info -f '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter || { echo "local-hub: Docker's containerd image store is off" >&2; exit 1; }
docker build -q -t ghcr.io/davidgodefroid/lockhub:e2e-local . >/dev/null
id=$(docker image inspect -f '{{.Id}}' ghcr.io/davidgodefroid/lockhub:e2e-local)
ref=ghcr.io/davidgodefroid/lockhub@$id
docker image inspect "$ref" >/dev/null || { echo "local-hub: $ref does not resolve" >&2; exit 1; }
mkdir -p "$shim"
real=$(command -v cosign) || { echo "local-hub: no cosign in PATH" >&2; exit 1; }
[ "$(realpath "$real")" != "$(realpath "$shim")/cosign" ] || { echo "local-hub: cosign resolves to the shim itself" >&2; exit 1; }
real=$(realpath "$real")
rm -f "$shim/released"
cat >"$shim/cosign" <<SHIM
#!/bin/sh
for a; do last=\$a; done
if [ "\${1:-}" = verify ] && [ "\${last:-}" = "$ref" ]; then
	released=\$(cat "$shim/released" 2>/dev/null) && [ -n "\$released" ] ||
		{ echo "e2e: no released hub in $shim/released (ci/e2e/lib.sh local_hub)" >&2; exit 1; }
	echo "e2e: \$last is this commit's hub build: cosign verifies the released hub \$released with lox up's flags" >&2
	# lox up's arguments but the last (the ref), then the released ref.
	n=\$#
	i=0
	for a; do
		i=\$((i + 1))
		[ "\$i" -lt "\$n" ] && set -- "\$@" "\$a"
	done
	shift "\$n"
	exec "$real" "\$@" "\$released"
fi
exec "$real" "\$@"
SHIM
chmod 0755 "$shim/cosign"
echo "$ref"
