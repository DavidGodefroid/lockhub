#!/bin/sh
# Builds this commit's hub image for lock up: phases 2 and 5 must run the
# hub of the commit under test, not the latest release that lock add pins.
# lock up takes only ghcr.io/davidgodefroid/lockhub@sha256:<digest>: with
# Docker's containerd image store, a local build answers to its own digest
# under that name (nothing is pushed). lock up also cosign-verifies every
# image: a cosign shim, first in PATH, accepts exactly this ref and runs
# the real cosign for anything else.
#
#   ci/e2e/local-hub.sh SHIM_DIR    (prints the ref)
set -eu
shim=$1
docker build -q -t ghcr.io/davidgodefroid/lockhub:e2e-local . >/dev/null
id=$(docker image inspect -f '{{.Id}}' ghcr.io/davidgodefroid/lockhub:e2e-local)
ref=ghcr.io/davidgodefroid/lockhub@$id
case "$id" in sha256:*) ;; *) echo "local-hub: image id $id is not a digest (containerd image store off?)" >&2; exit 1 ;; esac
docker image inspect "$ref" >/dev/null || { echo "local-hub: $ref does not resolve (containerd image store off?)" >&2; exit 1; }
real=$(command -v cosign)
mkdir -p "$shim"
cat >"$shim/cosign" <<SHIM
#!/bin/sh
for a; do last=\$a; done
if [ "\$1" = verify ] && [ "\${last:-}" = "$ref" ]; then
	echo "e2e: \$last is this commit's hub build, not a release: no cosign check" >&2
	exit 0
fi
exec "$real" "\$@"
SHIM
chmod 0755 "$shim/cosign"
echo "$ref"
