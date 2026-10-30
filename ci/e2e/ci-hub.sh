#!/bin/sh
# CI only (it restarts dockerd): turns on Docker's containerd image store,
# builds this commit's hub (local-hub.sh) and exports E2E_HUB_IMAGE,
# E2E_COSIGN_SHIM and the shim's PATH entry to the next steps.
#
#   ci/e2e/ci-hub.sh SHIM_DIR
set -eu
shim=$1
f=/etc/docker/daemon.json
t=$(mktemp)
{ sudo cat "$f" 2>/dev/null || echo '{}'; } | jq '. + {features: ((.features // {}) + {"containerd-snapshotter": true})}' >"$t"
sudo cp "$t" "$f"
rm -f "$t"
sudo systemctl restart docker
docker info -f '{{json .DriverStatus}}'
ref=$(sh "$(dirname "$0")/local-hub.sh" "$shim")
{
	echo "E2E_HUB_IMAGE=$ref"
	echo "E2E_COSIGN_SHIM=$shim"
} >>"$GITHUB_ENV"
echo "$shim" >>"$GITHUB_PATH"
