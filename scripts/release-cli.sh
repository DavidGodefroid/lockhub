#!/bin/sh
# Builds the release archives of the lox CLI, one per OS and architecture,
# and their checksums.txt:
#
#   scripts/release-cli.sh VERSION OUTDIR
#
#   OUTDIR/lox_VERSION_<os>_<arch>.tar.gz    lox (static) and LICENSE
#   OUTDIR/checksums.txt                     sha256sum format, sorted
#
# The release workflow signs checksums.txt with cosign (keyless) and attaches
# all of it to the GitHub release; the Lock Family install.sh verifies that
# signature, then the archive against checksums.txt. The archives are built
# reproducibly (-trimpath, fixed tar metadata), so the same commit and Go
# version give the same checksums.
set -eu

[ $# -eq 2 ] || { echo "usage: $0 VERSION OUTDIR" >&2; exit 2; }
version=$1
out=$2
printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?' ||
	{ echo "$0: invalid version $version: X.Y.Z, without the v" >&2; exit 2; }

mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
	os=${target%/*}
	arch=${target#*/}
	name="lox_${version}_${os}_${arch}"
	mkdir -p "$work/$name"
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=$version" -o "$work/$name/lox" ./cmd/lox
	cp LICENSE "$work/$name/LICENSE"
	chmod 0755 "$work/$name/lox"
	chmod 0644 "$work/$name/LICENSE"
	# GNU tar: fixed order, owner and mtime, so that the archive is reproducible.
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
		-C "$work/$name" -cf - lox LICENSE | gzip -n -9 >"$out/$name.tar.gz"
done

(cd "$out" && sha256sum lox_"${version}"_*.tar.gz | LC_ALL=C sort -k 2 >checksums.txt)
cat "$out/checksums.txt"
