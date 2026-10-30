#!/bin/sh
# compat.sh BUILD FIXTURES: lockhub's tests built on one lockkit, its
# ticket codec checked against the signed fixtures of another (plan H0:
# {pinned lockkit, N-1} x lockkit fixtures). Each of BUILD and FIXTURES is
# "pinned" (go.mod's lockkit) or "prev" (the release before it). It
# changes go.mod and go.sum for a "prev" build: run it in CI or on a copy.
set -eu
mod=github.com/DavidGodefroid/lockkit
pinned=$(go list -m -f '{{.Version}}' "$mod")
# The newest release (no pre-release) below the pinned one.
prev=$(go list -m -versions "$mod" | tr ' ' '\n' | sed 1d | grep -v -- - |
	awk -v p="${pinned%%-*}" '
		function n(v,  a) { split(substr(v, 2), a, "."); return a[1] * 1000000 + a[2] * 1000 + a[3] }
		n($0) < n(p) && n($0) > best { best = n($0); v = $0 }
		END { print v }')
[ -n "$prev" ] || { echo "compat: no lockkit release before $pinned" >&2; exit 1; }
pick() { if [ "$1" = prev ]; then echo "$prev"; else echo "$pinned"; fi; }
build=$(pick "$1")
fixtures=$(pick "$2")
echo "compat: build on lockkit $build, fixtures of lockkit $fixtures"
if [ "$build" != "$pinned" ]; then
	go get "$mod@$build"
fi
dir=$(go mod download -json "$mod@$fixtures" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
[ -d "$dir/ticket/testdata" ] || { echo "compat: no ticket fixtures in lockkit $fixtures" >&2; exit 1; }
go vet ./...
LOCKKIT_FIXTURES=$dir go test -count=1 -run 'Lockkit' -v ./internal/ticketcodec/
go test ./...
