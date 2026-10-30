#!/bin/sh
# compat.sh BUILD FIXTURES: lockhub's tests built on one lockkit, its
# ticket codec checked against the signed fixtures of another (plan H0:
# {pinned lockkit, N-1} x lockkit fixtures). BUILD is "pinned" (go.mod's
# lockkit) or "prev" (the release before it); FIXTURES is one of those or
# "latest" (the newest release: tickets of locks built on a newer
# lockkit). A "prev" build changes go.mod and go.sum: run it in CI or on a
# copy.
set -eu
usage() { echo "usage: compat.sh pinned|prev pinned|prev|latest" >&2; exit 2; }
[ $# -eq 2 ] || usage
case $1 in pinned | prev) ;; *) usage ;; esac
case $2 in pinned | prev | latest) ;; *) usage ;; esac
mod=github.com/DavidGodefroid/lockkit
pinned=$(go list -m -f '{{.Version}}' "$mod")
versions=$(go list -m -versions "$mod")
releases=$(echo "$versions" | tr ' ' '\n' | sed 1d | grep -v -- - || true)
# n turns vX.Y.Z into a number that orders as the version does.
pickv() {
	echo "$releases" | awk -v p="${pinned%%-*}" -v want="$1" '
		function n(v,  a) { split(substr(v, 2), a, "."); return a[1] * 1000000 + a[2] * 1000 + a[3] }
		want == "prev" && n($0) < n(p) && n($0) > best { best = n($0); v = $0 }
		want == "latest" && n($0) > best { best = n($0); v = $0 }
		END { print v }'
}
version() {
	case $1 in
	pinned) echo "$pinned" ;;
	*) v=$(pickv "$1"); [ -n "$v" ] || { echo "compat: no $1 lockkit release (pinned $pinned)" >&2; exit 1; }; echo "$v" ;;
	esac
}
build=$(version "$1")
fixtures=$(version "$2")
echo "compat: build on lockkit $build, fixtures of lockkit $fixtures"
if [ "$build" != "$pinned" ]; then
	go get "$mod@$build"
fi
go mod download "$mod@$fixtures"
dir=$(go list -m -f '{{.Dir}}' "$mod@$fixtures")
[ -f "$dir/ticket/testdata/ticket-v1.json" ] || { echo "compat: no ticket fixtures in lockkit $fixtures" >&2; exit 1; }
go vet ./...
# The tests that read the fixtures; -v lists them, so a rename that
# matches none shows in the log.
LOCKKIT_FIXTURES=$dir go test -count=1 -run 'LockkitFixtures|RequestSignature|TTLClampedToRisk' -v ./internal/ticketcodec/ >compat.out || { cat compat.out; exit 1; }
cat compat.out
grep -q -- '--- PASS: TestLockkitFixtures' compat.out || { echo "compat: TestLockkitFixtures did not run" >&2; exit 1; }
rm -f compat.out
go test ./...
