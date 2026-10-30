#!/bin/sh
# Phase 5 of the hub plan, end to end: the one-line install (install.sh)
# puts the lock CLI in ~/.local/bin; lock add pins a lock's latest signed
# release; lock up starts it; lock import merges two sub-projects keeping
# the strictest routing.
#
#   ci/e2e/phase5.sh INSTALL_SH DIST_DIR VERSION
#
# DIST_DIR holds this commit's release archives (scripts/release-cli.sh
# VERSION DIST_DIR), served as a local mirror; install.sh checks the
# archive against its sha256 (cosign would require a tagged release run).
. "$(dirname "$0")/lib.sh"
install=$1 dist=$2 v=$3
home=$(mktemp -d)
mirror=$(mktemp -d)
mkdir -p "$mirror/v$v"
cp "$dist"/* "$mirror/v$v/"
sum=$(sed -n "s/  lock_${v}_linux_amd64.tar.gz\$//p" "$dist/checksums.txt")
[ -n "$sum" ] || die "no checksum for the linux/amd64 archive"

say "install.sh, this commit, from a mirror"
HOME=$home LOCK_RELEASE_BASE=$mirror sh "$install" --version "v$v" --sha256 "$sum"
lock=$home/.local/bin/lock
"$lock" version | grep -qx "lock $v" || die "installed lock is not $v"

say "install.sh, the latest release, cosign-verified"
home2=$(mktemp -d)
HOME=$home2 sh "$install" 2>&1 | tee install2.out
grep -q 'cosign: checksums.txt signed by the lockhub release workflow' install2.out || die "install.sh did not report a cosign check"
"$home2/.local/bin/lock" version

ws=$(mktemp -d)/projects
mkdir -p "$ws"
cd "$ws"
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT TERM

say "lock add ${LOCK_TYPE:=lockhttp} (latest signed release)"
"$lock" add "$LOCK_TYPE" first | tee add.out
grep -q "signature verified" add.out || die "lock add did not verify the signature"
grep -q "ghcr.io/davidgodefroid/$LOCK_TYPE@sha256:" .lockfamily/lockfamily.yaml || die "not pinned by digest"
grep -q "ghcr.io/davidgodefroid/lockhub@sha256:" .lockfamily/lockfamily.yaml || die "hub not pinned"

say "lock up"
mkdir -p ".$LOCK_TYPE"
printf '[profiles.default]\nmode = "enforce"\nheuristics = "off"\nbuffer_limit = "1MiB"\nhold = "60s"\nconnect_grant = "1m"\ntrusted = []\nsplice = []\ndeny = []\n' >".$LOCK_TYPE/config.toml"
tty 'y\n' "$lock" up >up.out 2>&1 || { cat up.out; die "lock up failed"; }
cat up.out
grep -q "up: project " up.out || die "lock up did not finish"
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" ps --status running --services >svc.out
grep -qx lockhub svc.out || die "hub not running"
grep -qx lock-first svc.out || die "lock first not running"
"$lock" doctor || true

say "lock import: two sub-projects, the strictest routing kept, in either order"
hub=$(sed -n 's/^  image: *//p' .lockfamily/lockfamily.yaml | head -1)
img=$(sed -n '/^  first:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
# sub DIR ROUTING: a sub-project declaring the lock shared (and DIR-only),
# with ROUTING ("" or "shared: [tty]") under hub.routing.
sub() {
	mkdir -p "$1/.lockfamily"
	{
		printf 'version: 1\nhub:\n  image: %s\n  facades: [tty, deck]\n' "$hub"
		[ -z "$2" ] || printf '  routing:\n    %s\n' "$2"
		printf 'locks:\n  shared:\n    type: %s\n    image: %s\n  %s-only:\n    type: %s\n    image: %s\n' \
			"$LOCK_TYPE" "$img" "$(basename "$1")" "$LOCK_TYPE" "$img"
	} >"$1/.lockfamily/lockfamily.yaml"
}
for order in strict-first strict-last; do
	imp=$(mktemp -d)/ws
	# Sub-projects are imported in name order: a* before b*.
	if [ "$order" = strict-first ]; then
		sub "$imp/a" "shared: [tty]"; sub "$imp/b" ""
	else
		sub "$imp/a" ""; sub "$imp/b" "shared: [tty]"
	fi
	(cd "$imp" && "$lock" import) >import.out 2>&1 || { cat import.out; die "lock import failed ($order)"; }
	cat import.out
	f=$imp/.lockfamily/lockfamily.yaml
	for l in shared a-only b-only; do grep -q "^  $l:" "$f" || die "$l not merged ($order)"; done
	r=$(sed -n '/^  routing:/,/^locks:/p' "$f" | tr -d ' \n')
	echo "$order: $r"
	case "$r" in routing:shared:-ttylocks:) ;; *) cat "$f"; die "routing of shared is not exactly [tty] ($order)" ;; esac
	case "$r" in *deck*) die "a facade one sub-project refuses was kept ($order)" ;; esac
done
echo "phase 5: OK"
