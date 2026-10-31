#!/bin/sh
# Phase 5 of the hub plan, end to end: the one-line install (install.sh)
# puts the lox CLI in ~/.local/bin; lox add pins a lock's latest signed
# release; lox up starts it; lox import merges two sub-projects keeping
# the strictest routing.
#
#   ci/e2e/phase5.sh INSTALL_SH DIST_DIR VERSION
#
# DIST_DIR holds this commit's release archives (scripts/release-cli.sh
# VERSION DIST_DIR), served as a local mirror; install.sh checks the
# archive against its sha256 (cosign would require a tagged release run).
# lox up runs this commit's hub build (E2E_HUB_IMAGE, ci/e2e/local-hub.sh).
. "$(dirname "$0")/lib.sh"
install=$1 dist=$2 v=$3
home=$(mktemp -d)
mirror=$(mktemp -d)
mkdir -p "$mirror/v$v"
cp "$dist"/* "$mirror/v$v/"
sum=$(sed -n "s/  lox_${v}_linux_amd64.tar.gz\$//p" "$dist/checksums.txt")
[ -n "$sum" ] || die "no checksum for the linux/amd64 archive"

say "install.sh, this commit, from a mirror"
HOME=$home LOCK_RELEASE_BASE=$mirror sh "$install" --version "v$v" --sha256 "$sum"
lox=$home/.local/bin/lox
"$lox" version | grep -qx "lox $v" || die "installed lox is not $v"

say "install.sh, the latest release, cosign-verified"
home2=$(mktemp -d)
HOME=$home2 sh "$install" >install2.out 2>&1 || { cat install2.out; die "install.sh (latest release) failed"; }
cat install2.out
grep -q 'cosign: checksums.txt signed by the lockhub release workflow' install2.out || die "install.sh did not report a cosign check"
"$home2/.local/bin/lox" version

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

say "lox add ${LOCK_TYPE:=lockhttp} (latest signed release)"
"$lox" add "$LOCK_TYPE" first >add.out 2>&1 || { cat add.out; die "lox add failed"; }
cat add.out
grep -q "signature verified" add.out || die "lox add did not verify the signature"
grep -q "ghcr.io/davidgodefroid/$LOCK_TYPE@sha256:" .lockfamily/lockfamily.yaml || die "not pinned by digest"
grep -q "ghcr.io/davidgodefroid/lockhub@sha256:" .lockfamily/lockfamily.yaml || die "hub not pinned"
local_hub .lockfamily/lockfamily.yaml

say "lox up"
mkdir -p ".$LOCK_TYPE"
printf '[profiles.default]\nmode = "enforce"\nheuristics = "off"\nbuffer_limit = "1MiB"\nhold = "60s"\nconnect_grant = "1m"\ntrusted = []\nsplice = []\ndeny = []\n' >".$LOCK_TYPE/config.toml"
tty 'y\n' "$lox" up >up.out 2>&1 || { cat up.out; die "lox up failed"; }
cat up.out
grep -q "up: project " up.out || die "lox up did not finish"
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" ps --status running --services >svc.out
grep -qx lockhub svc.out || die "hub not running"
grep -qx lock-first svc.out || die "lock first not running"
hub_is_local "$p"
hub_cosigned up.out
"$lox" doctor

say "lox import: two sub-projects, the strictest routing kept, in either order"
hub=$(sed -n 's/^  image: *//p' .lockfamily/lockfamily.yaml | head -1)
img=$(sed -n '/^  first:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
# sub DIR ROUTING: a sub-project declaring the lock shared (and DIR-only),
# with ROUTING ("" or "shared: [tty]") under hub.routing.
# b is a legacy sub-project (lockfamily.yaml at its root, no .lockfamily).
sub() {
	if [ "$(basename "$1")" = b ]; then mkdir -p "$1"; out=$1/lockfamily.yaml; else mkdir -p "$1/.lockfamily"; out=$1/.lockfamily/lockfamily.yaml; fi
	{
		printf 'version: 1\nhub:\n  image: %s\n  facades: [tty, deck]\n' "$hub"
		[ -z "$2" ] || printf '  routing:\n    %s\n' "$2"
		printf 'locks:\n  shared:\n    type: %s\n    image: %s\n  %s-only:\n    type: %s\n    image: %s\n' \
			"$LOCK_TYPE" "$img" "$(basename "$1")" "$LOCK_TYPE" "$img"
	} >"$out"
}
for order in strict-first strict-last; do
	imp=$(mktemp -d)/ws
	# Sub-projects are imported in name order: a* before b*.
	if [ "$order" = strict-first ]; then
		sub "$imp/a" "shared: [tty]"; sub "$imp/b" ""
	else
		sub "$imp/a" ""; sub "$imp/b" "shared: [tty]"
	fi
	(cd "$imp" && "$lox" import) >import.out 2>&1 || { cat import.out; die "lox import failed ($order)"; }
	cat import.out
	f=$imp/.lockfamily/lockfamily.yaml
	for l in shared a-only b-only; do grep -q "^  $l:" "$f" || die "$l not merged ($order)"; done
	r=$(sed -n '/^  routing:/,/^locks:/p' "$f" | tr -d ' \n')
	echo "$order: $r"
	case "$r" in routing:shared:-ttylocks:) ;; *) cat "$f"; die "routing of shared is not exactly [tty] ($order)" ;; esac
done
# Disjoint routings: no facade both allow, so import refuses (union or
# "last wins" would pass the cases above).
imp=$(mktemp -d)/ws
sub "$imp/a" "shared: [tty]"; sub "$imp/b" "shared: [deck]"
rc=0; (cd "$imp" && "$lox" import) >import.out 2>&1 || rc=$?
cat import.out
[ "$rc" != 0 ] || die "lox import merged disjoint routings"
grep -q 'no facade left that every declaration allows' import.out || die "no note about the disjoint routings"
[ ! -e "$imp/.lockfamily/lockfamily.yaml" ] || die "lox import wrote a file after refusing"
# Control: no routing on either side, none in the result.
imp=$(mktemp -d)/ws
sub "$imp/a" ""; sub "$imp/b" ""
(cd "$imp" && "$lox" import) >import.out 2>&1 || { cat import.out; die "lox import failed (no routing)"; }
grep -q 'routing:' "$imp/.lockfamily/lockfamily.yaml" && { cat "$imp/.lockfamily/lockfamily.yaml"; die "a routing appeared from nowhere"; }
grep -q '^  b-only:' "$imp/.lockfamily/lockfamily.yaml" || die "b-only not merged (no routing)"
echo "phase 5: OK"
