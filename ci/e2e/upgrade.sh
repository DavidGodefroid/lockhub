#!/bin/sh
# lox run's automatic upgrade (lockhub#118), end to end, with real
# releases, real cosign and Docker: a workspace pinned on the releases
# before the ones this lox ships with (the hub, and a lockhttp lock), as
# after `brew upgrade lox`. lox run, first with every new signature
# refused (fail closed: the old images keep running, lockfamily.yaml is
# unchanged, each refusal is said), then for real: each image upgraded
# (one line each), the containers recreated on the new digests,
# lockfamily.yaml rewritten, nothing asked; then nothing more to upgrade.
#
#   ci/e2e/upgrade.sh OUTDIR
#
# Builds lox into OUTDIR at the latest lockhub release's version (the hub
# lox ships with), so that the hub before it is the one to upgrade.
. "$(dirname "$0")/lib.sh"
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../.." && pwd)
out=$1
# The lock's configuration must be writable by you alone.
umask 022
mkdir -p "$out"
command -v cosign >/dev/null || die "no cosign in PATH"
auth=""
[ -z "${GITHUB_TOKEN:-}" ] || auth="Authorization: Bearer $GITHUB_TOKEN"
# releases REPO: its release tags, newest first (drafts left out).
releases() {
	curl -fsS ${auth:+-H "$auth"} "https://api.github.com/repos/DavidGodefroid/$1/releases?per_page=100" |
		jq -r '.[] | select(.draft | not) | .tag_name' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' | sort -rV
}
# before REPO TAG: the release of REPO just before TAG.
before() { releases "$1" | sed -n "/^$2\$/{n;p;q}"; }
# digest REPO TAG: the digest the registry serves for the release's image.
digest() {
	docker buildx imagetools inspect "ghcr.io/davidgodefroid/$1:${2#v}" --format '{{json .Manifest.Digest}}' | tr -d '"'
}

hub_new=$(releases lockhub | grep -v -- - | head -1)
hub_old=$(before lockhub "$hub_new")
lock_new=$(sed -n 's/^	"lockhttp": *"\(v[^"]*\)",$/\1/p' "$src/internal/family/upgrade.go")
lock_old=$(before lockhttp "$lock_new")
for v in "$hub_new" "$hub_old" "$lock_new" "$lock_old"; do [ -n "$v" ] || die "a release was not found ($hub_new $hub_old $lock_new $lock_old)"; done
echo "hub $hub_old → $hub_new, lockhttp $lock_old → $lock_new"
hub_old_ref=ghcr.io/davidgodefroid/lockhub@$(digest lockhub "$hub_old")
hub_new_ref=ghcr.io/davidgodefroid/lockhub@$(digest lockhub "$hub_new")
lock_old_ref=ghcr.io/davidgodefroid/lockhttp@$(digest lockhttp "$lock_old")
lock_new_ref=ghcr.io/davidgodefroid/lockhttp@$(digest lockhttp "$lock_new")

say "lox $hub_new (this commit)"
(cd "$src" && CGO_ENABLED=0 go build -ldflags "-X main.version=${hub_new#v}" -o "$out/lox" ./cmd/lox)
lox=$out/lox
"$lox" version | grep -qx "lox ${hub_new#v}" || die "lox is not ${hub_new#v}"

ws=$(mktemp -d)/projects
mkdir -p "$ws"
cd "$ws"
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
		# The gate's volume (lea's, external to compose).
		docker volume ls -q --filter "label=com.docker.compose.project=$p" | xargs -r docker volume rm >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT TERM

say "a workspace on the previous releases: lockhub $hub_old, lockhttp $lock_old"
"$lox" add lockhttp first --version "$lock_old" --hub-image "$hub_old_ref" >add.out 2>&1 || { cat add.out; die "lox add failed"; }
cat add.out
grep -qxF "  image: $hub_old_ref" .lockfamily/lockfamily.yaml || die "hub not pinned on $hub_old"
grep -qxF "    image: $lock_old_ref" .lockfamily/lockfamily.yaml || die "lock not pinned on $lock_old"
mkdir -p .lockhttp
printf '[profiles.default]\nmode = "enforce"\nheuristics = "off"\nbuffer_limit = "1MiB"\nhold = "60s"\nconnect_grant = "1m"\ntrusted = []\nsplice = []\ndeny = []\n' >.lockhttp/config.toml
tty 'y\n' "$lox" up >up.out 2>&1 || { cat up.out; die "lox up failed"; }
grep -q "up: project " up.out || { cat up.out; die "lox up did not finish"; }
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
# images: the image each running container of the project was created on.
images() {
	docker ps --filter "label=com.docker.compose.project=$p" --format '{{.Names}} {{.Image}}' | sort
}
# runs NAME REF: the container NAME of the project runs REF.
runs() {
	got=$(docker inspect -f '{{.Config.Image}}' "$p-$1-1") || die "no container $p-$1-1"
	[ "$got" = "$2" ] || { images; die "$1 runs $got, not $2"; }
}
runs lockhub "$hub_old_ref"
runs lock-first "$lock_old_ref"
cp .lockfamily/lockfamily.yaml pinned.yaml

# run NAME: lox run at a terminal, quit once it serves decisions; its
# output in NAME.out, without the terminal's \r.
run() {
	python3 "$here/expect.py" 600 "up: project " "<pause>qq" -- "$lox" run >"$1.raw" 2>&1 || { tr -d '\r' <"$1.raw"; die "lox run ($1) failed"; }
	tr -d '\r' <"$1.raw" >"$1.out"
	sed -n '1,/^up: project /p' "$1.out"
}

say "lox run, every new signature refused: fail closed"
# A cosign that refuses the verification of a release's image for its very
# tag (lox run's check of a new image: the identity regexp ends with $),
# and passes everything else to the real one.
shim=$(mktemp -d)
real=$(command -v cosign)
cat >"$shim/cosign" <<SHIM
#!/bin/sh
for a; do case "\$a" in *'refs/tags/v'*'\$') echo "e2e: signature refused for \$a" >&2; exit 1 ;; esac; done
exec "$real" "\$@"
SHIM
chmod 0755 "$shim/cosign"
PATH="$shim:$PATH" run refused
grep -qF "hub image: not upgraded to lockhub $hub_new, keeping $hub_old: " refused.out || die "no reason given for the hub"
grep -qF "lock first: image: not upgraded to lockhttp $lock_new, keeping $lock_old: " refused.out || die "no reason given for the lock"
grep -q " upgraded: " refused.out && die "an image was upgraded although its signature was refused"
grep -qx "configuration unchanged since the last lox run" refused.out || die "the configuration changed"
cmp pinned.yaml .lockfamily/lockfamily.yaml || die "lockfamily.yaml changed although nothing was upgraded"
runs lockhub "$hub_old_ref"
runs lock-first "$lock_old_ref"

say "lox run: upgraded, verified, recreated, nothing asked"
run upgraded
grep -qxF "hub image upgraded: lockhub $hub_old → $hub_new (signature verified)" upgraded.out || die "no upgrade line for the hub"
grep -qxF "lock first: image upgraded: lockhttp $lock_old → $lock_new (signature verified)" upgraded.out || die "no upgrade line for the lock"
grep -qx "only the upgraded images changed since the last lox run: applied without a question" upgraded.out || die "not applied as an upgrade alone"
grep -q "Apply?" upgraded.out && die "an upgrade alone asked a question"
grep -qxF "  image: $hub_new_ref" .lockfamily/lockfamily.yaml || die "lockfamily.yaml does not pin the new hub"
grep -qxF "    image: $lock_new_ref" .lockfamily/lockfamily.yaml || die "lockfamily.yaml does not pin the new lock"
runs lockhub "$hub_new_ref"
runs lock-first "$lock_new_ref"
images
tail -1 "$state/hub-images.log" | grep -qF " $hub_new_ref" || die "hub-images.log does not end on the new hub"

say "lox run again: nothing more to upgrade"
run again
grep -q "upgraded" again.out && die "upgraded again"
grep -qx "configuration unchanged since the last lox run" again.out || die "the configuration changed"
runs lockhub "$hub_new_ref"
echo "upgrade: OK"
