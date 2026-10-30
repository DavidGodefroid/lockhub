#!/bin/sh
# Phase 2 of the hub plan, end to end: lock up on a 2-lock lockfamily.yaml
# starts the stack; a ticket is approved through the facade socket
# (lock approve, at a terminal); an agent can reach the hub neither
# directly nor through the LockHTTP gate (I2); .lockfamily is read-only
# for an agent (I11).
#
#   ci/e2e/phase2.sh LOCK_BIN
#
# Locks: LOCKS="name:type ..." (default: two LockHTTP instances, the lock
# with hub mode in a release); a lockhttp named "web" is the gate.
. "$(dirname "$0")/lib.sh"
lock=$1
LOCKS=${LOCKS:-"web:lockhttp api:lockhttp"}
ws=$(mktemp -d)/projects
mkdir -p "$ws"
cd "$ws"
agents="$E2E_ID-agents"
gate="$E2E_ID-gate"
cleanup() {
	docker rm -f "$gate" "$E2E_ID-agent" >/dev/null 2>&1 || true
	if [ -f .lockfamily/up.json ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	docker network rm "$agents" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "lock add: each lock pinned to its latest signed release"
for l in $LOCKS; do
	"$lock" add "${l#*:}" "${l%%:*}"
done
cat .lockfamily/lockfamily.yaml

say "the locks' own profiles"
mkdir -p .lockhttp
cat >.lockhttp/config.toml <<'TOML'
[profiles.default]
mode = "enforce"
heuristics = "off"
buffer_limit = "1MiB"
hold = "90s"
connect_grant = "1m"
trusted = []
splice = []
deny = []
TOML
chmod 0644 .lockhttp/config.toml

say "lock up (review at a terminal)"
tty 'y\n' "$lock" up | tee up.out
grep -q "First lock up of this workspace" up.out || die "no full review on the first lock up"
grep -q "  profile lockhttp " up.out || die "the profile is not in the review"
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
jq . .lockfamily/up.json

say "each console asks its policy at its terminal: lock attach"
for l in $LOCKS; do
	n=${l%%:*}
	# y to the policy, then detach (Ctrl-P Ctrl-Q).
	(sleep 3; printf 'y\n'; sleep 8; printf '\020\021') | timeout 60 script -qefc "$lock attach $n" /dev/null || true
done
sleep 5
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" ps
running=$(docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" ps --status running --services | sort | tr '\n' ' ')
echo "running: $running"
for s in lockhub $(for l in $LOCKS; do echo "lock-${l%%:*}"; done); do
	case " $running " in *" $s "*) ;; *) die "service $s is not running" ;; esac
done
for l in $LOCKS; do
	n=${l%%:*}
	docker run --rm --network none -v "${p}_$n-run:/r:ro" alpine:3.22 sh -c 'ls -la /r; ls /r | grep -q "\.sock$"' ||
		die "no console socket in ${p}_$n-run"
done

say "the gate, as lea runs it: on the hub network, beside the agents"
docker network create "$agents" >/dev/null
hubnet=$(jq -r .hub_network .lockfamily/up.json)
subnet=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$hubnet")
img=$(sed -n '/^  web:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
docker run -d --name "$gate" --network "$hubnet" --user 10003:10020 \
	-v "${p}_web-run:/run/lockhttp" -v "${p}_web-gate:/g" -v "${p}_hubkey:/run/lockfamily:ro" \
	"$img" gate --listen 0.0.0.0:3128 --profile default \
	--hub "$(jq -r .hub_url .lockfamily/up.json)" --hub-plain-http --hub-key-file /run/lockfamily/hub.pub \
	--instance web --home /g --hub-net "$subnet" >/dev/null
docker network connect "$agents" "$gate"
sleep 5
docker logs "$gate" 2>&1 | tail -5
hubip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$hubnet\").IPAddress}}" "${p}-lockhub-1")
agent() { docker run --rm --network "$agents" curlimages/curl:8.11.1 -sS -m 10 "$@"; }

say "I2: no route from an agent to the hub"
agent "http://lockhub:8443/v1/hello" && die "an agent reached the hub by name"
agent "http://$hubip:8443/v1/hello" && die "an agent reached the hub by address"
say "I2: not through the gate either"
for u in "http://lockhub:8443/v1/hello" "http://$hubip:8443/v1/hello"; do
	code=$(agent -o /dev/null -w '%{http_code}' -x "http://$gate:3128" "$u" || true)
	echo "$u via the gate: $code"
	case "$code" in 2??) die "an agent reached the hub through the gate ($u)" ;; esac
done

say "a ticket, approved through the facade socket"
# A write (a body the agent chose): the gate holds it and asks the hub.
agent -o /dev/null -w '%{http_code}\n' -x "http://$gate:3128" -m 120 -d probe=1 "http://example.com/" >curl.out 2>&1 &
cpid=$!
ok=""
for i in $(seq 1 30); do
	sleep 2
	tty 'y\n' "$lock" approve --once >approve.out 2>&1 || true
	if tr -d '\r' <approve.out | grep -q '^approved'; then ok=1; break; fi
done
cat approve.out
if [ -z "$ok" ]; then
	cat curl.out
	docker logs "$gate" 2>&1 | tail -20
	docker logs "${p}-lockhub-1" 2>&1 | tail -20
	die "no ticket approved"
fi
wait "$cpid" || true
cat curl.out
# example.com answers a POST with 200 or an error of its own: what counts
# is that the gate let it out (not 403/E_DENIED or 5xx of the gate).
code=$(tr -d '\r' <curl.out | tail -1)
case "$code" in 2??|3??|404|405|411) ;; *) docker logs "$gate" 2>&1 | tail -20; die "the approved request did not pass ($code)" ;; esac
"$lock" audit verify --data "$state/hub" --hub-key-file "$state/hub.pub"

say "I11: .lockfamily is read-only for an agent (mounted as lea mounts it)"
docker run --rm --user "$(id -u):$(id -g)" -v "$ws:$ws" -v "$ws/.lockfamily:$ws/.lockfamily:ro" alpine:3.22 \
	sh -c "echo x >>'$ws/.lockfamily/lockfamily.yaml'" 2>err.out && die "an agent wrote lockfamily.yaml"
grep -qi 'read-only' err.out || die "not EROFS: $(cat err.out)"
say "I11: a change of lockfamily.yaml is reviewed, not applied silently"
"$lock" add lockhttp extra >/dev/null
tty 'n\n' "$lock" up >up2.out 2>&1 || true
grep -q "+ lock extra" up2.out || die "the change was not shown"
grep -q 'not applied' up2.out || die "the change was applied without a yes"
echo "phase 2: OK"
