#!/bin/sh
# A host agent reaches a lox run locklog lock (lockhub#132, one e2e per
# lock type as lockhub#78): `lox add locklog logs` pins locklog's latest
# signed release, its profile reads a log file under /var/log, `locklog
# init claude` (the launcher, LOCKLOG_LAUNCHER, at the release lox add
# pins) writes the agent's .mcp.json, and lox run (this commit's hub)
# reviews the lock, its mount plan, its auto rules and its routing, and
# starts it. The agent then runs what .mcp.json says (`locklog mcp`,
# through the socket volume up.json names): a count, masked and free of
# any ticket, then an unmask of one e-mail address of a record, pending on
# the hub, approved at the terminal facade (lox approve), and run with
# the ticket: the clear value, to the agent only.
#
# Flow: agent -> locklog client (launcher) -> socket -> console -> masked
# ticket -> hub -> facade -> signed decision -> console -> agent. The agent
# never talks to the hub.
#
#   LOCKLOG_LAUNCHER=.../scripts/locklog ci/e2e/locklog-agent.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
[ -n "${LOCKLOG_LAUNCHER:-}" ] && [ -f "$LOCKLOG_LAUNCHER" ] || die "LOCKLOG_LAUNCHER (locklog's scripts/locklog) is not set"
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
logs=/var/log/lockhub-agent-$E2E_ID
bin=$(dirname "$ws")/bin
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	sudo rm -rf "$logs"
}
trap cleanup EXIT INT TERM

# locklog136 FILE: the run in FILE failed only because the console, with
# local sources only, refused lox run's internal hub network: locklog#136
# (released after locklog v0.2.0) makes it accept that network. Until the
# locklog release lox ships with has it, the agent's half is skipped, and
# says so; any other failure fails.
locklog136() {
	if grep -qE "the console has a network \(.*\) but (in hub mode|its profile reads only local logs)" "$1"; then
		cat "$1"
		say "SKIP: the agent's session on a local-only locklog console needs locklog#136 (a local-only console accepts lox run's internal hub network), not in locklog v0.2.0; the review, the start and the console's policy above passed"
		exit 0
	fi
}

say "host logs: a logfmt file with e-mail addresses (personal data the console masks)"
sudo mkdir -p "$logs/app"
{
	echo 'time=2026-11-06T10:00:00Z level=error msg="payment failed" user=alice.e2e@example.com status=502'
	echo 'time=2026-11-06T10:00:05Z level=info msg="payment ok" user=bob.e2e@example.com status=200'
	echo 'time=2026-11-06T10:00:09Z level=error msg="payment failed" user=carol.e2e@example.com status=502'
} | sudo tee "$logs/app/app.log" >/dev/null
sudo chmod 0755 "$logs/app"
sudo chmod 0644 "$logs/app/app.log"

say "lox add locklog logs: pinned to locklog's latest signed release"
"$lox" add locklog logs --profile files
local_hub .lockfamily/lockfamily.yaml
img=$(sed -n '/^  logs:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
case "$img" in ghcr.io/davidgodefroid/locklog@sha256:*) ;; *) die "lox add pinned no locklog image: $img" ;; esac
mkdir -p .locklog && chmod 0700 .locklog
cat >.locklog/config.toml <<EOF
version = 1

[profiles.files]
production = false

[profiles.files.sources.app]
kind = "file"
paths = ["$logs/app/*.log"]
format = "logfmt"
EOF
chmod 0600 .locklog/config.toml

say "locklog init claude: the agent's .mcp.json, as the launcher writes it"
mkdir -p "$bin"
cp "$LOCKLOG_LAUNCHER" "$bin/locklog"
chmod 0755 "$bin/locklog"
PATH="$bin:$PATH"
export PATH
LOCKLOG_IMAGE="$img" locklog init claude </dev/null || die "locklog init claude failed"
[ -f .mcp.json ] || die "locklog init claude wrote no .mcp.json"
cat .mcp.json
mcpcmd=$(jq -r '.mcpServers.locklog.command' .mcp.json)
[ "$mcpcmd" = locklog ] || die ".mcp.json: the locklog server's command is $mcpcmd, not locklog"
jq -e '.mcpServers.locklog.args == ["mcp"]' .mcp.json >/dev/null || die ".mcp.json: the locklog server's args are not [\"mcp\"]"

say "lox run: the review shows the lock, its plan, its auto rules and its routing"
python3 "$here/expect.py" 600 'Apply? [y/N]' 'y\n' "up: project " "<pause>qq" -- "$lox" run >run.raw 2>&1 || { tr -d '\r' <run.raw; die "lox run failed"; }
tr -d '\r' <run.raw >run.out
sed -n '1,/^up: project /p' run.out
hub_cosigned run.out
p=$(ws_project "$ws")
hub_is_local "$p"
for want in \
	"lock logs plan file $logs/app $logs/app/*.log" \
	"lock logs bind $logs/app (read-only, non-recursive)" \
	"lock logs network lockhub only (local sources: no route out)" \
	"lock logs auto rules of profile files: read ask · unmask ask · lookup ask (locklog profile rules, on the reviewed copy)" \
	"lock logs routed only to tty,deck (locklog's default: no chat facade)"; do
	grep -qF "$want" run.out || die "the review lacks: $want"
done
jq -e '.rules.profile == "files" and .rules.rules == {"read":"ask","unmask":"ask","lookup":"ask"}' "$XDG_STATE_HOME/lockfamily/$p/locklog/logs/plan.json" >/dev/null ||
	{ cat "$XDG_STATE_HOME/lockfamily/$p/locklog/logs/plan.json"; die "plan.json does not keep the auto rules lox run applied"; }

say "the console's first start: its policy, approved at its terminal (lox attach)"
python3 "$here/attach.py" 120 'y\n' 'Listening on ' -- "$lox" attach logs >attach.out 2>&1 || {
	locklog136 attach.out
	cat attach.out
	die "the locklog console did not start listening once its policy was approved"
}
tr -d '\r' <attach.out | tail -5

# hostlog TOOL ARGS: one MCP call, as the agent's harness makes it from
# .mcp.json: its command and args, from the workspace.
hostlog() { LOCKLOG_IMAGE="$img" python3 "$here/mcp.py" 120 "$@" -- "$mcpcmd" mcp; }
clear_values='alice.e2e@example.com bob.e2e@example.com carol.e2e@example.com'
# masked FILE: no clear e-mail address of the log in FILE.
masked() {
	for v in $clear_values; do
		grep -qF "$v" "$1" && { cat "$1"; die "$1: the clear value $v reached the agent"; }
	done
	return 0
}

say "a host agent: locklog_status through up.json's socket volume"
hostlog locklog_status '{}' >status.json 2>status.err || { cat status.json status.err; locklog136 status.json; locklog136 status.err; die "locklog_status failed"; }
cat status.json
locklog136 status.json
grep -q "console running" status.json || die "locklog_status: the console is not running"

say "a host agent: a count, masked, with no ticket"
range='"from":"2026-11-06T09:00:00Z","to":"2026-11-06T11:00:00Z"'
hostlog locklog_count "{$range}" >count.json 2>count.err || { cat count.json count.err; locklog136 count.json; die "locklog_count failed"; }
cat count.json
masked count.json
[ "$(jq '[.data.groups[].n | tonumber] | add' count.json)" = 3 ] || die "locklog_count: want 3 records"

say "a host agent: a record's pseudonym, then its unmask, pending on the hub"
hostlog locklog_search "{$range,\"limit\":1}" >search.json 2>search.err ||
	{ cat search.json search.err; die "locklog_search failed"; }
cat search.json
masked search.json
ref=$(jq -r '.data.records[0].ref' search.json)
tok=$(jq -c '.data.records[0]' search.json | grep -o '⟦email:[A-Z0-9]*⟧' | head -1)
[ -n "$ref" ] && [ "$ref" != null ] && [ -n "$tok" ] || die "locklog_search: no record ref or e-mail pseudonym"
unmask() { printf '{"ref":"%s","pseudonyms":["%s"],"reason":"e2e: the user asked who failed to pay"%s}' "$ref" "$tok" "$1"; }
hostlog locklog_unmask "$(unmask '')" >unmask1.json 2>unmask1.err || { cat unmask1.json unmask1.err; die "locklog_unmask failed"; }
cat unmask1.json
masked unmask1.json
jq -e '.data.status == "pending" and .data.lock == "locklog" and .data.instance == "logs"' unmask1.json >/dev/null ||
	die "locklog_unmask did not answer pending on the instance logs"
ticket=$(jq -r .data.ticket unmask1.json)
[ -n "$ticket" ] && [ "$ticket" != null ] || die "locklog_unmask: no ticket"

say "the unmask (read-pii), approved at the terminal facade"
ok=""
for i in $(seq 1 30); do
	tty 'y\n' "$lox" approve --once >approve.out 2>&1 || true
	if tr -d '\r' <approve.out | grep -Eq '(^|: )approved$'; then ok=1; break; fi
	sleep 2
done
cat approve.out
[ -n "$ok" ] || { docker logs "${p}-lockhub-1" 2>&1 | tail -20; die "the unmask ticket was not approved"; }
tr -d '\r' <approve.out | grep -q "$ticket" || die "the approved ticket is not the agent's unmask ($ticket)"
tr -d '\r' <approve.out | grep -q 'locklog' || die "the facade screen does not name the locklog lock"
masked approve.out

say "the unmask run with the ticket: the clear value, to the agent"
# clear FILE: the clear values of the log FILE holds, one per line.
clear() { for v in $clear_values; do grep -qF "$v" "$1" && echo "$v"; done; return 0; }
ok=""
for i in $(seq 1 30); do
	if hostlog locklog_unmask "$(unmask ",\"ticket\":\"$ticket\"")" >unmask2.json 2>unmask2.err && [ -n "$(clear unmask2.json)" ]; then ok=1; break; fi
	jq -e --arg t "$ticket" '.data.status == "pending" and .data.ticket == $t' unmask2.json >/dev/null 2>&1 ||
		grep -q "no decision yet" unmask2.json || break
	sleep 2
done
cat unmask2.json
[ -n "$ok" ] || { cat unmask2.err; die "the approved unmask did not give the clear value"; }
# One record, one pseudonym: exactly one address, the record's.
[ "$(clear unmask2.json | wc -l)" = 1 ] || die "the unmask gave more than the one pseudonym's value: $(clear unmask2.json | tr '\n' ' ')"
got=$(clear unmask2.json)
echo "host agent: $tok of the record unmasked as $got, approved as $ticket"
# The hub keeps the masked ticket only: never the clear value.
docker run --rm --network none -v "$XDG_STATE_HOME/lockfamily/$p/hub:/h:ro" alpine:3.22 sh -c 'cat /h/* 2>/dev/null' | grep -aqF "$got" &&
	die "the hub's data holds the clear value"

say "PASS: a host agent reaches a lox run locklog lock: a masked count, then an approved unmask"
