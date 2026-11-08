#!/bin/sh
# A host agent reaches a lox run lockssh lock (lockhub#133, one e2e per
# lock type as lockhub#78): `lox add lockssh web` pins lockssh's latest
# signed release; its profile names an SSH server in a container of this
# machine (host.docker.internal), a key and a known_hosts file in the
# lock's home, which lox run's review says are missing and how to copy
# them there (the command it prints is the one run here). `lockssh init
# claude` (the launcher, LOCKSSH_LAUNCHER, at the release lox add pins)
# writes the agent's .mcp.json, and lox run (this commit's hub) reviews
# the lock, its egress, its auto rules and its routing, and starts it.
# The agent then runs what .mcp.json says (`lockssh mcp`, through the
# socket volume up.json names): an allow-listed command whose output holds
# e-mail addresses, masked, once the human approved the first connection;
# then a command outside the allow list, pending on the hub, approved at
# the terminal facade (lox approve), and run with the ticket.
#
# Flow: agent -> lockssh client (launcher) -> socket -> console -> masked
# ticket -> hub -> facade -> signed decision -> console -> SSH -> agent.
# The agent never holds the key, nor talks to the hub.
#
#   LOCKSSH_LAUNCHER=.../scripts/lockssh ci/e2e/lockssh-agent.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
[ -n "${LOCKSSH_LAUNCHER:-}" ] && [ -f "$LOCKSSH_LAUNCHER" ] || die "LOCKSSH_LAUNCHER (lockssh's scripts/lockssh) is not set"
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
bin=$(dirname "$ws")/bin
keys=$(dirname "$ws")/keys
sshd=lockssh-sshd-$E2E_ID
port=${SSH_PORT:-22022}
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	docker rm -f "$sshd" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

say "an SSH server: alpine's openssh, login deploy by key only, a log with e-mail addresses"
mkdir -p "$keys"
ssh-keygen -q -t ed25519 -N '' -C lockssh-e2e -f "$keys/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -C sshd-e2e -f "$keys/host_ed25519"
chmod 0644 "$keys/host_ed25519" # read by the container's root only, from a throwaway mount
docker run -d --name "$sshd" -p "$port:22" -v "$keys:/keys:ro" alpine:3.22 sh -c '
	set -e
	apk add --no-cache openssh >/dev/null
	adduser -D -s /bin/sh deploy
	sed -i "s/^deploy:!/deploy:*/" /etc/shadow
	install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh
	install -m 0600 -o deploy -g deploy /keys/id_ed25519.pub /home/deploy/.ssh/authorized_keys
	install -m 0600 /keys/host_ed25519 /etc/ssh/ssh_host_ed25519_key
	printf "%s\n" "time=2026-11-08T10:00:00Z msg=\"payment failed\" user=alice.e2e@example.com" \
		"time=2026-11-08T10:00:05Z msg=\"payment ok\" user=bob.e2e@example.com" >/home/deploy/app.log
	chown deploy:deploy /home/deploy/app.log
	exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=no \
		-o HostKey=/etc/ssh/ssh_host_ed25519_key -o AllowTcpForwarding=no -o AllowAgentForwarding=no -o X11Forwarding=no
' >/dev/null
ok=""
for i in $(seq 1 60); do
	if docker logs "$sshd" 2>&1 | grep -q 'Server listening'; then ok=1; break; fi
	sleep 1
done
[ -n "$ok" ] || { docker logs "$sshd"; die "sshd did not start"; }
# The host key the profile pins: a key it does not hold is refused, so
# the console asks no trust question.
printf '[host.docker.internal]:%s %s\n' "$port" "$(cut -d' ' -f1,2 "$keys/host_ed25519.pub")" >"$keys/known_hosts.e2e"

say "lox add lockssh web: pinned to lockssh's latest signed release"
"$lox" add lockssh web --profile e2e
local_hub .lockfamily/lockfamily.yaml
img=$(sed -n '/^  web:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
case "$img" in ghcr.io/davidgodefroid/lockssh@sha256:*) ;; *) die "lox add pinned no lockssh image: $img" ;; esac
# Readable by the agent account the launcher's mcp runs as; writable by
# you only.
mkdir -p .lockssh && chmod 0755 .lockssh
cat >.lockssh/config.toml <<EOF
[profiles.e2e]
host        = "host.docker.internal"
port        = $port
user        = "deploy"
auth        = "key"
key         = "~/.ssh/id_ed25519"
credentials = "none"
known_hosts = "~/.ssh/known_hosts.e2e"
production  = false
exec        = true
allow       = ["cat /home/deploy/app.log", "uptime"]
EOF
chmod 0644 .lockssh/config.toml

say "lockssh init claude: the agent's .mcp.json, as the launcher writes it"
mkdir -p "$bin"
cp "$LOCKSSH_LAUNCHER" "$bin/lockssh"
chmod 0755 "$bin/lockssh"
PATH="$bin:$PATH"
export PATH
LOCKSSH_IMAGE="$img" lockssh init claude </dev/null || die "lockssh init claude failed"
[ -f .mcp.json ] || die "lockssh init claude wrote no .mcp.json"
cat .mcp.json
mcpcmd=$(jq -r '.mcpServers.lockssh.command' .mcp.json)
[ "$mcpcmd" = lockssh ] || die ".mcp.json: the lockssh server's command is $mcpcmd, not lockssh"
jq -e '.mcpServers.lockssh.args == ["mcp"]' .mcp.json >/dev/null || die ".mcp.json: the lockssh server's args are not [\"mcp\"]"

say "lox run, a first look: the review says the key and known_hosts are not in the lock's home, and how to copy them"
python3 "$here/expect.py" 600 'Apply? [y/N]' 'n\n' -- "$lox" run >look.raw 2>&1 || true
tr -d '\r' <look.raw >look.out
grep -q 'Apply? \[y/N\]' look.out || { cat look.out; die "lox run did not reach its review"; }
for f in id_ed25519 known_hosts.e2e; do
	cmd=$(sed -n "s/.* is not in the lock's home volume; copy it there: \(docker run .* < $f\)\$/\1/p" look.out | head -1)
	[ -n "$cmd" ] || { cat look.out; die "the review gives no command to copy $f into the lock's home"; }
	echo "copy: $cmd"
	(cd "$keys" && sh -c "$cmd") || die "the review's copy command for $f failed"
done

say "lox run: the review shows the lock, its egress, its auto rules and its routing"
python3 "$here/expect.py" 600 'Apply? [y/N]' 'y\n' "up: project " "<pause>qq" -- "$lox" run >run.raw 2>&1 || { tr -d '\r' <run.raw; die "lox run failed"; }
tr -d '\r' <run.raw >run.out
sed -n '1,/^up: project /p' run.out
hub_cosigned run.out
p=$(ws_project "$ws")
hub_is_local "$p"
for want in \
	"ssh deploy@host.docker.internal:$port" \
	"lock web auto rules of profile e2e: connect ask · run auto · exec ask · unmask ask (lockssh profile rules, on the reviewed copy)" \
	"lock web answers read-pii on the local facades only, never in a chat (lockssh's default)"; do
	grep -qF "$want" run.out || die "the review lacks: $want"
done
grep -q "is not in the lock's home volume" run.out && die "the review still says a file is missing from the lock's home"
jq -e '.e2e.lock == "lockssh" and .e2e.rules == {"connect":"ask","run":"auto","exec":"ask","unmask":"ask"}' "$XDG_STATE_HOME/lockfamily/$p/lockssh/web/rules.json" >/dev/null ||
	{ cat "$XDG_STATE_HOME/lockfamily/$p/lockssh/web/rules.json"; die "rules.json does not keep the auto rules lox run applied"; }

say "the console's first start: its policy, approved at its terminal (lox attach)"
python3 "$here/attach.py" 120 'y\n' 'Listening on ' -- "$lox" attach web >attach.out 2>&1 || {
	cat attach.out
	die "the lockssh console did not start listening once its policy was approved"
}
tr -d '\r' <attach.out | tail -5

# hostssh TOOL ARGS: one MCP call, as the agent's harness makes it from
# .mcp.json: its command and args, from the workspace.
hostssh() { LOCKSSH_IMAGE="$img" python3 "$here/mcp.py" 300 "$@" -- "$mcpcmd" mcp; }
clear_values='alice.e2e@example.com bob.e2e@example.com'
masked() {
	for v in $clear_values; do
		grep -qF "$v" "$1" && { cat "$1"; die "$1: the clear value $v reached the agent"; }
	done
	return 0
}
# approve_one WHAT: one pending ticket approved at the terminal facade;
# its id on stdout.
approve_one() {
	for i in $(seq 1 60); do
		tty 'y\n' "$lox" approve --once >approve.out 2>&1 || true
		if tr -d '\r' <approve.out | grep -Eq '(^|: )approved$'; then
			masked approve.out
			tr -d '\r' <approve.out | grep -q lockssh || die "the facade screen of the $1 does not name the lockssh lock"
			return 0
		fi
		sleep 2
	done
	cat approve.out
	docker logs "${p}-lockhub-1" 2>&1 | tail -20
	die "the $1 ticket was not approved"
}

say "a host agent: lockssh_status through up.json's socket volume"
hostssh lockssh_status '{}' >status.json 2>status.err || { cat status.json status.err; die "lockssh_status failed"; }
cat status.json
jq -e '[.data[] | select(.profile == "e2e" and .running == true)] | length == 1' status.json >/dev/null || die "lockssh_status: the console of profile e2e is not running"

say "a host agent: an allow-listed command; its first connection approved by the human; its output masked"
run_log='{"argv":["cat","/home/deploy/app.log"],"intent":"e2e: who failed to pay"}'
hostssh lockssh_run "$run_log" >run1.json 2>run1.err &
agent=$!
# The first use of an SSH session is a connect ticket (read-pii, never
# auto on the console's first run): the human approves it.
approve_one connect
wait "$agent" || { cat run1.json run1.err; die "lockssh_run failed"; }
cat run1.json
if jq -e '.data.status == "pending"' run1.json >/dev/null 2>&1; then
	# The connection was decided after the call answered: run it again.
	hostssh lockssh_run "$run_log" >run1.json 2>run1.err || { cat run1.json run1.err; die "lockssh_run failed"; }
	cat run1.json
fi
masked run1.json
jq -e '.data.exit_status == 0' run1.json >/dev/null || die "lockssh_run: cat did not exit 0"
grep -q '⟦email:' run1.json || die "lockssh_run: the output holds no e-mail pseudonym"

say "a host agent: a command outside the allow list, pending on the hub (exec)"
touched=/home/deploy/lockssh-$E2E_ID
run_exec="{\"argv\":[\"touch\",\"$touched\"],\"intent\":\"e2e: a write the human approves\""
hostssh lockssh_run "$run_exec}" >exec1.json 2>exec1.err || { cat exec1.json exec1.err; die "lockssh_run (exec) failed"; }
cat exec1.json
jq -e '.data.status == "pending" and .data.lock == "lockssh" and .data.instance == "web"' exec1.json >/dev/null ||
	die "lockssh_run (exec) did not answer pending on the instance web"
ticket=$(jq -r .data.ticket exec1.json)
[ -n "$ticket" ] && [ "$ticket" != null ] || die "lockssh_run (exec): no ticket"
docker exec "$sshd" test -e "$touched" && die "the command ran before the human decided"

say "the exec (write), approved at the terminal facade"
approve_one exec
tr -d '\r' <approve.out | grep -q "$ticket" || die "the approved ticket is not the agent's exec ($ticket)"

say "the exec run with the ticket"
ok=""
for i in $(seq 1 30); do
	if hostssh lockssh_run "$run_exec,\"ticket\":\"$ticket\"}" >exec2.json 2>exec2.err && jq -e '.data.exit_status == 0' exec2.json >/dev/null 2>&1; then ok=1; break; fi
	jq -e --arg t "$ticket" '.data.status == "pending" and .data.ticket == $t' exec2.json >/dev/null 2>&1 ||
		grep -q "no decision yet" exec2.json || break
	sleep 2
done
cat exec2.json
[ -n "$ok" ] || { cat exec2.err; die "the approved exec did not run"; }
docker exec "$sshd" test -e "$touched" || die "the approved command did not run on the server"

say "PASS: a host agent reaches a lox run lockssh lock: a masked run, then an approved command"
