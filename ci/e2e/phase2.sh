#!/bin/sh
# Phase 2 of the hub plan, end to end: lock up on a lockfamily.yaml with a
# database lock (locksql, on the job's Postgres) and LockHTTP starts the
# stack; tickets are approved through the facade socket (lock approve, at a
# terminal): a LockHTTP write held by the gate, and a locksql query an
# agent's container plans and runs (pending, approved, run by ticket,
# PII masked by the rule set the console wrote in its own volume at its
# first start: lockhub#41); an agent can reach the hub neither
# directly nor through the LockHTTP gate (I2); lock up's side of I11: a
# legacy root lockfamily.yaml is copied into .lockfamily, a planted root file
# is never read once .lockfamily exists, a .lockfamily others can write
# or that is a link is refused. The hub is this commit's build
# (E2E_HUB_IMAGE, ci/e2e/local-hub.sh), not the release lock add pins.
#
#   ci/e2e/phase2.sh LOCK_BIN
#
# Locks: LOCKS="name:type ..." (default: locksql db, LockHTTP web and api);
# a lockhttp named "web" is the gate, "api" the control gate without
# --hub-net, a locksql named "db" serves Postgres at PGHOST:PGPORT
# (superuser postgres, password PGPASSWORD, both required by default: a
# throwaway server, the workflow's container; the script creates the app
# database and the ro role in it, and drops both at exit, only if it
# created them: a server that already has one makes the run fail first).
#
# The deck facade (lea's deck, lea#182/#200) is not driven here: lea
# routes a hub ticket only to the deck of the lea container whose agent
# asked (internal/daemon/hubdeck.go: hubDecide), so a deck approval needs
# lea's daemon and an agent container, which lea's own tests cover. The
# deck and lock approve speak the same facade socket API (queue, decide),
# which lock approve at a pty exercises here.
. "$(dirname "$0")/lib.sh"
lock=$1
LOCKS=${LOCKS:-"db:locksql web:lockhttp api:lockhttp"}
here=$(cd "$(dirname "$0")" && pwd)
case " $LOCKS " in *" db:locksql "*) sql=1 ;; *) sql="" ;; esac
# Canonical (lock up prints resolved paths; a TMPDIR may be a link).
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
agents="$E2E_ID-agents"
gate="$E2E_ID-gate"
pg() { docker run --rm --network host -e PGPASSWORD="$PGPASSWORD" postgres:17 psql -v ON_ERROR_STOP=1 -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" -U postgres "$@"; }
# What this run created on the Postgres server, dropped at exit.
made_db="" made_role=""
cleanup() {
	docker rm -f "$gate" "$gate-ctl" "$E2E_ID-squat" >/dev/null 2>&1 || true
	# A run that died while .lockfamily was moved aside (the link check).
	if [ ! -f "$ws/.lockfamily/up.json" ] && [ -f "$ws/lf-real/up.json" ]; then
		rm -f "$ws/.lockfamily" || true
		mv "$ws/lf-real" "$ws/.lockfamily" || true
	fi
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	docker network rm "$agents" >/dev/null 2>&1 || true
	# After compose down: no console holds a session any more (FORCE ends
	# one left anyway). The database first: the role's grants live in it.
	if [ -n "$made_db" ]; then
		pg -c "DROP DATABASE IF EXISTS app WITH (FORCE)" >/dev/null 2>&1 || echo "e2e: could not drop the database app" >&2
	fi
	if [ -n "$made_role" ]; then
		pg -c "DROP ROLE IF EXISTS ro" >/dev/null 2>&1 || echo "e2e: could not drop the role ro" >&2
	fi
}
trap cleanup EXIT INT TERM

say "lock add: each lock pinned to its latest signed release"
for l in $LOCKS; do
	"$lock" add "${l#*:}" "${l%%:*}"
done
local_hub .lockfamily/lockfamily.yaml
# lea's agents run as the host user's uid, which has no account in the
# lock's image: the locksql lock names one (allowed_uids, locksql v0.11.2).
if [ -n "$sql" ]; then
	sed -i '/^  db:$/a\    allowed_uids: [4242]' .lockfamily/lockfamily.yaml
	grep -q '^    allowed_uids: \[4242\]$' .lockfamily/lockfamily.yaml || die "allowed_uids not added to the db lock"
fi
# The layout before .lockfamily: lockfamily.yaml at the workspace's root.
mv .lockfamily/lockfamily.yaml lockfamily.yaml
rmdir .lockfamily
cp lockfamily.yaml reviewed.yaml
cat lockfamily.yaml

say "the locks' own profiles"
if [ -n "$sql" ]; then
	say "Postgres: a read-only account and a table with personal data"
	pg -c "CREATE DATABASE app" >/dev/null
	made_db=1
	pg -d app -c "CREATE ROLE ro LOGIN PASSWORD 'ro-e2e-only'" >/dev/null
	made_role=1
	pg -d app -c "CREATE TABLE people (id int PRIMARY KEY, email text NOT NULL, label text NOT NULL);
INSERT INTO people VALUES (1, 'alice@example.com', 'alpha'), (2, 'bob@example.com', 'beta');
GRANT SELECT ON people TO ro;" >/dev/null
	# No PII rule set: the console writes its first one in its own
	# volume (LOCKSQL_PII_DIR), the profile's copy being read-only. The
	# throwaway server has no TLS (host.docker.internal is not local to
	# locksql, whose default is then verify-full).
	mkdir -p .locksql
	printf '[profiles.e2e]\nengine = "postgres"\nhost = "host.docker.internal"\nport = %s\nuser = "ro"\ndatabase = "app"\ntls = "disable"\n' "${PGPORT:-5432}" >.locksql/config.toml
	chmod 0644 .locksql/config.toml
fi
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

# The worst case for I2: the policy itself lets the agents reach a host
# named lockhub, on the hub's port, read freely. Only the gate's hub rule
# (lockhttp#11) stands between them and the hub.
[[profiles.default.internal_hosts]]
host = "lockhub"
ports = [80, 443, 8443]
read = true

# Another name of the hub on its network (an alias lock up never made):
# only the hub-network rule (--hub-net) can refuse it.
[[profiles.default.internal_hosts]]
host = "e2ehubalias"
ports = [8443]
read = true
TOML
chmod 0644 .lockhttp/config.toml
# A subdirectory and an owner-only file: the copy keeps both.
mkdir -p .lockhttp/notes && chmod 0700 .lockhttp/notes && echo note >.lockhttp/notes/n.txt && chmod 0600 .lockhttp/notes/n.txt

say "lock up (review at a terminal)"
tty 'y\n' "$lock" up >up.out 2>&1 || { cat up.out; die "lock up failed"; }
cat up.out
grep -q "up: project " up.out || die "lock up did not finish"
grep -q "First lock up of this workspace" up.out || die "no full review on the first lock up"
grep -q "  profile lockhttp " up.out || die "the profile is not in the review"
[ -z "$sql" ] || grep -q "  profile locksql " up.out || die "the locksql profile is not in the review"
[ -z "$sql" ] || grep -q "lock db serves uids 4242 besides its clients group" up.out || die "the db lock's allowed_uids is not in the review"
say "I11: the legacy root file is read with a warning and copied, exactly as reviewed; the human removes it"
grep -q "warning: $ws/lockfamily.yaml is at the workspace's root" up.out || die "no warning about the legacy root lockfamily.yaml"
grep -qF "lockfamily.yaml now lives in $ws/.lockfamily/lockfamily.yaml (lea's agents only read it there); remove $ws/lockfamily.yaml" up.out || die "the legacy file was not copied into .lockfamily"
cmp reviewed.yaml .lockfamily/lockfamily.yaml || die ".lockfamily/lockfamily.yaml is not what was reviewed"
cmp reviewed.yaml lockfamily.yaml || die "lock up changed the root lockfamily.yaml (it copies, the human removes)"
rm lockfamily.yaml
say "lock up checked the hub's signer identity (on the release lock add pinned)"
hub_cosigned up.out
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
jq . .lockfamily/up.json
# What lea's gate pins (lockhub#40): said, and nothing pinned here (no
# devices: true, no device paired).
jq -e '.lockhttp_gate == 1 and (has("devices") | not) and ([.locks[] | select(.devices or .seal_clear or .require_device)] | length == 0)' .lockfamily/up.json >/dev/null ||
	die "up.json does not say what the lockhttp gate pins (lockhttp_gate 1)"
hub_is_local "$p"

say "each console asks its policy at its terminal: lock attach"
for l in $LOCKS; do
	n=${l%%:*}
	case "${l#*:}" in
	locksql)
		# y to the policy, the password, a to the PII proposal (the first
		# rule set, written in the console's volume), then detach.
		python3 "$here/attach.py" 90 'y\n' 'Listening' 'Password for ro@' 'ro-e2e-only\n' 'Accept all [a]' 'a\n' -- "$lock" attach "$n" >attach.out 2>&1 ||
			{ cat attach.out; die "the console of $n did not start listening"; }
		grep -q '(approved policy)' attach.out || { cat attach.out; die "the console of $n did not approve its policy"; }
		grep -q 'Accept all \[a\]' attach.out || { cat attach.out; die "no PII proposal at the first start of $n: the email column must be proposed"; }
		;;
	*)
		python3 "$here/attach.py" 60 'y\n' '(approved policy)' -- "$lock" attach "$n" >attach.out 2>&1 ||
			{ cat attach.out; die "the console of $n did not approve its policy"; }
		;;
	esac
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
# The control: a gate as lea would run it without --hub-net (lockhttp
# instance api). It knows the hub only by the name and the address it
# had at start.
docker run -d --name "$gate-ctl" --network "$hubnet" --user 10003:10020 \
	-v "${p}_api-run:/run/lockhttp" -v "${p}_api-gate:/g" -v "${p}_hubkey:/run/lockfamily:ro" \
	"$img" gate --listen 0.0.0.0:3128 --profile default \
	--hub "$(jq -r .hub_url .lockfamily/up.json)" --hub-plain-http --hub-key-file /run/lockfamily/hub.pub \
	--instance api --home /g >/dev/null
docker network connect "$agents" "$gate-ctl"
sleep 5
docker logs "$gate" 2>&1 | tail -5
hubip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$hubnet\").IPAddress}}" "${p}-lockhub-1")
agent() { docker run --rm --network "$agents" curlimages/curl:8.11.1 -sS -m 10 "$@"; }

say "the agents' network carries traffic (positive control: the timeouts below would prove nothing otherwise)"
code=$(agent -o /dev/null -w '%{http_code}' "http://$gate:3128/" || true)
echo "agent -> gate: $code"
case "$code" in 000|"") die "an agent cannot reach the gate on its network" ;; esac

say "I2: the hub answers on its own network (positive control)"
docker run --rm --network "$hubnet" curlimages/curl:8.11.1 -sS -m 10 -o /dev/null -w '%{http_code}\n' "http://lockhub:8443/v1/hello" | grep -qx 200 ||
	die "the hub does not answer on its network: the checks below would prove nothing"
say "I2: the hub's network is internal and publishes nothing"
[ "$(docker network inspect -f '{{.Internal}}' "$hubnet")" = true ] || die "the hub network is not internal"
[ -z "$(docker port "${p}-lockhub-1")" ] || die "the hub publishes a port"
say "I2: no route from an agent to the hub"
rc=0; agent "http://lockhub:8443/v1/hello" || rc=$?
[ "$rc" = 6 ] || die "an agent resolved the hub's name (curl exit $rc, want 6)"
rc=0; agent "http://$hubip:8443/v1/hello" || rc=$?
case "$rc" in 7|28) ;; *) die "an agent reached the hub's address (curl exit $rc, want 7 or 28)" ;; esac
say "I2 through the gate, though the policy allows the name: lockhttp's floor:hub and --hub-net rules (flags as lea passes them)"
for u in "http://lockhub:8443/v1/hello" "http://lockhub/v1/hello"; do
	code=$(agent -o /dev/null -w '%{http_code}' -x "http://$gate:3128" "$u" || true)
	echo "$u via the gate: $code"
	[ "$code" = 403 ] || die "the gate did not refuse $u ($code)"
done
# By another name resolving into the hub's network: the --hub-net rule.
# The hub moves to another address of its network, under a new name:
# neither the gates' start-time resolution nor the name rule covers it.
# (compose's network has no user subnet, so no --ip: a placeholder takes
# the hub's old address while it reconnects.)
docker network disconnect "$hubnet" "${p}-lockhub-1"
docker run -d --name "$E2E_ID-squat" --network "$hubnet" alpine:3.22 sleep 900 >/dev/null
docker network connect --alias lockhub --alias e2ehubalias "$hubnet" "${p}-lockhub-1"
got=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$hubnet\").IPAddress}}" "${p}-lockhub-1")
echo "hub moved from $hubip to $got"
[ -n "$got" ] && [ "$got" != "$hubip" ] || die "the hub did not move to a new address"
docker run --rm --network "$hubnet" curlimages/curl:8.11.1 -sS -m 10 -o /dev/null -w '%{http_code}\n' "http://e2ehubalias:8443/v1/hello" | grep -qx 200 ||
	die "the alias does not reach the hub on its network"
code=$(agent -o /dev/null -w '%{http_code}' -x "http://$gate:3128" "http://e2ehubalias:8443/v1/hello" || true)
echo "http://e2ehubalias:8443/v1/hello via the gate: $code"
[ "$code" = 403 ] || die "the gate did not refuse the hub's alias ($code)"
docker logs "$gate" 2>&1 | grep '"host":"e2ehubalias"' | tee alias.log
grep '"rule":"floor:hub"' alias.log | grep -q '"reason":"e2ehubalias is the approval hub' ||
	die "the alias was not refused by the hub-network rule (resolved into --hub-net)"
# Falsification: without --hub-net the same request reaches the hub.
code=$(agent -o /dev/null -w '%{http_code}' -x "http://$gate-ctl:3128" "http://e2ehubalias:8443/v1/hello" || true)
echo "http://e2ehubalias:8443/v1/hello via a gate without --hub-net: $code"
[ "$code" = 200 ] || die "control: a gate without --hub-net did not let it through ($code): the check above proves nothing"
code=$(agent -o /dev/null -w '%{http_code}' -x "http://$gate:3128" "http://$got:8443/v1/hello" || true)
echo "http://$got:8443/v1/hello (IP literal) via the gate: $code"
[ "$code" = 403 ] || die "the gate did not refuse the hub's address ($code)"
docker logs "$gate" 2>&1 | grep "\"host\":\"$got\"" | grep -q '"rule":"floor:' || die "no floor refusal logged for $got"
code=$(agent -o /dev/null -w '%{http_connect}' -x "http://$gate:3128" "https://lockhub:8443/v1/hello" || true)
echo "CONNECT lockhub:8443 via the gate: $code"
[ "$code" = 403 ] || die "the gate did not refuse a tunnel to the hub ($code)"
docker logs "$gate" 2>&1 | grep '"host":"lockhub"' >gate-hub.log || true
n=$(grep -c '"rule":"floor:hub"' gate-hub.log || true)
cat gate-hub.log
[ "$n" -ge 3 ] || die "the gate's hub rule (floor:hub) refused $n of 3 requests to the hub"
grep -v '"rule":"floor:hub"' gate-hub.log | grep -q '"decision":"approved"' && die "a request to the hub was approved"

say "a ticket, approved through the facade socket"
# A write (a body the agent chose): the gate holds it and asks the hub.
agent -o /dev/null -w '%{http_code}\n' -x "http://$gate:3128" -m 120 -d probe=1 "http://example.com/" >curl.out 2>&1 &
cpid=$!
ok=""
for i in $(seq 1 30); do
	sleep 2
	tty 'y\n' "$lock" approve --once >approve.out 2>&1 || true
	if tr -d '\r' <approve.out | grep -Eq '(^|: )approved$'; then ok=1; break; fi
done
cat approve.out
# The ticket approved is the probe's, not some other pending request: the
# gate's instance and class, its method and URL, its body.
if [ -n "$ok" ]; then
	tr -d '\r' <approve.out >approve.txt
	grep -qx 'lockhttp · web · write' approve.txt && grep -qx '  POST plain://example.com/' approve.txt && grep -qx '    probe=1' approve.txt ||
		die "the approved ticket is not the probe's (instance, method and URL, body)"
fi
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
decisions=1

if [ -n "$sql" ]; then
	say "a locksql ticket from an agent's container, approved through the facade socket"
	sqlimg=$(sed -n '/^  db:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
	# As lea runs an agent: its own account in the clients group, the
	# socket volume, the workspace at its path; no network at all.
	asagent() { docker run --rm --network none --user agent -v "${p}_db-run:/run/locksql" -v "$ws:$ws:ro" -w "$ws" "$sqlimg" "$@"; }
	# As lea runs its agents: a uid with no account in the image (the
	# host user's), in the clients group. allowed_uids names 4242 only.
	asuid() { docker run --rm --network none --user "$1:$1" --group-add 10000 -e HOME=/tmp -v "${p}_db-run:/run/locksql" -v "$ws:$ws:ro" -w "$ws" "$sqlimg" status --profile e2e; }
	ok=""
	for i in $(seq 1 30); do
		if asuid 4242 >uid4242.out 2>&1; then ok=1; break; fi
		sleep 2
	done
	[ -n "$ok" ] || { cat uid4242.out; die "uid 4242 (allowed_uids) refused by the locksql lock"; }
	asuid 4243 >uid4243.out 2>&1 && { cat uid4243.out; die "uid 4243 (not in allowed_uids) served by the locksql lock"; }
	grep -q "closed the connection" uid4243.out || { cat uid4243.out; die "uid 4243: not refused by the console"; }
	# A literal the agent typed, shaped as a personal value (on a column
	# that is not personal: locksql limits how a PII column is filtered): the
	# screen that leaves the lock masks every literal (locksql's
	# hubScreen), so the hub and its facades never see it. No row has it:
	# the result is both rows.
	asagent plan --profile e2e --db app --json "SELECT id, email, label FROM people WHERE label <> 'carol@mail.test' ORDER BY id LIMIT 10" >plan.json 2>plan.err || { cat plan.json plan.err; die "locksql plan failed"; }
	plan=$(jq -r .plan_id plan.json)
	[ -n "$plan" ] && [ "$plan" != null ] || { cat plan.json; die "no plan id"; }
	asagent run --profile e2e --json "$plan" >run1.json 2>run1.err || true
	cat run1.json run1.err
	[ "$(jq -r .status run1.json)" = pending ] || die "the run did not answer pending"
	ticket=$(jq -r .ticket run1.json)
	[ -n "$ticket" ] && [ "$ticket" != null ] || die "no ticket"
	asagent run --profile e2e --json "$ticket" >early.json 2>&1 && { cat early.json; die "the ticket ran before a decision"; }
	ok=""
	for i in $(seq 1 30); do
		tty 'y\n' "$lock" approve --once >approve2.out 2>&1 || true
		if tr -d '\r' <approve2.out | grep -Eq '(^|: )approved$'; then ok=1; break; fi
		sleep 2
	done
	cat approve2.out
	[ -n "$ok" ] || { docker logs "${p}-lockhub-1" 2>&1 | tail -20; die "the locksql ticket was not approved"; }
	tr -d '\r' <approve2.out | grep -q "$ticket" || die "the approved ticket is not the agent's ($ticket)"
	# The screen shown is the statement's (positive control), without the
	# literal: the approval screen of a query never holds its results, so
	# only a value of the statement itself can leak there.
	tr -d '\r' <approve2.out | grep -q 'FROM people' || die "the facade screen does not show the statement"
	tr -d '\r' <approve2.out | grep -q 'carol@mail.test' && die "the facade screen shows the statement's literal in clear"
	ok=""
	for i in $(seq 1 30); do
		if asagent run --profile e2e --json "$ticket" >run2.json 2>run2.err; then ok=1; break; fi
		cat run2.json run2.err >run2.all; grep -q "no decision yet" run2.all || break
		sleep 2
	done
	cat run2.json run2.err
	[ -n "$ok" ] || die "the approved ticket did not run"
	[ "$(jq -r '.rows | length' run2.json)" = 2 ] || die "want 2 rows"
	[ "$(jq -r '.rows[0][2]' run2.json)" = alpha ] || die "want label alpha in the first row"
	grep -q 'example.com' run2.json && die "the agent got an email in clear: the console's PII rule set is not in force"
	say "the first PII rule set is in the console's volume, not in the profile's copy"
	docker run --rm --network none -v "${p}_db-home:/h:ro" alpine:3.22 cat /h/pii-rules/pii/e2e.toml | tee rules.out
	grep -q 'people.email' rules.out || die "the console's rule set does not mask people.email"
	docker run --rm --network none -v "${p}_profile-locksql:/p:ro" alpine:3.22 sh -c '! ls -A /p/pii 2>/dev/null | grep -q .' ||
		die "the profile copy holds a rule set (it is read-only: the console's set belongs in its volume)"
	decisions=2
fi
"$lock" audit verify --data "$state/hub" --hub-key-file "$state/hub.pub" >audit.out 2>&1 || { cat audit.out; die "lock audit verify failed"; }
cat audit.out
grep -q " $decisions decisions signed" audit.out || die "the approvals are not in the hub's audit (want $decisions)"

say "control (Docker, not lockhub): .lockfamily read-only in a container, the mount lea makes"
docker run --rm --user "$(id -u):$(id -g)" -v "$ws:$ws" -v "$ws/.lockfamily:$ws/.lockfamily:ro" alpine:3.22 \
	sh -c "echo x >>'$ws/.lockfamily/lockfamily.yaml'" 2>err.out && die "an agent wrote lockfamily.yaml"
grep -qi 'read-only' err.out || die "not EROFS: $(cat err.out)"
say "I11: a change of lockfamily.yaml is reviewed, not applied silently; a planted root file is never read"
"$lock" add lockhttp extra >/dev/null
# An agent plants a root lockfamily.yaml with a lock of its own.
{ cat .lockfamily/lockfamily.yaml; printf '  planted:\n    type: lockhttp\n    image: %s\n' "$img"; } >lockfamily.yaml
tty 'n\n' "$lock" up >up2.out 2>&1 || true
cat up2.out | tr -d '\r' | grep -v 'Pull\|Running\|Creat' | tail -20
grep -q "+ lock extra" up2.out || die "the change was not shown"
grep -q 'not applied' up2.out || die "the change was applied without a yes"
grep -q planted up2.out && die "lock up read the planted root lockfamily.yaml"
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" ps -a --services | grep -qx lock-extra && die "lock-extra exists without a yes"
grep -q 'lock-extra' "$state/compose.yaml" && die "lock-extra was applied without a yes"
say "lock up again, confirmed: the setup services run again on volumes that are the console's now (copy re-owned by the console, modes kept)"
tty 'y\n' "$lock" up >up3.out 2>&1 || { tail -20 up3.out; die "a second lock up failed"; }
grep -q "up: project " up3.out || { tail -20 up3.out; die "a second lock up did not finish"; }
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" ps -a --services | grep -qx lock-extra || die "lock-extra not applied after the yes"
grep -q planted up3.out "$state/compose.yaml" && die "the planted root lockfamily.yaml was applied"
hub_is_local "$p"
hub_cosigned up3.out
docker run --rm --network none -v "${p}_profile-lockhttp:/p:ro" alpine:3.22 stat -c '%n %u:%g %a' /p/notes /p/notes/n.txt | tee st.out
grep -q '/p/notes 10021:10020 700' st.out && grep -q '/p/notes/n.txt 10021:10020 600' st.out ||
	die "the profile copy is not the console's, or lost its owner-only modes"
say "I11: lock up refuses a .lockfamily others can write, or a link"
chmod g+w .lockfamily
rc=0; tty 'y\n' "$lock" up >up4.out 2>&1 || rc=$?
tr -d '\r' <up4.out | tail -3
[ "$rc" != 0 ] && grep -qF "$ws/.lockfamily: mode 0775: writable by others than you" up4.out || die "lock up took a group-writable .lockfamily (exit $rc)"
grep -q "up: project " up4.out && die "lock up applied a group-writable .lockfamily"
chmod g-w .lockfamily
mv .lockfamily lf-real
ln -s lf-real .lockfamily
rc=0; tty 'y\n' "$lock" up >up5.out 2>&1 || rc=$?
tr -d '\r' <up5.out | tail -3
[ "$rc" != 0 ] && grep -qF "$ws/.lockfamily: not a directory (a link?)" up5.out || die "lock up took a .lockfamily that is a link (exit $rc)"
grep -q "up: project " up5.out && die "lock up applied a .lockfamily that is a link"
rm .lockfamily
mv lf-real .lockfamily
echo "phase 2: OK"
