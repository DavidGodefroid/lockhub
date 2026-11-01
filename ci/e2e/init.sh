#!/bin/sh
# lox init end to end (lockhub#80): a project with a compose file
# (PostgreSQL and RabbitMQ, their passwords in .env) and the released
# locksql and lockmq launchers on PATH. lox init --yes detects both,
# runs each launcher's verbs, lox add, lox up (its review typed y at a
# terminal) and attaches to each console (policy, password, PII
# proposal), all in one run. A host agent's locksql query and lockmq read
# are then approved through the facade (lox approve). Then a second
# database is added to the compose file and lox init runs again: it adds
# that lock and keeps the others as they were (lockfamily.yaml entries,
# profiles, the lockmq console's container), and a query on the new lock
# is approved. No secret is ever written: the workspace (but .env) and
# lox up's state directory are grepped for the passwords.
#
#   ci/e2e/init.sh LOX_BIN
#
# Needs LOCKSQL_LAUNCHER and LOCKMQ_LAUNCHER (the launchers' scripts),
# LOCKSQL_IMAGE and LOCKMQ_IMAGE (the images they run for the verbs: a
# launcher from a checkout has no pinned digest), host ports 55432,
# 55433, 55672 and 55673 free. With E2E_HUB_IMAGE and E2E_COSIGN_SHIM
# (ci/e2e/local-hub.sh), the hub is this commit's build; without them,
# the latest hub release.
. "$(dirname "$0")/lib.sh"
lox=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
[ -n "${LOCKSQL_LAUNCHER:-}" ] && [ -n "${LOCKMQ_LAUNCHER:-}" ] || die "LOCKSQL_LAUNCHER and LOCKMQ_LAUNCHER are required"
[ -n "${LOCKSQL_IMAGE:-}" ] && [ -n "${LOCKMQ_IMAGE:-}" ] || die "LOCKSQL_IMAGE and LOCKMQ_IMAGE are required"
verb_sql_image=$LOCKSQL_IMAGE
verb_mq_image=$LOCKMQ_IMAGE
top=$(realpath "$(mktemp -d)")
ws=$top/shop
out=$top/out
bin=$top/bin
mkdir -p "$ws" "$out" "$bin"
# The launchers, as their installers put them on PATH.
printf '#!/bin/sh\nexec sh %s "$@"\n' "$LOCKSQL_LAUNCHER" >"$bin/locksql"
printf '#!/bin/sh\nexec sh %s "$@"\n' "$LOCKMQ_LAUNCHER" >"$bin/lockmq"
chmod 0755 "$bin/locksql" "$bin/lockmq"
export PATH="$bin:$PATH"
cd "$ws"
# Throwaway passwords, only in .env (and typed at the consoles).
pg_pw="pg-$E2E_ID-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
inv_pw="inv-$E2E_ID-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
mq_pw="mq-$E2E_ID-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
cproject="$E2E_ID-shop"
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	(cd "$ws" && docker compose -p "$cproject" down -v --remove-orphans >/dev/null 2>&1) || true
}
trap cleanup EXIT INT TERM

say "the project: compose (PostgreSQL, RabbitMQ), passwords in .env"
cat >.env <<ENV
POSTGRES_PASSWORD=$pg_pw
INVENTORY_PASSWORD=$inv_pw
RABBITMQ_PASSWORD=$mq_pw
SHOP_DB=shop
ENV
cat >compose.yaml <<'YAML'
services:
  db:
    image: postgres:17
    ports: ["55432:5432"]
    environment:
      POSTGRES_USER: shop
      POSTGRES_DB: ${SHOP_DB:-shop}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
  mq:
    image: rabbitmq:4.1.8-management
    ports: ["55672:15672", "55673:5672"]
    environment:
      RABBITMQ_DEFAULT_USER: shop
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD}
      RABBITMQ_DEFAULT_VHOST: shop
YAML
docker compose -p "$cproject" up -d --quiet-pull db mq
for i in $(seq 1 60); do docker compose -p "$cproject" exec -T db pg_isready -U shop -q && break; sleep 1; done
docker compose -p "$cproject" exec -T db pg_isready -U shop
mqapi() {
	curl -fsS -m 10 -u "shop:$mq_pw" -H 'content-type: application/json' -X "$1" ${3:+--data} ${3:+"$3"} "http://127.0.0.1:55672/api$2"
}
for i in $(seq 1 90); do mqapi GET /overview >/dev/null 2>&1 && break; sleep 2; done
mqapi GET /overview >/dev/null
# A table with personal data (the console proposes masking its email),
# and a stream with one message. The databases' accounts are their
# superusers (compose's POSTGRES_USER), the broker's an administrator:
# each console warns and asks to type "continue" (it stays read-only).
table="CREATE TABLE customers (id int PRIMARY KEY, email text NOT NULL, label text NOT NULL);
INSERT INTO customers VALUES (1, 'alice@example.com', 'alpha'), (2, 'bob@example.com', 'beta');"
docker compose -p "$cproject" exec -T db psql -v ON_ERROR_STOP=1 -U shop -d shop -c "$table" >/dev/null
mqapi PUT /queues/shop/orders '{"durable":true,"arguments":{"x-queue-type":"stream"}}' >/dev/null
mqapi POST /exchanges/shop/amq.default/publish '{"properties":{},"routing_key":"orders","payload":"{\"order\":\"e2e-1\"}","payload_encoding":"string"}' >"$out/publish.json"
jq -e '.routed == true' "$out/publish.json" >/dev/null || die "the message was not routed to the stream orders"

hubflag=""
if [ -n "${E2E_HUB_IMAGE:-}" ]; then
	say "this commit's hub: the released hub lox add would pin is the cosign shim's reference"
	probe=$(mktemp -d)
	(cd "$probe" && "$lox" add lockhttp probe >/dev/null)
	local_hub "$probe/.lockfamily/lockfamily.yaml"
	rm -rf "$probe"
	hubflag="--hub-image $E2E_HUB_IMAGE"
fi

say "lox init --yes: auto mode, lox up's review, then each console's questions (one run, at a terminal)"
# shellcheck disable=SC2086
python3 "$here/expect.py" 900 \
	'Apply? [y/N]' 'y\n' \
	'attached to lock db' '<pause>y\n' \
	'Password for shop@' "$pg_pw\\n" \
	'Type "continue" to proceed' 'continue\n' \
	'Accept all [a]' 'a\n' \
	'Listening' '<detach>' \
	'attached to lock mq' '<pause>y\n' \
	'Password for shop@' "$mq_pw\\n" \
	'Type "continue" to proceed' 'continue\n' \
	'Listening' '<detach>' \
	'Run `' '' \
	-- env LOCKSQL_IMAGE="$verb_sql_image" LOCKMQ_IMAGE="$verb_mq_image" "$lox" init --yes $hubflag >"$out/init1.out" 2>&1 ||
	{ cat "$out/init1.out"; die "lox init failed"; }
cat "$out/init1.out"
for w in "PostgreSQL  host.docker.internal:55432  user shop, database shop" "RabbitMQ    http://host.docker.internal:55672  user shop, vhost shop, AMQP amqp://host.docker.internal:55673" \
	"lox add: lock db declared" "lox add: lock mq declared" "First lox up of this workspace" "up: project "; do
	grep -qF "$w" "$out/init1.out" || die "lox init: no \"$w\""
done
grep -q -- '--fix' "$out/init1.out" && ! grep -q 'lox init does not run' "$out/init1.out" && die "a doctor --fix hint without lox init's note"
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
[ -z "${E2E_HUB_IMAGE:-}" ] || { hub_is_local "$p"; hub_cosigned "$out/init1.out"; }
cat .lockfamily/lockfamily.yaml
grep -q '^  db:$' .lockfamily/lockfamily.yaml && grep -q '^  mq:$' .lockfamily/lockfamily.yaml || die "lockfamily.yaml lacks db or mq"
[ -f .mcp.json ] || die "no .mcp.json: init claude did not run"

sqlimg=$(sed -n '/^  db:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
mqimg=$(sed -n '/^  mq:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
# hostmcp INSTANCE TOOL ARGS: as .mcp.json starts locksql mcp, the lock
# named (the workspace has several locksql locks after the re-run).
hostmcp() { i=$1; shift; LOCKSQL_IMAGE="$sqlimg" python3 "$here/mcp.py" 120 "$@" -- sh "$LOCKSQL_LAUNCHER" mcp --instance "$i"; }
hostmq() { LOCKMQ_IMAGE="$mqimg" python3 "$here/mcp.py" 120 "$@" -- sh "$LOCKMQ_LAUNCHER" mcp; }
# approve_once OUT: lox approve at a terminal until a ticket is approved.
approve_once() {
	for i in $(seq 1 30); do
		tty 'y\n' "$lox" approve --once >"$1" 2>&1 || true
		if tr -d '\r' <"$1" | grep -Eq '(^|: )approved$'; then return 0; fi
		sleep 2
	done
	cat "$1"
	return 1
}
# sql_query INSTANCE DATABASE: a host agent's locksql query (locksql mcp,
# as .mcp.json starts it) on the instance's profile (named after it),
# approved through the facade, its rows returned.
sql_query() {
	inst=$1 prof=$1 dbname=$2
	hostmcp "$inst" locksql_plan "{\"profile\":\"$prof\",\"db\":\"$dbname\",\"sql\":\"SELECT id, label FROM customers ORDER BY id LIMIT 10\",\"intent\":\"e2e lox init\"}" \
		>"$out/plan-$inst.json" || { cat "$out/plan-$inst.json"; die "$inst: locksql_plan failed"; }
	plan=$(jq -r .plan_id "$out/plan-$inst.json")
	[ -n "$plan" ] && [ "$plan" != null ] || { cat "$out/plan-$inst.json"; die "$inst: no plan id"; }
	hostmcp "$inst" locksql_run "{\"profile\":\"$prof\",\"plan_id\":\"$plan\"}" >"$out/run1-$inst.json" || { cat "$out/run1-$inst.json"; die "$inst: locksql_run failed"; }
	[ "$(jq -r .status "$out/run1-$inst.json")" = pending ] || { cat "$out/run1-$inst.json"; die "$inst: the run did not answer pending"; }
	ticket=$(jq -r .ticket "$out/run1-$inst.json")
	approve_once "$out/approve-$inst.out" || die "$inst: the ticket was not approved"
	tr -d '\r' <"$out/approve-$inst.out" | grep -q "$ticket" || die "$inst: the approved ticket is not the agent's ($ticket)"
	ok=""
	for i in $(seq 1 30); do
		if hostmcp "$inst" locksql_run "{\"profile\":\"$prof\",\"ticket\":\"$ticket\"}" >"$out/run2-$inst.json" && [ "$(jq -r '.rows | length' "$out/run2-$inst.json" 2>/dev/null)" = 2 ]; then ok=1; break; fi
		grep -q "no decision yet" "$out/run2-$inst.json" || break
		sleep 2
	done
	cat "$out/run2-$inst.json"
	[ -n "$ok" ] && [ "$(jq -r '.rows[0][1]' "$out/run2-$inst.json")" = alpha ] || die "$inst: the approved query did not return its rows"
	echo "lox init e2e: agent query on $inst approved as $ticket, 2 rows returned"
}

say "a host agent's locksql query on db, approved through the facade"
sql_query db shop

say "a host agent's lockmq read on mq, approved through the facade"
mqread='"profile":"mq","vhost":"shop","name":"orders","from":"first","count":1'
hostmq lockmq_read "{$mqread,\"intent\":\"e2e lox init\"}" >"$out/mread1.json" || { cat "$out/mread1.json"; die "lockmq_read failed"; }
jq -e '.data.status == "pending" and .data.instance == "mq"' "$out/mread1.json" >/dev/null || { cat "$out/mread1.json"; die "the read did not answer pending on mq"; }
mticket=$(jq -r .data.ticket "$out/mread1.json")
approve_once "$out/approve-mq.out" || die "the lockmq ticket was not approved"
ok=""
for i in $(seq 1 30); do
	if hostmq lockmq_read "{$mqread,\"ticket\":\"$mticket\"}" >"$out/mread2.json" && [ "$(jq -r '.data.messages | length' "$out/mread2.json" 2>/dev/null)" = 1 ]; then ok=1; break; fi
	jq -e --arg t "$mticket" '.data.status == "pending" and .data.ticket == $t' "$out/mread2.json" >/dev/null 2>&1 || grep -q "no decision yet" "$out/mread2.json" || break
	sleep 2
done
[ -n "$ok" ] && jq -e '.data.messages[0].body | tostring | contains("e2e-1")' "$out/mread2.json" >/dev/null || { cat "$out/mread2.json"; die "the approved read did not return e2e-1"; }
echo "lox init e2e: agent read on mq approved as $mticket, message e2e-1 returned"

say "re-run: a second database in the compose file; lox init adds it, keeps the others"
# block NAME: the lock NAME's entry in lockfamily.yaml.
block() { awk -v n="  $1:" '$0 == n { on = 1; print; next } on && /^  [^ ]/ { on = 0 } on && /^[^ ]/ { on = 0 } on { print }' .lockfamily/lockfamily.yaml; }
# section NAME FILE: the profile NAME's lines in a TOML config (blank
# lines left out: a profile added after it brings one).
section() { awk -v s="[profiles.$1]" '$0 == s { on = 1; print; next } on && /^\[/ { on = 0 } on && NF { print }' "$2"; }
block db >"$out/db.before"
block mq >"$out/mq.before"
section db .locksql/config.toml >"$out/dbprof.before"
cp .lockmq/config.toml "$out/lockmq.before"
mqid=$(docker inspect -f '{{.Id}}' "$p-lock-mq-1")
cat >>compose.yaml <<'YAML'
  inventory:
    image: postgres:17
    ports: ["55433:5432"]
    environment:
      POSTGRES_USER: stock
      POSTGRES_DB: stock
      POSTGRES_PASSWORD: ${INVENTORY_PASSWORD}
YAML
docker compose -p "$cproject" up -d --quiet-pull inventory
for i in $(seq 1 60); do docker compose -p "$cproject" exec -T inventory pg_isready -U stock -q && break; sleep 1; done
docker compose -p "$cproject" exec -T inventory psql -v ON_ERROR_STOP=1 -U stock -d stock -c "$table" >/dev/null
# lox up recreates the db console (its type's profile directory changed:
# a profile was added), which then asks only its password (its policy is
# approved already); the new console asks its policy, password and PII.
# shellcheck disable=SC2086
python3 "$here/expect.py" 900 \
	'Apply? [y/N]' 'y\n' \
	'attached to lock db' "<pause>$pg_pw\\n" \
	'Type "continue" to proceed' 'continue\n' \
	'Listening' '<detach>' \
	'attached to lock inventory' '<pause>y\n' \
	'Password for stock@' "$inv_pw\\n" \
	'Type "continue" to proceed' 'continue\n' \
	'Accept all [a]' 'a\n' \
	'Listening' '<detach>' \
	'Run `' '' \
	-- env LOCKSQL_IMAGE="$verb_sql_image" LOCKMQ_IMAGE="$verb_mq_image" "$lox" init --yes >"$out/init2.out" 2>&1 ||
	{ cat "$out/init2.out"; die "lox init (re-run) failed"; }
cat "$out/init2.out"
for w in "kept: db (locksql, profile db), declared already: not changed" "kept: mq (lockmq, profile mq), declared already: not changed" \
	"lox add: lock inventory declared" "+ lock inventory type locksql" "up: project "; do
	grep -qF "$w" "$out/init2.out" || die "lox init (re-run): no \"$w\""
done
grep -q 'lockmq profile add' "$out/init2.out" && die "the re-run ran lockmq's verbs again"
block db | cmp -s - "$out/db.before" || die "the re-run changed db's entry in lockfamily.yaml"
block mq | cmp -s - "$out/mq.before" || die "the re-run changed mq's entry in lockfamily.yaml"
section db .locksql/config.toml | cmp -s - "$out/dbprof.before" || die "the re-run changed locksql's profile db"
cmp -s .lockmq/config.toml "$out/lockmq.before" || die "the re-run changed lockmq's profile"
[ "$(docker inspect -f '{{.Id}}' "$p-lock-mq-1")" = "$mqid" ] || die "the re-run recreated the mq console"
grep -q '^  inventory:$' .lockfamily/lockfamily.yaml || die "lockfamily.yaml lacks inventory"

say "a host agent's locksql query on the new lock, approved through the facade"
sql_query inventory stock

say "no secret written: the workspace (but .env) and lox up's state directory"
leak=""
for pw in "$pg_pw" "$inv_pw" "$mq_pw"; do
	if grep -rlF --exclude=.env -- "$pw" "$ws" "$state" 2>/dev/null; then leak=1; fi
done
[ -z "$leak" ] || die "a password is on disk (above)"
# Positive control: grep finds the passwords where they are.
grep -qF -- "$pg_pw" .env || die "control: the password is not in .env (the check above proves nothing)"
[ -n "$(ls -A "$state")" ] || die "control: the state directory is empty"
echo "lox init e2e: OK"
