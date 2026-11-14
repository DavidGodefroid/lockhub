#!/bin/sh
# A lock's gateway joining an existing Docker network (lockhub#194): a
# Postgres container db on a compose-style network shop, no published
# port; a locksql lock with networks: [shop] and a profile host = "db".
# lox up reviews the joined network; an agent's locksql query, approved
# through the facade socket, gets its rows; from the console's container,
# another container of shop and another port of db are unreachable; the
# console is not on shop, gwout-db is not on shop, gwnet-db is; once the
# stack is down, gwnet-db is detached and shop still exists. The hub is
# this commit's build (ci/e2e/local-hub.sh).
#
#   ci/e2e/joinnet.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
shop=$E2E_ID-shop
db=$E2E_ID-db
other=$E2E_ID-other
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	docker rm -f "$db" "$other" >/dev/null 2>&1 || true
	docker network rm "$shop" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

say "a dev stack: Postgres db and another container on network $shop, no published port"
docker network create "$shop" >/dev/null
docker run -d --name "$db" --network "$shop" --network-alias db -e POSTGRES_PASSWORD=e2e-only postgres:17 >/dev/null
docker run -d --name "$other" --network "$shop" --network-alias other alpine:3.22 nc -lk -p 5432 -e cat >/dev/null
ok=""
for i in $(seq 1 60); do
	docker exec "$db" pg_isready -h 127.0.0.1 -U postgres -q && { ok=1; break; }
	sleep 1
done
[ -n "$ok" ] || { docker logs "$db" 2>&1 | tail -20; die "Postgres did not start"; }
[ -z "$(docker port "$db")" ] || die "db publishes a port"
psql() { docker exec -i "$db" psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres "$@"; }
psql -c "CREATE DATABASE app" >/dev/null
psql -d app -c "CREATE ROLE ro LOGIN PASSWORD 'ro-e2e-only'" >/dev/null
psql -d app -c "CREATE TABLE people (id int PRIMARY KEY, email text NOT NULL, label text NOT NULL);
INSERT INTO people VALUES (1, 'alice@example.com', 'alpha'), (2, 'bob@example.com', 'beta');
GRANT SELECT ON people TO ro;" >/dev/null
say "control: a container on $shop reaches db:5432 and other:5432 by name"
docker run --rm --network "$shop" alpine:3.22 nc -z -w 5 db 5432 || die "control: db:5432 unreachable on $shop"
docker run --rm --network "$shop" alpine:3.22 nc -z -w 5 other 5432 || die "control: other:5432 unreachable on $shop"

say "lox add locksql db, networks: [$shop], a profile host = \"db\""
"$lox" add locksql db
local_hub .lockfamily/lockfamily.yaml
sed -i "/^  db:\$/a\\    networks: [$shop]" .lockfamily/lockfamily.yaml
grep -qxF "    networks: [$shop]" .lockfamily/lockfamily.yaml || die "networks not added to the db lock"
cat .lockfamily/lockfamily.yaml
mkdir -p .locksql
printf '[profiles.e2e]\nengine = "postgres"\nhost = "db"\nport = 5432\nuser = "ro"\ndatabase = "app"\ntls = "disable"\n' >.locksql/config.toml
chmod 0644 .locksql/config.toml

say "lox up: the review shows the joined network and the route of db:5432"
tty 'y\n' "$lox" up >up.raw 2>&1 || { tr -d '\r' <up.raw; die "lox up failed"; }
tr -d '\r' <up.raw >up.out
cat up.out
grep -q "up: project " up.out || die "lox up did not finish"
grep -qE "^  egress +only db:5432 via network $shop\$" up.out || die "the review lacks the egress db:5432 via network $shop"
grep -qE "^  networks +$shop \(its gateway gwnet only" up.out || die "the review lacks the joined network"
hub_cosigned up.raw
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
hub_is_local "$p"
lock=$p-lock-db-1

say "only gwnet-db joins $shop: not the console, not gwout-db"
nets() { docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$1"; }
echo "console: $(nets "$lock")"
case " $(nets "$lock") " in *" $shop "*) die "the console is on $shop" ;; esac
case " $(nets "$p-gwnet-db-1") " in *" $shop "*) ;; *) die "gwnet-db is not on $shop" ;; esac
case " $(nets "$p-gwnet-db-1") " in *"_out-db "*) die "gwnet-db has the route out" ;; esac
docker inspect "$p-gwout-db-1" >/dev/null 2>&1 && die "gwout-db runs, with no endpoint through out-db"

say "the console's first start: its policy, the password, the PII proposal"
python3 "$here/attach.py" 90 'y\n' "lock db serves: detached" 'Password for ro@' 'ro-e2e-only\n' 'Accept all [a]' 'a\n' -- "$lox" attach db >attach.out 2>&1 ||
	{ cat attach.out; die "lox attach db did not detach once its console served"; }

say "from the console's network: db:5432 only; other:5432 and db's other ports are unreachable"
reaches "$lock" db 5432 || die "the console does not reach db:5432"
reaches "$lock" other 5432 && die "the console reached other:5432, a container of $shop outside its profile"
reaches "$lock" db 5433 && die "the console reached db:5433, outside its profile"
reaches "$lock" "$db" 5432 && die "the console reached $db:5432 by its container name"
echo "egress: db:5432 only"

say "an agent's locksql query, approved through the facade socket"
sqlimg=$(sed -n '/^  db:/,/image:/s/^ *image: *//p' .lockfamily/lockfamily.yaml)
asagent() { docker run --rm --network none --user agent -v "${p}_db-run:/run/locksql" -v "$ws:$ws:ro" -w "$ws" "$sqlimg" "$@"; }
ok=""
for i in $(seq 1 30); do
	asagent plan --profile e2e --db app --json "SELECT id, label FROM people ORDER BY id LIMIT 10" >plan.json 2>plan.err && { ok=1; break; }
	sleep 2
done
[ -n "$ok" ] || { cat plan.json plan.err; die "locksql plan failed"; }
plan=$(jq -r .plan_id plan.json)
asagent run --profile e2e --json "$plan" >run1.json 2>run1.err || true
[ "$(jq -r .status run1.json)" = pending ] || { cat run1.json run1.err; die "the run did not answer pending"; }
ticket=$(jq -r .ticket run1.json)
ok=""
for i in $(seq 1 30); do
	tty 'y\n' "$lox" approve --once >approve.out 2>&1 || true
	if tr -d '\r' <approve.out | grep -Eq '(^|: )approved$'; then ok=1; break; fi
	sleep 2
done
[ -n "$ok" ] || { cat approve.out; die "the ticket was not approved"; }
ok=""
for i in $(seq 1 30); do
	if asagent run --profile e2e --json "$ticket" >run2.json 2>run2.err; then ok=1; break; fi
	cat run2.json run2.err >run2.all; grep -q "no decision yet" run2.all || break
	sleep 2
done
cat run2.json run2.err
[ -n "$ok" ] || die "the approved ticket did not run"
[ "$(jq -r '.rows | length' run2.json)" = 2 ] && [ "$(jq -r '.rows[0][1]' run2.json)" = alpha ] || die "want the 2 rows of people"

say "the stack down: gwnet-db is detached from $shop, which still exists"
docker compose -p "$p" --project-directory "$state" -f "$state/compose.yaml" down --remove-orphans
docker network inspect "$shop" >/dev/null 2>&1 || die "$shop was removed"
docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$shop" | tee shop.out
grep -q "gwnet-db" shop.out && die "gwnet-db is still on $shop"
docker inspect "$db" >/dev/null || die "db was removed"

say "PASS: a lock's gateway joins $shop for db:5432 only, the console never does, and $shop outlives the stack"
