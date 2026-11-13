#!/bin/sh
# The first run end to end: a project with a compose file (PostgreSQL, its
# password in .env) and the released locksql launcher on PATH.
#
#   ci/e2e/firstrun.sh LOX_BIN
#
# E2E_VAULT=1 (default 0) also adds a lock whose credentials Vault holds,
# against the Vault dev server the CI job starts (E2E_VAULT_CONTAINER and
# E2E_VAULT_TOKEN). That half needs a locksql console that asks the Vault
# token at its start (locksql v0.13.1 or later; e2e.yml checks out v0.17.0) and
# the job's Vault image, pinned by digest; e2e.yml runs it as a step of its
# own.
#
# Steps: lox init (no question, the found hint, the end line, the hub alone
# in up.json; a re-run changes nothing) — lox add locksql for orders (the
# form, the review, then the console's policy, password, privilege audit
# and PII) — with E2E_VAULT=1, the same for inventory with credentials
# vault, then lockhub#124: vault_token: cli answers its console's Vault
# token prompt from the host's Vault CLI, and a revoked CLI token falls
# back to the typed one — a host agent's query approved through the facade
# on each lock —
# without E2E_VAULT, lockhub#158: a lock whose tls_ca is missing from its
# home flagged at lox add, copied with the review's command, then started
# past the console's file check; lockhub#167: a relative tls_ca in the
# profile's directory not flagged, an inline ssh table's missing key
# flagged —
# lox remove (the console stops, the yaml entry goes, the profile stays
# unless --purge) — no secret on disk (the workspace but .env, and lox
# up's state directory).
#
# Needs LOCKSQL_LAUNCHER and host port 55432 free. With E2E_HUB_IMAGE and
# E2E_COSIGN_SHIM (ci/e2e/local-hub.sh), the hub is this commit's build;
# without them, the latest hub release. The images the launcher's verbs
# run are LOCKSQL_IMAGE, by default the one lox add pins (the latest
# signed release; a launcher from a checkout has no pinned digest).
. "$(dirname "$0")/lib.sh"
vault=${E2E_VAULT:-0}
lox=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
[ -n "${LOCKSQL_LAUNCHER:-}" ] || die "LOCKSQL_LAUNCHER is required"
if [ "$vault" = 1 ]; then
	[ -n "${E2E_VAULT_CONTAINER:-}" ] || die "E2E_VAULT=1 needs E2E_VAULT_CONTAINER (the CI job's Vault dev server)"
	[ -n "${E2E_VAULT_TOKEN:-}" ] || die "E2E_VAULT=1 needs E2E_VAULT_TOKEN (its dev root token)"
fi
verb_image=${LOCKSQL_IMAGE:-}
if [ -z "$verb_image" ]; then
	probe=$(mktemp -d)
	(cd "$probe" && "$lox" add locksql psql >/dev/null) || die "lox add (image probe) failed"
	verb_image=$(sed -n '/^  psql:/,/image:/s/^ *image: *//p' "$probe/.lockfamily/lockfamily.yaml")
	rm -rf "$probe"
	[ -n "$verb_image" ] || die "lox add pinned no locksql image"
fi
echo "first run e2e: the verbs run $verb_image"
top=$(realpath "$(mktemp -d)")
ws=$top/shop
out=$top/out
bin=$top/bin
mkdir -p "$ws" "$out" "$bin"
# The launcher, as its installer puts it on PATH.
printf '#!/bin/sh\nexec sh %s "$@"\n' "$LOCKSQL_LAUNCHER" >"$bin/locksql"
chmod 0755 "$bin/locksql"
export PATH="$bin:$PATH"
cd "$ws"
# The throwaway password: only in .env (and typed at the consoles; with
# E2E_VAULT=1 it is also the login the Vault dev server holds).
inv_pw="inv-$E2E_ID-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
cproject="$E2E_ID-shop"
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	(cd "$ws" && docker compose -p "$cproject" down -v --remove-orphans >/dev/null 2>&1) || true
}
trap cleanup EXIT INT TERM

say "the project: compose (PostgreSQL), the password in .env"
cat >.env <<ENV
POSTGRES_PASSWORD=$inv_pw
ENV
cat >compose.yaml <<'YAML'
services:
  db:
    image: postgres:17
    ports: ["55432:5432"]
    environment:
      POSTGRES_USER: shop
      POSTGRES_DB: shop
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
YAML
docker compose -p "$cproject" up -d --quiet-pull db
for i in $(seq 1 60); do docker compose -p "$cproject" exec -T db pg_isready -U shop -q && break; sleep 1; done
docker compose -p "$cproject" exec -T db pg_isready -U shop
# The orders data (its email column is what the console proposes to mask),
# and the inventory database with no personal-data column.
cust="CREATE TABLE customers (id int PRIMARY KEY, email text NOT NULL, label text NOT NULL);
INSERT INTO customers VALUES (1, 'alice@example.com', 'alpha'), (2, 'bob@example.com', 'beta');"
docker compose -p "$cproject" exec -T db psql -v ON_ERROR_STOP=1 -U shop -d shop -c "$cust" >/dev/null
docker compose -p "$cproject" exec -T db psql -v ON_ERROR_STOP=1 -U shop -d shop -c "CREATE DATABASE inventory" >/dev/null
stock="CREATE TABLE stock (id int PRIMARY KEY, sku text NOT NULL, qty int NOT NULL);
INSERT INTO stock VALUES (1, 'sku-1', 5), (2, 'sku-2', 3);"
docker compose -p "$cproject" exec -T db psql -v ON_ERROR_STOP=1 -U shop -d inventory -c "$stock" >/dev/null
if [ "$vault" = 1 ]; then
	say "the Vault dev server holds the inventory login"
	docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$E2E_VAULT_TOKEN" \
		"$E2E_VAULT_CONTAINER" vault kv put secret/shop/inventory username=shop password="$inv_pw"
fi

hubflag=""
if [ -n "${E2E_HUB_IMAGE:-}" ]; then
	say "this commit's hub: the released hub lox init would pin is the cosign shim's reference"
	probe=$(mktemp -d)
	(cd "$probe" && "$lox" add lockhttp probe >/dev/null)
	local_hub "$probe/.lockfamily/lockfamily.yaml"
	rm -rf "$probe"
	hubflag="--hub-image $E2E_HUB_IMAGE"
fi

endline='Ready. Run `lea` (or `claude` + `lox approve`). Add a source: `lox add locksql|lockmq|lockfile|lockhttp|locklog|lockssh`.'

say "lox init: no question, the hub alone"
# shellcheck disable=SC2086
"$lox" init $hubflag </dev/null >"$out/init1.out" 2>&1 || { cat "$out/init1.out"; die "lox init failed"; }
cat "$out/init1.out"
grep -qF 'found: postgres on host.docker.internal:55432 (compose.yaml) → `lox add locksql`' "$out/init1.out" || die "lox init: no found hint"
grep -qF "$endline" "$out/init1.out" || die "lox init: no end line"
grep -qF '[y/N]' "$out/init1.out" && die "lox init asked a question"
p=$(ws_project "$ws")
state="$XDG_STATE_HOME/lockfamily/$p"
[ "$(docker inspect -f '{{.State.Running}}' "$p-lockhub-1" 2>/dev/null)" = true ] || die "the hub is not running"
jq -e '.locks | length == 0' "$ws/.lockfamily/up.json" >/dev/null || die "up.json does not declare zero locks"
[ -z "${E2E_HUB_IMAGE:-}" ] || hub_is_local "$p"

say "a re-run: the same end line, the same hub"
hubid=$(docker inspect -f '{{.Id}}' "$p-lockhub-1")
"$lox" init </dev/null >"$out/init2.out" 2>&1 || { cat "$out/init2.out"; die "lox init (re-run) failed"; }
grep -qF "$endline" "$out/init2.out" || die "lox init (re-run): no end line"
[ "$(docker inspect -f '{{.Id}}' "$p-lockhub-1")" = "$hubid" ] || die "the re-run recreated the hub"
# block NAME FILE: the lock NAME's entry (two-space key) of FILE.
block() { awk -v n="  $1:" '$0 == n { on = 1; print; next } on && /^  [^ ]/ { on = 0 } on && /^[^ ]/ { on = 0 } on { print }' "$2"; }

say "lockhub#145: a host named by its IP is refused at lox add, with the fix"
cp "$ws/.lockfamily/lockfamily.yaml" "$out/before-ip.yaml"
rc=0
"$lox" add locksql --non-interactive --engine postgres --host 203.0.113.10 --name bastion </dev/null >"$out/add-ip.out" 2>&1 || rc=$?
cat "$out/add-ip.out"
[ "$rc" = 2 ] || die "lox add with an IP host: exit $rc, want 2"
grep -qF -- '--host: 203.0.113.10 is an IP address' "$out/add-ip.out" || die "lox add with an IP host: no reason"
grep -qF 'name the host instead' "$out/add-ip.out" || die "lox add with an IP host: no fix"
cmp -s "$ws/.lockfamily/lockfamily.yaml" "$out/before-ip.yaml" || die "lox add with an IP host changed lockfamily.yaml"
[ ! -e "$ws/.locksql" ] || die "lox add with an IP host wrote a profile"

say "lox add locksql for orders: the form, the review, the console's questions"
# The form's defaults are the found source's (postgres on
# host.docker.internal:55432, user and database shop; its TLS disable is
# written unasked); the typed answers name the lock orders. The console asks its policy, the
# password, the privilege audit and the PII proposal; detaching leaves it
# running.
# shellcheck disable=SC2086
python3 "$here/expect.py" 900 \
	'Engine: postgres, mysql, mariadb or sqlite' '\n' \
	'Host (required)' '\n' \
	'Port (required)' '\n' \
	'User (optional:' 'shop\n' \
	'Database (optional:' 'shop\n' \
	'Production? (tickets flagged' '\n' \
	'Credentials: ask' '\n' \
	'Name (required)' 'orders\n' \
	'Apply? [y/N]' 'y\n' \
	'Ctrl-P Ctrl-Q detaches' '<pause>y\n' \
	'Password for shop@' "$inv_pw\\n" \
	'Type "continue" to proceed' 'continue\n' \
	'Accept all [a]' 'a\n' \
	'lock orders serves: detached' '' \
	-- env LOCKSQL_IMAGE="$verb_image" "$lox" add locksql >"$out/add1.out" 2>&1 ||
	{ cat "$out/add1.out"; die "lox add locksql (orders) failed"; }
cat "$out/add1.out"
grep -q '^  orders:$' .lockfamily/lockfamily.yaml || die "lockfamily.yaml lacks orders"

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
# hostmcp INSTANCE TOOL ARGS: a host agent's locksql mcp (as .mcp.json
# starts it) on the instance's lock, its lock's image.
hostmcp() {
	i=$1 img=$(sed -n "/^  $i:/,/image:/s/^ *image: *//p" .lockfamily/lockfamily.yaml)
	shift
	[ -n "$img" ] || die "no image in lockfamily.yaml for $i"
	LOCKSQL_IMAGE="$img" python3 "$here/mcp.py" 120 "$@" -- sh "$LOCKSQL_LAUNCHER" mcp --instance "$i"
}
# sql_query INSTANCE DATABASE TABLE COLUMN WANT: the agent's locksql_plan
# and locksql_run on the instance's profile, approved through the facade,
# its two rows returned.
sql_query() {
	inst=$1 prof=$1 dbname=$2 table=$3 col=$4 want=$5
	hostmcp "$inst" locksql_plan "{\"profile\":\"$prof\",\"db\":\"$dbname\",\"sql\":\"SELECT id, $col FROM $table ORDER BY id LIMIT 10\",\"intent\":\"e2e first run\"}" \
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
	[ -n "$ok" ] && [ "$(jq -r '.rows[0][1]' "$out/run2-$inst.json")" = "$want" ] || die "$inst: the approved query did not return its rows"
	echo "first run e2e: agent query on $inst approved as $ticket, 2 rows returned"
}

say "a host agent's locksql query on orders, approved through the facade"
sql_query orders shop customers label alpha

# The ask half only: the Vault half adds its own lock.
if [ "$vault" = 0 ]; then
	say "lockhub#158: a tls_ca missing from the lock's home is flagged, copied with the given command"
	# The certs profile is orders' with tls_ca = "~/db-ca.pem" (tls disable:
	# the console only checks the file is there, before its secrets).
	awk '/^\[/ { on = ($0 == "[profiles.orders]") } on { sub(/^\[profiles\.orders\]$/, "[profiles.certs]\ntls_ca = \"~/db-ca.pem\""); print }' \
		.locksql/config.toml >"$out/certs.toml"
	grep -qF 'tls_ca = "~/db-ca.pem"' "$out/certs.toml" || die "no certs profile made from orders"
	printf '\n' >>.locksql/config.toml
	cat "$out/certs.toml" >>.locksql/config.toml
	# The first try is declined: nothing kept, the file not copied.
	rc=0
	python3 "$here/expect.py" 600 \
		'Engine: postgres, mysql, mariadb or sqlite' '\n' \
		'Host (required)' '\n' \
		'Port (required)' '\n' \
		'User (optional:' 'shop\n' \
		'Database (optional:' 'shop\n' \
		'Production? (tickets flagged' '\n' \
		'Credentials: ask' '\n' \
		'Name (required)' 'certs\n' \
		'WARNING: tls_ca: /home/locksql/db-ca.pem (~/db-ca.pem) is not in the lock' '' \
		"Copy tls_ca into the lock's home as /home/locksql/db-ca.pem" '\n' \
		'Apply? [y/N]' 'n\n' \
		-- env LOCKSQL_IMAGE="$verb_image" "$lox" add locksql >"$out/certs1.out" 2>&1 || rc=$?
	cat "$out/certs1.out"
	[ "$rc" != 0 ] || die "lox add certs (declined) exited 0"
	grep -qF 'nothing kept' "$out/certs1.out" || die "lox add certs (declined): no rollback said"
	cmd=$(tr -d '\r' <"$out/certs1.out" | sed -n 's/^.*WARNING: tls_ca: .* copy it there: //p' | head -n 1)
	case $cmd in "docker run --rm -i --network none --user 10001:10000 -v $p"_certs-home:/home/locksql" "*) ;; *) die "no copy command in the review: $cmd" ;; esac
	printf '%s\n' '-----BEGIN CERTIFICATE-----' 'e2e' '-----END CERTIFICATE-----' >db-ca.pem
	sh -c "$cmd" || die "the review's copy command failed: $cmd"
	rm db-ca.pem
	# The second try: no warning, the console passes its file check (it asks
	# the password only after it), detached at that question.
	python3 "$here/expect.py" 900 \
		'Engine: postgres, mysql, mariadb or sqlite' '\n' \
		'Host (required)' '\n' \
		'Port (required)' '\n' \
		'User (optional:' 'shop\n' \
		'Database (optional:' 'shop\n' \
		'Production? (tickets flagged' '\n' \
		'Credentials: ask' '\n' \
		'Name (required)' 'certs\n' \
		'Apply? [y/N]' 'y\n' \
		'Ctrl-P Ctrl-Q detaches' '<pause>y\n' \
		'Password for shop@' '<detach>' \
		'detached from certs' '' \
		-- env LOCKSQL_IMAGE="$verb_image" "$lox" add locksql >"$out/certs2.out" 2>&1 ||
		{ cat "$out/certs2.out"; die "lox add certs failed"; }
	cat "$out/certs2.out"
	grep -qF 'WARNING: tls_ca' "$out/certs2.out" && die "lox add certs: tls_ca still flagged once copied"
	[ "$(docker inspect -f '{{.State.Running}}' "$p-lock-certs-1" 2>/dev/null)" = true ] || die "the certs console is not running"
	docker logs "$p-lock-certs-1" 2>&1 | grep -F 'tls_ca:' && die "the certs console refused its tls_ca"
	tty 'y\n' "$lox" remove certs --purge >"$out/rm-certs.out" 2>&1 || { cat "$out/rm-certs.out"; die "lox remove certs failed"; }

	say "lockhub#167: a relative CA in the profile's directory passes, an inline SSH key table is checked"
	# The rel profile is orders' with tls_ca in .locksql/ (only in the copy
	# this review applies: the volume holds the previous one) and a key
	# file in an inline ssh table, missing from the lock's home.
	awk '/^\[/ { on = ($0 == "[profiles.orders]") } on { sub(/^\[profiles\.orders\]$/, "[profiles.rel]\ntls_ca = \".locksql/rel-ca.pem\"\nssh = { host = \"bastion.invalid\", user = \"e2e\", auth = \"key\", key = \"~/.ssh/id_e2e\" }"); print }' \
		.locksql/config.toml >"$out/rel.toml"
	grep -qF 'tls_ca = ".locksql/rel-ca.pem"' "$out/rel.toml" || die "no rel profile made from orders"
	printf '\n' >>.locksql/config.toml
	cat "$out/rel.toml" >>.locksql/config.toml
	printf '%s\n' '-----BEGIN CERTIFICATE-----' 'e2e' '-----END CERTIFICATE-----' >.locksql/rel-ca.pem
	rc=0
	python3 "$here/expect.py" 600 \
		'Engine: postgres, mysql, mariadb or sqlite' '\n' \
		'Host (required)' '\n' \
		'Port (required)' '\n' \
		'User (optional:' 'shop\n' \
		'Database (optional:' 'shop\n' \
		'Production? (tickets flagged' '\n' \
		'Credentials: ask' '\n' \
		'Name (required)' 'rel\n' \
		'WARNING: ssh.key: /home/locksql/.ssh/id_e2e (~/.ssh/id_e2e) is not in the lock' '' \
		"Copy ssh.key into the lock's home as /home/locksql/.ssh/id_e2e" '\n' \
		'Apply? [y/N]' 'n\n' \
		-- env LOCKSQL_IMAGE="$verb_image" "$lox" add locksql >"$out/rel.out" 2>&1 || rc=$?
	cat "$out/rel.out"
	[ "$rc" != 0 ] || die "lox add rel (declined) exited 0"
	# Declined at the review, not refused before it.
	grep -qF 'nothing kept' "$out/rel.out" || die "lox add rel (declined): no rollback said"
	grep -qF 'Apply? [y/N]' "$out/rel.out" || die "lox add rel: no review"
	grep -qF 'WARNING: ssh.key: /home/locksql/.ssh/id_e2e (~/.ssh/id_e2e) is not in the lock' "$out/rel.out" ||
		die "lox add rel: the inline ssh table's missing key not flagged"
	grep -qF 'WARNING: tls_ca' "$out/rel.out" && die "lox add rel: the relative tls_ca in .locksql/ flagged"
	grep -qF 'WARNING: ssh: ' "$out/rel.out" && die "lox add rel: the inline ssh table not read"
	rm .locksql/rel-ca.pem
fi

if [ "$vault" = 1 ]; then
	say "lox add locksql for inventory: credentials from Vault"
	# The same form; credentials vault brings the vault block questions
	# (the first vault lock asks it), then the console asks its policy, the
	# Vault token and the privilege audit.
	# shellcheck disable=SC2086
	python3 "$here/expect.py" 900 \
		'Engine: postgres, mysql, mariadb or sqlite' '\n' \
		'Host (required)' '\n' \
		'Port (required)' '\n' \
		'User (optional:' 'shop\n' \
		'Database (optional:' 'inventory\n' \
		'Production? (tickets flagged' '\n' \
		'Credentials: ask' 'vault\n' \
		'Vault path (required)' 'secret/data/shop/inventory\n' \
		'Vault address, such as' 'http://host.docker.internal:58200\n' \
		'Vault namespace (optional:' '\n' \
		'Vault CA file (optional:' '\n' \
		'Name (required)' 'inventory\n' \
		'Apply? [y/N]' 'y\n' \
		'Ctrl-P Ctrl-Q detaches' '<pause>y\n' \
		'Vault token for http://host.docker.internal:58200:' "$E2E_VAULT_TOKEN\\n" \
		'Type "continue" to proceed' 'continue\n' \
		'lock inventory serves: detached' '' \
		-- env LOCKSQL_IMAGE="$verb_image" "$lox" add locksql >"$out/add2.out" 2>&1 ||
		{ cat "$out/add2.out"; die "lox add locksql (inventory, vault) failed"; }
	cat "$out/add2.out"
	cat .lockfamily/lockfamily.yaml
	block inventory .lockfamily/lockfamily.yaml | grep -q '^    vault: true$' || die "lockfamily.yaml: inventory has no vault: true"
	block inventory .lockfamily/lockfamily.yaml | grep -q '^    profile: inventory$' || die "lockfamily.yaml: inventory names no profile"
	# The pinned image is the registry's <ver>-vault digest (the add names
	# its release; the registry names the variant's digest).
	ver=$(sed -n 's/^locksql v\([0-9][0-9.]*\) (vault): .*$/\1/p' "$out/add2.out")
	pinned=$(block inventory .lockfamily/lockfamily.yaml | sed -n 's/^    image: \(ghcr\.io\/davidgodefroid\/locksql@sha256:\([0-9a-f]\{64\}\)\)$/\1/p')
	[ -n "$ver" ] || die "lox add (vault) named no release in its output"
	[ -n "$pinned" ] || die "lockfamily.yaml: inventory pins no locksql digest"
	tok=$(curl -fsS -m 30 "https://ghcr.io/token?scope=repository:davidgodefroid/locksql:pull" | jq -r .token)
	# The registry answers the digest as an HTTP header: its name arrives
	# lower case over HTTP/2.
	reg=$(curl -fsSI -m 30 -H "Authorization: Bearer $tok" \
		-H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
		"https://ghcr.io/v2/davidgodefroid/locksql/manifests/$ver-vault" | tr -d '\r' | grep -i '^docker-content-digest: ' | cut -d' ' -f2)
	[ -n "$reg" ] || die "the registry names no $ver-vault digest"
	[ "${pinned#*@}" = "$reg" ] || die "inventory pins $pinned, not the $ver-vault digest $reg"
	# VAULT_ADDR is only the inventory console's, in the applied compose.
	[ -f "$state/compose.yaml" ] || die "no applied compose"
	[ "$(grep -c 'VAULT_ADDR' "$state/compose.yaml")" = 1 ] || die "VAULT_ADDR is not the only one in the applied compose"
	block lock-inventory "$state/compose.yaml" | grep -q 'VAULT_ADDR: "http://host.docker.internal:58200"' || die "lock-inventory has no VAULT_ADDR in the applied compose"
	block lock-orders "$state/compose.yaml" | grep -q 'VAULT_ADDR' && die "lock-orders has VAULT_ADDR in the applied compose"

	say "a host agent's locksql query on inventory, approved through the facade"
	sql_query inventory inventory stock sku sku-1

	say "lockhub#143: a restarted console's pending question, shown by lox attach"
	# Its policy is approved: on a restart it asks only the Vault token,
	# and records it next to its socket before lox attach reads it.
	docker restart "$p-lock-inventory-1" >/dev/null
	i=0
	until docker exec "$p-lock-inventory-1" sh -c 'ls /run/locksql/*.question' >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -le 60 ] || die "the restarted inventory console recorded no question"
		sleep 1
	done
	python3 "$here/expect.py" 120 \
		'lock inventory waits for: Vault token for http://host.docker.internal:58200: (typed, not shown)' "<pause>$E2E_VAULT_TOKEN\\n" \
		'Type "continue" to proceed' 'continue\n' \
		'lock inventory serves: detached' '' \
		-- "$lox" attach inventory >"$out/attach-restart.out" 2>&1 ||
		{ cat "$out/attach-restart.out"; die "lox attach did not show the restarted console's question"; }
	cat "$out/attach-restart.out"
	grep -q 'Apply these changes\|Type the profile name' "$out/attach-restart.out" && die "lox attach printed a guess list"
	python3 "$here/expect.py" 60 \
		'lock inventory is serving: nothing to answer' '<detach>' \
		-- "$lox" attach inventory >"$out/attach-serving.out" 2>&1 ||
		{ cat "$out/attach-serving.out"; die "lox attach did not say the serving console asks nothing"; }

	say "lockhub#124: vault_token: cli, the host's Vault CLI token answers the console's prompt"
	# A child token of the dev root token, so revoking it leaves the typed
	# fallback working. The host's Vault CLI is a vault binary on PATH that
	# prints it (as a token helper would), only with the reviewed address
	# and without lox's VAULT_TOKEN.
	cli_tok=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$E2E_VAULT_TOKEN" \
		"$E2E_VAULT_CONTAINER" vault token create -policy=root -ttl=1h -field=token)
	[ -n "$cli_tok" ] || die "no child Vault token"
	(umask 077 && printf '%s\n' "$cli_tok" >"$top/vault-token")
	printf '#!/bin/sh\n[ "$1 $2" = "print token" ] || exit 2\n[ "$VAULT_ADDR" = http://host.docker.internal:58200 ] || exit 3\n[ -z "${VAULT_TOKEN:-}" ] || exit 4\nexec cat %s\n' "$top/vault-token" >"$bin/vault"
	chmod 0755 "$bin/vault"
	awk '{ print } /^  inventory:$/ { on = 1; next } /^  [^ ]/ { on = 0 } on && /^    vault: true$/ { print "    vault_token: cli" }' \
		.lockfamily/lockfamily.yaml >"$out/lf.yaml" && cat "$out/lf.yaml" >.lockfamily/lockfamily.yaml
	block inventory .lockfamily/lockfamily.yaml | grep -q '^    vault_token: cli$' || die "lockfamily.yaml: no vault_token: cli on inventory"
	# restart_inventory: its console asks the Vault token again, recorded
	# next to its socket.
	restart_inventory() {
		docker restart "$p-lock-inventory-1" >/dev/null
		i=0
		until docker exec "$p-lock-inventory-1" sh -c 'ls /run/locksql/*.question' >/dev/null 2>&1; do
			i=$((i + 1))
			[ "$i" -le 60 ] || die "the restarted inventory console recorded no question"
			sleep 1
		done
	}
	restart_inventory
	# lox run with its output piped: plain lines, keys still read at the
	# terminal. The review asks the loosening; the Vault token prompt is
	# answered by lox run alone, the console's next question by the human.
	python3 "$here/expect.py" 600 \
		'Apply? [y/N]' 'y\n' \
		'vault token: from CLI' '' \
		'Type "continue" to proceed' '<pause>continue\n' \
		'+ you' '<pause>qq' \
		-- sh -c '"$1" run 2>&1 | cat' sh "$lox" >"$out/run-cli.raw" 2>&1 ||
		{ tr -d '\r' <"$out/run-cli.raw"; die "lox run (vault_token: cli) failed"; }
	tr -d '\r' <"$out/run-cli.raw" >"$out/run-cli.out"
	cat "$out/run-cli.out"
	grep -qF "vault token  from the host's Vault CLI" "$out/run-cli.out" || die "the review does not show vault_token: cli"
	# One card only: the console's "continue", not its Vault token prompt.
	[ "$(grep -c 'answer: type it, then Enter' "$out/run-cli.out")" = 1 ] || die "lox run asked the human more than the console's continue"
	python3 "$here/expect.py" 60 \
		'lock inventory is serving: nothing to answer' '<detach>' \
		-- "$lox" attach inventory >"$out/attach-cli.out" 2>&1 ||
		{ cat "$out/attach-cli.out"; die "inventory is not serving with the Vault CLI's token"; }
	say "a host agent's locksql query on inventory, its console on the Vault CLI's token"
	sql_query inventory inventory stock sku sku-1

	say "lockhub#124: the Vault CLI's token revoked, the next start falls back to the typed token"
	docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$E2E_VAULT_TOKEN" \
		"$E2E_VAULT_CONTAINER" vault token revoke "$cli_tok" >/dev/null || die "the child token was not revoked"
	restart_inventory
	python3 "$here/expect.py" 600 \
		"the Vault CLI's token cannot be used" "<pause>$E2E_VAULT_TOKEN\\n" \
		'Type "continue" to proceed' '<pause>continue\n' \
		'+ you' '<pause>qq' \
		-- sh -c '"$1" run 2>&1 | cat' sh "$lox" >"$out/run-revoked.raw" 2>&1 ||
		{ tr -d '\r' <"$out/run-revoked.raw"; die "lox run (revoked CLI token) failed"; }
	tr -d '\r' <"$out/run-revoked.raw" >"$out/run-revoked.out"
	cat "$out/run-revoked.out"
	python3 "$here/expect.py" 60 \
		'lock inventory is serving: nothing to answer' '<detach>' \
		-- "$lox" attach inventory >"$out/attach-typed.out" 2>&1 ||
		{ cat "$out/attach-typed.out"; die "inventory is not serving with the typed token"; }
	# The journal says how each token went, never the token.
	how=$(jq -r 'select(.event == "vault-token" and .instance == "inventory") | .vault' "$state/runs.jsonl" | tr '\n' ' ')
	[ "$how" = "cli typed " ] || { cat "$state/runs.jsonl"; die "the journal says '$how', want 'cli typed '"; }
	rm "$bin/vault"

	say "lockhub#123: the Vault address is an endpoint of the vault: true lock only"
	reaches "$p-lock-inventory-1" host.docker.internal 58200 || die "inventory (vault: true) does not reach Vault"
	reaches "$p-lock-orders-1" host.docker.internal 55432 || die "control: orders does not reach its database"
	reaches "$p-lock-orders-1" host.docker.internal 58200 && die "orders (no vault: true) reached Vault"
	grep -qF '"58200=gwout-inventory:' "$state/compose.yaml" || die "inventory's gateway does not forward Vault"

	say "lox remove inventory: its console stops, its profile stays"
	tty 'y\n' "$lox" remove inventory >"$out/rm-inv.out" 2>&1 || { cat "$out/rm-inv.out"; die "lox remove inventory failed"; }
	cat "$out/rm-inv.out"
	docker inspect "$p-lock-inventory-1" >/dev/null 2>&1 && die "the inventory console still exists"
	grep -q '^  inventory:$' .lockfamily/lockfamily.yaml && die "lockfamily.yaml still declares inventory"
	grep -q '^\[profiles\.inventory\]' .locksql/config.toml || die "the inventory profile did not stay in .locksql/config.toml"
fi

say "lox remove orders --purge: its console stops, its profile goes"
tty 'y\n' "$lox" remove orders --purge >"$out/rm-orders.out" 2>&1 || { cat "$out/rm-orders.out"; die "lox remove orders failed"; }
cat "$out/rm-orders.out"
docker inspect "$p-lock-orders-1" >/dev/null 2>&1 && die "the orders console still exists"
grep -q '^  orders:$' .lockfamily/lockfamily.yaml && die "lockfamily.yaml still declares orders"
grep -q '^\[profiles\.orders\]' .locksql/config.toml && die "the orders profile stayed in .locksql/config.toml"
jq -e '.locks | length == 0' "$ws/.lockfamily/up.json" >/dev/null || die "up.json does not declare zero locks"

say "no secret written: the workspace (but .env) and lox up's state directory"
leak=""
if [ "$vault" = 1 ]; then secrets="$inv_pw $E2E_VAULT_TOKEN $cli_tok"; else secrets=$inv_pw; fi
for s in $secrets; do
	if grep -rlF --exclude=.env -- "$s" "$ws" "$state" 2>/dev/null; then leak=1; fi
done
[ -z "$leak" ] || die "a secret is on disk (above)"
# Positive controls: grep finds the password where it is.
grep -qF -- "$inv_pw" .env || die "control: the password is not in .env (the check above proves nothing)"
[ -n "$(ls -A "$state")" ] || die "control: the state directory is empty"
echo "first run e2e: OK"
