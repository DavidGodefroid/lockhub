#!/bin/sh
# lox add lockfile with an sftp source, its known hosts file a host file
# (lockhub#174): lox add copies it into .lockfile/ and the profile names
# ~/.config/lockfile/known_hosts, where the console sees its profile's
# reviewed copy, so the console opens it at its first start and that
# copy pins the server's key (a strict login from the console's network
# shows it). The SFTP
# server runs in a container of this machine (host.docker.internal), login
# by password (typed at the console's start). Before that, a profile that
# names the host path is said in lox run's review, before any start.
#
# `lockfile profile add` runs on the host: LOCKFILE_BIN is lockfile's
# binary at the release lox add pins.
#
#   LOCKFILE_BIN=.../lockfile ci/e2e/lockfile-sftp.sh LOX_BIN
. "$(dirname "$0")/lib.sh"
lox=$1
here=$(cd "$(dirname "$0")" && pwd)
[ -n "${LOCKFILE_BIN:-}" ] && [ -x "$LOCKFILE_BIN" ] || die "LOCKFILE_BIN (lockfile's binary) is not set"
ws=$(realpath "$(mktemp -d)")/projects
mkdir -p "$ws"
cd "$ws"
bin=$(dirname "$ws")/bin
keys=$(dirname "$ws")/keys
sftpd=lockfile-sftpd-$E2E_ID
probe=lockfile-sftp-probe-$E2E_ID
port=${SFTP_PORT:-22023}
cleanup() {
	if [ -f "$ws/.lockfamily/up.json" ]; then
		p=$(ws_project "$ws")
		docker compose -p "$p" --project-directory "$XDG_STATE_HOME/lockfamily/$p" -f "$XDG_STATE_HOME/lockfamily/$p/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	docker rm -f "$sftpd" "$probe" >/dev/null 2>&1 || true
	docker image rm "$probe:e2e" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

say "an SFTP server: alpine's openssh, login deploy by password, sftp only"
mkdir -p "$keys"
ssh-keygen -q -t ed25519 -N '' -C sftpd-e2e -f "$keys/host_ed25519"
chmod 0644 "$keys/host_ed25519" # read by the container's root only, from a throwaway mount
docker run -d --name "$sftpd" -p "$port:22" -v "$keys:/keys:ro" alpine:3.22 sh -c '
	set -e
	apk add --no-cache openssh >/dev/null
	adduser -D -s /bin/sh deploy
	echo "deploy:sftp-e2e-only" | chpasswd
	install -m 0600 /keys/host_ed25519 /etc/ssh/ssh_host_ed25519_key
	mkdir -p /home/deploy/inbox
	echo "order 1001" >/home/deploy/inbox/orders.txt
	chown -R deploy:deploy /home/deploy/inbox
	exec /usr/sbin/sshd -D -e -o PasswordAuthentication=yes -o PermitRootLogin=no -o "Subsystem sftp internal-sftp" \
		-o ForceCommand=internal-sftp -o HostKey=/etc/ssh/ssh_host_ed25519_key -o AllowTcpForwarding=no -o X11Forwarding=no -o LogLevel=VERBOSE
' >/dev/null
ok=""
for i in $(seq 1 60); do
	if docker logs "$sftpd" 2>&1 | grep -q 'Server listening'; then ok=1; break; fi
	sleep 1
done
[ -n "$ok" ] || { docker logs "$sftpd"; die "sshd did not start"; }
# The host key the profile pins, in a host file outside the workspace (the
# issue's case).
printf '[host.docker.internal]:%s %s\n' "$port" "$(cut -d' ' -f1,2 "$keys/host_ed25519.pub")" >"$keys/known_hosts_sftp"

mkdir -p "$bin"
cp "$LOCKFILE_BIN" "$bin/lockfile"
PATH="$bin:$PATH"
export PATH

say "lox add lockfile --source sftp --known-hosts <a host file>: the file copied into .lockfile/"
"$lox" add lockfile --non-interactive --source sftp --host host.docker.internal --port "$port" --user deploy \
	--auth password --known-hosts "$keys/known_hosts_sftp" --base-dir inbox --credentials ask --name drop >add.out 2>&1 ||
	{ cat add.out; die "lox add lockfile failed"; }
cat add.out
cmp "$keys/known_hosts_sftp" .lockfile/known_hosts || die ".lockfile/known_hosts is not the host file"
grep -qx 'known_hosts *= *"~/.config/lockfile/known_hosts"' .lockfile/config.toml ||
	{ cat .lockfile/config.toml; die "the profile does not name ~/.config/lockfile/known_hosts"; }
grep -qF "$keys" .lockfile/config.toml && die "the profile still names a host path"
local_hub .lockfamily/lockfamily.yaml

say "lox run, a profile naming the host path: the review says it, before any start"
cp .lockfile/config.toml config.toml.good
sed -i "s#^known_hosts *=.*#known_hosts = \"$keys/known_hosts_sftp\"#" .lockfile/config.toml
python3 "$here/expect.py" 600 'Apply? [y/N]' 'n\n' -- "$lox" run >bad.raw 2>&1 || true
tr -d '\r' <bad.raw >bad.out
grep -qF "known_hosts: $keys/known_hosts_sftp not found in the lock's container; copy it to .lockfile/known_hosts_sftp and write it ~/.config/lockfile/known_hosts_sftp" bad.out ||
	{ cat bad.out; die "the review does not flag the host path"; }
cp config.toml.good .lockfile/config.toml

say "lox run: the review checks known_hosts in the reviewed copy, and starts the lock"
python3 "$here/expect.py" 600 'Apply? [y/N]' 'y\n' "up: project " "<pause>qq" -- "$lox" run >run.raw 2>&1 || { tr -d '\r' <run.raw; die "lox run failed"; }
tr -d '\r' <run.raw >run.out
sed -n '1,/^up: project /p' run.out
hub_cosigned run.out
p=$(ws_project "$ws")
hub_is_local "$p"
grep -q "known_hosts:" run.out && { cat run.out; die "the review flags the known_hosts lox add wrote"; }
grep -qF "only host.docker.internal:$port" run.out || die "the review lacks the egress to host.docker.internal:$port"

# The console opens the profile's known_hosts at its start, once the
# password is typed, and stops there when it cannot (the issue's
# "sftp known_hosts: open ...: no such file or directory"): it listens
# only once that file is read. Its SFTP session itself opens on an agent's
# first request (lockfile's source dials per request).
say "the console's first start: its policy, then the SFTP password; it opens known_hosts and listens"
python3 "$here/attach.py" 120 'y\n' 'Listening on ' 'Password for ' 'sftp-e2e-only\n' -- "$lox" attach drop >attach.out 2>&1 || {
	tr -d '\r' <attach.out
	die "the lockfile console did not start (its known_hosts not opened?)"
}
tr -d '\r' <attach.out | tail -5
tr -d '\r' <attach.out | grep -q "known_hosts" && die "the console said something of known_hosts"

c="$p-lock-drop-1"
[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || { docker logs "$c" 2>&1 | tail -20 || true; die "$c is not running"; }
say "the console's account reads the known_hosts its profile names, where the console sees it"
docker exec "$c" cat /home/lockfile/.config/lockfile/known_hosts >seen_known_hosts || die "the console's account cannot read ~/.config/lockfile/known_hosts"
cmp seen_known_hosts "$keys/known_hosts_sftp" || die "the console sees another known_hosts"

# A strict SSH client in the console's own network namespace, with the
# profile's reviewed copy (its volume, read-only): the server's key is
# the one pinned, and the console's egress reaches it.
say "an SFTP login from the console's network, strict on the copy's known_hosts"
docker rm -f "$probe" >/dev/null 2>&1 || true
docker run --name "$probe" alpine:3.22 apk add --no-cache openssh-client sshpass >/dev/null || die "the probe's tools did not install"
docker commit "$probe" "$probe:e2e" >/dev/null
docker rm -f "$probe" >/dev/null
printf 'ls inbox\n' | docker run --rm -i --network "container:$c" -v "${p}_profile-lockfile:/p:ro" -e SSHPASS=sftp-e2e-only "$probe:e2e" \
	sshpass -e sftp -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/p/known_hosts -o GlobalKnownHostsFile=/dev/null \
	-o PubkeyAuthentication=no -o PreferredAuthentications=password -P "$port" deploy@host.docker.internal >probe.out 2>&1 ||
	{ cat probe.out; docker logs "$sftpd" 2>&1 | tail -20; die "a strict SFTP login with the profile's known_hosts failed"; }
cat probe.out
grep -q orders.txt probe.out || die "the SFTP listing lacks inbox/orders.txt"
docker logs "$sftpd" 2>&1 | grep -Eq "Accepted password for deploy" || { docker logs "$sftpd" 2>&1 | tail -20; die "the SFTP server saw no login"; }

say "PASS: lox add lockfile --known-hosts <host file>: the console opens it at its first start, and it pins the server's key"
