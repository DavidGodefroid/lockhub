# Helpers of the lock up end-to-end scripts (sourced). The scripts remove
# only what they create: their compose project, gate and network.
set -eu
E2E_ID=${E2E_ID:-e2e$$}
say() { printf '\n=== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# tty INPUT CMD...: runs CMD at a pseudo-terminal (lock up, approve and
# attach refuse a pipe), INPUT typed in. Output goes to stdout.
tty() {
	in=$1
	shift
	printf '%b' "$in" | script -qefc "$*" /dev/null
}
# ws_project WS: the compose project of the workspace WS.
ws_project() { jq -r .project "$1/.lockfamily/up.json"; }
