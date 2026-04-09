#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ACTION="${1:-up}"
LAB_DIR="${2:-${DIODE_MANUAL_LAB_DIR:-$ROOT_DIR/.manual/cli-lab}}"
BIN_PATH="$ROOT_DIR/diode"
RUN_DIR="$LAB_DIR/run"
WALLET_DIR="$LAB_DIR/wallets"
HTTP_DIR="$LAB_DIR/http"
FILES_DIR="$LAB_DIR/files"
OUT_DIR="$LAB_DIR/out"
ENV_PATH="$LAB_DIR/env.sh"

OWNER_DB="$WALLET_DIR/owner/private.db"
PEER_DB="$WALLET_DIR/peer/private.db"
VIEWER_DB="$WALLET_DIR/viewer/private.db"

OWNER_HTTP_PORT=18080
PEER_HTTP_PORT=18081

OWNER_HTTP_ROOT="$HTTP_DIR/owner"
PEER_HTTP_ROOT="$HTTP_DIR/peer"
OWNER_FILES_ROOT="$FILES_DIR/owner"
PEER_FILES_ROOT="$FILES_DIR/peer"

usage() {
	cat <<EOF
Usage:
  $(basename "$0") up [lab-dir]
  $(basename "$0") down [lab-dir]
  $(basename "$0") status [lab-dir]

The lab script:
  - builds ./diode
  - creates three isolated wallet DBs
  - starts two local Python HTTP fixture servers
  - writes $ENV_PATH with exported paths and helper shell functions
EOF
}

require_cmd() {
	local name="$1"
	if ! command -v "$name" >/dev/null 2>&1; then
		echo "missing required command: $name" >&2
		exit 1
	fi
}

stop_pidfile() {
	local pidfile="$1"
	if [[ ! -f "$pidfile" ]]; then
		return
	fi
	local pid=""
	pid="$(cat "$pidfile" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
		kill "$pid" >/dev/null 2>&1 || true
		for _ in $(seq 1 20); do
			if ! kill -0 "$pid" >/dev/null 2>&1; then
				break
			fi
			sleep 0.1
		done
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill -9 "$pid" >/dev/null 2>&1 || true
		fi
	fi
	rm -f "$pidfile"
}

start_http_server() {
	local name="$1"
	local root="$2"
	local port="$3"
	local pidfile="$RUN_DIR/$name.pid"
	local logfile="$RUN_DIR/$name.log"

	stop_pidfile "$pidfile"
	nohup python3 -m http.server "$port" --bind 127.0.0.1 --directory "$root" >"$logfile" 2>&1 &
	local pid=$!
	echo "$pid" >"$pidfile"

	for _ in $(seq 1 20); do
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			echo "failed to start $name fixture server, see $logfile" >&2
			exit 1
		fi
		if python3 - <<PY >/dev/null 2>&1
import socket
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", $port))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
		then
			return
		fi
		sleep 0.2
	done
	echo "timed out waiting for $name fixture server on 127.0.0.1:$port" >&2
	exit 1
}

wallet_address() {
	local dbpath="$1"
	local output
	output="$("$BIN_PATH" -update=false -no-daemon -dbpath "$dbpath" config -list 2>&1)"
	printf '%s\n' "$output" | awk -F: '/<address>/{gsub(/[[:space:]]/, "", $2); print $2; exit}'
}

write_lab_files() {
	mkdir -p "$OWNER_HTTP_ROOT" "$PEER_HTTP_ROOT" "$OWNER_FILES_ROOT" "$PEER_FILES_ROOT" "$OUT_DIR" "$RUN_DIR"

	cat >"$OWNER_HTTP_ROOT/index.html" <<'EOF'
owner-public-fixture
EOF
	cat >"$OWNER_HTTP_ROOT/health.json" <<'EOF'
{"service":"owner","status":"ok"}
EOF
	cat >"$PEER_HTTP_ROOT/index.html" <<'EOF'
peer-public-fixture
EOF
	cat >"$PEER_HTTP_ROOT/health.json" <<'EOF'
{"service":"peer","status":"ok"}
EOF
	cat >"$LAB_DIR/sample-upload.txt" <<'EOF'
manual-upload-payload
EOF
}

write_env() {
	local owner_addr="$1"
	local peer_addr="$2"
	local viewer_addr="$3"

	cat >"$ENV_PATH" <<EOF
export DIODE_LAB_DIR='$LAB_DIR'
export DIODE_BIN='$BIN_PATH'
export DIODE_OWNER_DB='$OWNER_DB'
export DIODE_PEER_DB='$PEER_DB'
export DIODE_VIEWER_DB='$VIEWER_DB'
export DIODE_OWNER_ADDR='$owner_addr'
export DIODE_PEER_ADDR='$peer_addr'
export DIODE_VIEWER_ADDR='$viewer_addr'
export DIODE_OWNER_HTTP_PORT='$OWNER_HTTP_PORT'
export DIODE_PEER_HTTP_PORT='$PEER_HTTP_PORT'
export DIODE_OWNER_HTTP_ROOT='$OWNER_HTTP_ROOT'
export DIODE_PEER_HTTP_ROOT='$PEER_HTTP_ROOT'
export DIODE_OWNER_FILES_ROOT='$OWNER_FILES_ROOT'
export DIODE_PEER_FILES_ROOT='$PEER_FILES_ROOT'
export DIODE_SAMPLE_UPLOAD='$LAB_DIR/sample-upload.txt'
export DIODE_OUTPUT_DIR='$OUT_DIR'

downer() { "\$DIODE_BIN" -update=false -no-daemon -dbpath "\$DIODE_OWNER_DB" "\$@"; }
dpeer() { "\$DIODE_BIN" -update=false -no-daemon -dbpath "\$DIODE_PEER_DB" "\$@"; }
dviewer() { "\$DIODE_BIN" -update=false -no-daemon -dbpath "\$DIODE_VIEWER_DB" "\$@"; }
ddaemon() { "\$DIODE_BIN" -update=false -dbpath "\$DIODE_OWNER_DB" "\$@"; }

dstopdaemon() {
	"\$DIODE_BIN" -update=false -dbpath "\$DIODE_OWNER_DB" daemon stop >/dev/null 2>&1 || true
	rm -f "\$HOME/.config/diode/daemon.sock" "\$HOME/.config/diode/daemon.sock.json"
}
EOF
}

do_up() {
	require_cmd go
	require_cmd python3

	mkdir -p "$LAB_DIR"
	write_lab_files

	(
		cd "$ROOT_DIR"
		go build -o ./diode ./cmd/diode
	)

	local owner_addr peer_addr viewer_addr
	owner_addr="$(wallet_address "$OWNER_DB")"
	peer_addr="$(wallet_address "$PEER_DB")"
	viewer_addr="$(wallet_address "$VIEWER_DB")"

	if [[ -z "$owner_addr" || -z "$peer_addr" || -z "$viewer_addr" ]]; then
		echo "failed to derive one or more wallet addresses" >&2
		exit 1
	fi

	start_http_server "owner-http" "$OWNER_HTTP_ROOT" "$OWNER_HTTP_PORT"
	start_http_server "peer-http" "$PEER_HTTP_ROOT" "$PEER_HTTP_PORT"
	write_env "$owner_addr" "$peer_addr" "$viewer_addr"

	cat <<EOF
Manual CLI lab is ready.

Lab dir      : $LAB_DIR
Env file     : $ENV_PATH
Owner wallet : $owner_addr
Peer wallet  : $peer_addr
Viewer wallet: $viewer_addr

HTTP fixtures:
  owner: http://127.0.0.1:$OWNER_HTTP_PORT/
  peer : http://127.0.0.1:$PEER_HTTP_PORT/

Next:
  source '$ENV_PATH'
EOF
}

do_down() {
	stop_pidfile "$RUN_DIR/owner-http.pid"
	stop_pidfile "$RUN_DIR/peer-http.pid"
	echo "Stopped lab HTTP fixtures in $LAB_DIR"
}

do_status() {
	local name pidfile pid
	for name in owner-http peer-http; do
		pidfile="$RUN_DIR/$name.pid"
		if [[ -f "$pidfile" ]]; then
			pid="$(cat "$pidfile" 2>/dev/null || true)"
			if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
				echo "$name: running (pid $pid)"
				continue
			fi
		fi
		echo "$name: stopped"
	done
	if [[ -f "$ENV_PATH" ]]; then
		echo "env: $ENV_PATH"
	else
		echo "env: missing"
	fi
}

case "$ACTION" in
up)
	do_up
	;;
down)
	do_down
	;;
status)
	do_status
	;;
help|-h|--help)
	usage
	;;
*)
	usage >&2
	exit 2
	;;
esac
