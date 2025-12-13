#!/usr/bin/env bash
# Launches a demo setup with server + two clients (alice/bob) in separate tmux windows.
# Cleans up temp data and the tmux session on exit.

set -euo pipefail

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required to run this script." >&2
  exit 1
fi

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d -t pch-demo-XXXX)"
SESSION="pch-demo"
PORT="${PORT:-8001}"

cleanup() {
  tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "workdir: $WORKDIR"
echo "server port: $PORT"
echo "starting tmux session '$SESSION'..."

# Server window
tmux new-session -d -s "$SESSION" -c "$ROOT_DIR" \
  "go run ./cmd/server -port \"$PORT\" -db \"$WORKDIR/server.db\""

# Alice client
tmux new-window -t "$SESSION" -n "alice" -c "$ROOT_DIR" \
  "go run ./cmd/client -username alice -server \"localhost:$PORT\" -storage \"$WORKDIR/alice.db\""

# Bob client
tmux new-window -t "$SESSION" -n "bob" -c "$ROOT_DIR" \
  "go run ./cmd/client -username bob -server \"localhost:$PORT\" -storage \"$WORKDIR/bob.db\""

tmux select-window -t "$SESSION:alice"

cat <<EOF

Controls:
- tmux session: $SESSION
- windows: server | alice | bob
- detach: Ctrl+b then d
- end demo: exit clients/server or kill-session (:kill-session) — script will clean up.

Temporary files are under: $WORKDIR
EOF

tmux attach -t "$SESSION"
