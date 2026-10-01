#!/usr/bin/env bash
# Launch the crackme inside Sogen with the GDB stub enabled.
#
#   tools/debug_crackme.sh samples/crackme.exe            # debug mode (waits for client)
#   TRACE=1 tools/debug_crackme.sh samples/crackme.exe    # plain traced run, no debugger
#
# Then, from a second shell:
#   ~/.venv/bin/python tools/rsp_debugger.py --port 28960
set -euo pipefail

SAMPLE=${1:?usage: debug_crackme.sh <sample.exe>}
ROOT=${ROOT:-$HOME/tools/sogen/root}
ANALYZER=${ANALYZER:-$HOME/tools/sogen/bin/analyzer}
PORT=${PORT:-28960}

if [ ! -d "$ROOT" ]; then
  echo "!! emulation root missing at $ROOT"
  echo "   get it from https://sogen.dev/root.zip (or build one per the Sogen wiki)"
  echo "   and unzip it there."
  exit 1
fi

SAMPLE_ABS=$(readlink -f "$SAMPLE")
GUEST_PATH="c:/analysis-sample.exe"

if [ "${TRACE:-0}" = "1" ]; then
  exec "$ANALYZER" -v --call-count --reproducible \
    -e "$ROOT" -p "$GUEST_PATH" "$SAMPLE_ABS" "$GUEST_PATH"
fi

exec "$ANALYZER" -d --bind 0.0.0.0 --port "$PORT" --gdb-arch 64bits \
  -e "$ROOT" -p "$GUEST_PATH" "$SAMPLE_ABS" "$GUEST_PATH"
