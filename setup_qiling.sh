#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements-qiling.txt"
if [[ ! -d "$ROOT/qiling-rootfs/x8664_windows" ]]; then
  mkdir -p "$ROOT/qiling-rootfs/x8664_windows"
  unzip -q "$ROOT/qiling_x8664_rootfs.zip" -d "$ROOT/qiling-rootfs/x8664_windows"
fi
# The archive contains the Windows directory expected by Qiling.
cat <<'EOF'
Qiling is installed. Windows PE emulation additionally needs Windows DLLs and registry
hives in qiling-rootfs/x8664_windows (see qilingframework/qiling examples/scripts/dllscollector.bat).
Run: .venv/bin/python run_qiling.py crackmevm1.exe
EOF
