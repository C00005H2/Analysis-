#!/usr/bin/env bash
set -euo pipefail

# Sogen source is vendored as a git submodule tree under tools/sogen.  This script
# installs the Python bindings and fetches the optional Windows emulation root.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -d tools/sogen/.git ]]; then
  git clone --recurse-submodules https://github.com/momo5502/sogen.git tools/sogen
else
  git -C tools/sogen submodule update --init --recursive
fi

python3 -m venv .venv-tools
. .venv-tools/bin/activate
python -m pip install --upgrade pip setuptools wheel
# Binary wheels provide CMake/Ninja without requiring apt repositories.
python -m pip install cmake ninja libclang
export PATH="$ROOT_DIR/.venv-tools/bin:$PATH"

python3 -m venv "$ROOT_DIR/.venv-sogen"
. "$ROOT_DIR/.venv-sogen/bin/activate"
python -m pip install --upgrade pip setuptools wheel
# The current upstream package is source distributed; this compiles the native
# extension and therefore needs the system C++ compiler and Python headers.
python -m pip install sogen

if [[ ! -d tools/sogen/root ]]; then
  mkdir -p tools/sogen/root
  echo "Downloading the upstream emulation root..."
  python - <<'PY'
import urllib.request
urllib.request.urlretrieve('https://sogen.dev/root.zip', '/tmp/sogen-root.zip')
PY
  unzip -q /tmp/sogen-root.zip -d tools/sogen/root
fi

echo
printf 'Sogen source: %s\n' "$ROOT_DIR/tools/sogen"
printf 'Python:       %s\n' "$(python -c 'import sogen; print(sogen.__file__)')"
printf 'Root:         %s\n' "$ROOT_DIR/tools/sogen/root"
printf '\nRun: .venv-sogen/bin/python tools/analyze_crackme.py crackmevm1.exe\n'
