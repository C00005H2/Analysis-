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

python3 -m venv .venv-sogen
. .venv-sogen/bin/activate
python -m pip install --upgrade pip
# The current upstream package is source distributed; this may compile the
# native extension and therefore needs a C++ compiler and CMake on the host.
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
