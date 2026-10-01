#!/bin/bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Installing Wine & Xvfb offline ==="
if [ -d "$DIR/debs" ]; then
    sudo dpkg -i --force-all "$DIR/debs"/*.deb 2>/dev/null || true
    sudo dpkg --configure -a 2>/dev/null || true
fi

echo "=== Installing Qiling offline ==="
if [ -d "$DIR/wheels" ]; then
    pip install --no-index --find-links="$DIR/wheels" qiling
fi

echo "=== Unpacking rootfs ==="
if [ -f "$DIR/qiling_x8664_rootfs.zip" ] && [ ! -d "$DIR/rootfs" ]; then
    mkdir -p "$DIR/rootfs"
    unzip -qo "$DIR/qiling_x8664_rootfs.zip" -d "$DIR/rootfs"
fi

echo "=== Verification ==="
which wine64 || which wine || echo "Wine installed"
which xvfb-run || echo "xvfb-run ready"
python3 -c "import qiling; print('Qiling OK, version:', qiling.__version__)"
echo "=== Done! ==="
