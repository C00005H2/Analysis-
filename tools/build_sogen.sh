#!/usr/bin/env bash
# Build Sogen (https://github.com/momo5502/sogen) from source in this sandbox.
#
# Environment notes (Debian 12, 2 cores, no apt / no sudo):
#   * cmake + ninja come from pip (no apt), installed into ~/.venv
#   * qemu's configure inside deps/unicorn requires a `pkg-config` binary;
#     a stub that always fails is enough -> ~/bin/pkg-config
#   * GCC 12 trips two false-positive -Wrestrict/-Wstringop-overflow warnings and
#     Sogen builds with -Werror, so -Werror is dropped from cmake/utils.cmake
#   * rust / SDL3 / LTO / reflection are disabled to keep the build small & fast
set -euo pipefail

SRC=${SRC:-$HOME/tools/sogen-src}
OUT=${OUT:-$HOME/tools/sogen/bin}

python3 -m venv "$HOME/.venv" 2>/dev/null || true
"$HOME/.venv/bin/pip" -q install cmake ninja capstone pefile

mkdir -p "$HOME/bin"
printf '#!/bin/sh\nexit 1\n' > "$HOME/bin/pkg-config"
chmod +x "$HOME/bin/pkg-config"
export PATH="$HOME/bin:$HOME/.venv/bin:$PATH"

if [ ! -d "$SRC" ]; then
  git clone --recurse-submodules --depth 1 https://github.com/momo5502/sogen.git "$SRC"
fi

sed -i 's/-pedantic -Werror -Wno-comment/-pedantic -Wno-comment -Wno-error/' "$SRC/cmake/utils.cmake"

cmake -S "$SRC" -B "$SRC/build/rel" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DSOGEN_ENABLE_RUST_CODE=OFF \
  -DSOGEN_ENABLE_SDL3=OFF \
  -DSOGEN_ENABLE_LTO=OFF \
  -DSOGEN_ENABLE_REFLECTION=OFF

cmake --build "$SRC/build/rel" --target analyzer -j"$(nproc)"

mkdir -p "$OUT"
cp "$SRC/build/rel/artifacts/analyzer" "$SRC"/build/rel/artifacts/*.so "$OUT/"
echo "built: $OUT/analyzer"
"$OUT/analyzer" --help | head -5
