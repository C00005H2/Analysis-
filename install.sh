#!/bin/bash
# ---------------------------------------------------------------------------
# Offline installer for Wine (64/32-bit), Xvfb and Qiling.
#
# The bundled .deb files are Ubuntu 24.04 "noble" builds. They are installed
# here with no network access at all. Two portability problems are handled
# automatically:
#
#   1. glibc skew - noble binaries reference glibc 2.38/2.39 symbols. On an
#      older host (e.g. Debian 12 / glibc 2.36) the dynamic loader refuses to
#      load them. tools/elfcompat.c rewrites the affected references in place
#      (see that file for the details) so the binaries load natively.
#
#   2. Host package replacement - by default we never replace a package the
#      host already provides, so core tooling (python3, apt, ...) keeps its
#      known-good libraries. Pass --replace-host to opt out.
#
# Usage: bash install.sh [--replace-host] [--no-i386] [--skip-debs]
# ---------------------------------------------------------------------------
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"
BACKUP="${ELFCOMPAT_BACKUP:-/var/tmp/glibc-compat-backup}"

REPLACE_HOST=0; WITH_I386=1; SKIP_DEBS=0
for a in "$@"; do
    case "$a" in
        --replace-host) REPLACE_HOST=1 ;;
        --no-i386)      WITH_I386=0 ;;
        --skip-debs)    SKIP_DEBS=1 ;;
        -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

say()  { printf '\n\033[1;34m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '  \033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '  \033[1;31m[fail]\033[0m %s\n' "$*"; }

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
RC=0

# ---------------------------------------------------------------------------
say "Preflight"
HOST_GLIBC=$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$')
HOST_MINOR=${HOST_GLIBC#*.}
ok "host: $(. /etc/os-release && echo "$PRETTY_NAME")  glibc $HOST_GLIBC  $(dpkg --print-architecture)"
ok "bundle: $(ls "$DIR"/debs/*.deb 2>/dev/null | wc -l) debs, $(ls "$DIR"/wheels/*.whl 2>/dev/null | wc -l) wheels"

# ---------------------------------------------------------------------------
if [ "$SKIP_DEBS" -eq 0 ] && [ -d "$DIR/debs" ]; then
    say "Installing Wine & Xvfb (offline)"

    if [ "$WITH_I386" -eq 1 ]; then
        $SUDO dpkg --add-architecture i386
        ok "i386 multiarch enabled"
    fi

    native=(); foreign=(); skipped=()
    for f in "$DIR"/debs/*.deb; do
        pkg=$(dpkg-deb -f "$f" Package); arch=$(dpkg-deb -f "$f" Architecture)
        if [ "$arch" = "i386" ]; then
            [ "$WITH_I386" -eq 1 ] && foreign+=("$f")
            continue
        fi
        if [ "$REPLACE_HOST" -eq 0 ] &&
           dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "^install ok installed$"; then
            skipped+=("$pkg")
        else
            native+=("$f")
        fi
    done

    if [ ${#skipped[@]} -gt 0 ]; then
        warn "keeping host version of ${#skipped[@]} package(s): $(printf '%s ' "${skipped[@]}")"
    fi
    echo "  installing ${#native[@]} amd64/all + ${#foreign[@]} i386 package(s)..."
    [ ${#foreign[@]} -gt 0 ] && $SUDO dpkg -i --force-all "${foreign[@]}" >/dev/null 2>&1 || true
    [ ${#native[@]}  -gt 0 ] && $SUDO dpkg -i --force-all "${native[@]}"  >/dev/null 2>&1 || true
    $SUDO dpkg --configure -a >/dev/null 2>&1 || true
    $SUDO ldconfig || true
    ok "deb installation pass complete"

    # -----------------------------------------------------------------------
    say "Applying glibc compatibility patches"
    CC=$(command -v gcc || command -v cc || true)
    if [ -z "$CC" ]; then
        warn "no C compiler; skipping. Noble binaries may fail to load on glibc < 2.38."
    else
        "$CC" -O2 -o /tmp/elfcompat "$DIR/tools/elfcompat.c"
        mapfile -t cands < <(
            for d in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu /usr/bin /usr/sbin \
                     /usr/lib/wine /usr/libexec /usr/lib/gstreamer-1.0; do
                [ -d "$d" ] && grep -rlZ -e GLIBC_2.38 -e GLIBC_2.39 -e GLIBC_2.40 "$d" 2>/dev/null | tr '\0' '\n'
            done | sort -u
        )
        targets=()
        for f in "${cands[@]:-}"; do
            [ -f "$f" ] || continue
            head -c5 "$f" 2>/dev/null | grep -q $'\x7fELF\x02' && targets+=("$f")
        done
        if [ ${#targets[@]} -gt 0 ]; then
            $SUDO mkdir -p "$BACKUP"
            for f in "${targets[@]}"; do
                [ -e "$BACKUP$f" ] || { $SUDO mkdir -p "$BACKUP$(dirname "$f")"; $SUDO cp -a "$f" "$BACKUP$f"; }
            done
            ok "backed up ${#targets[@]} binaries to $BACKUP"
            $SUDO /tmp/elfcompat "$HOST_MINOR" "${targets[@]}" >/dev/null
            ok "patched ${#targets[@]} binaries for glibc $HOST_GLIBC"
        else
            ok "nothing to patch (host glibc is new enough)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
say "Installing Qiling (offline)"
if [ -d "$DIR/wheels" ]; then
    PYTAG=$(python3 -c 'import sys;print("cp%d%d"%sys.version_info[:2])')
    echo "  interpreter: $(python3 -V 2>&1) ($PYTAG)"
    [ -d "$VENV" ] || python3 -m venv "$VENV"
    PIP="$VENV/bin/pip"
    FL=(--no-index --find-links="$DIR/wheels")

    if $PIP install -q "${FL[@]}" qiling 2>/dev/null; then
        ok "Qiling installed with its full dependency set"
    else
        warn "bundled binary wheels are cp313-only; $PYTAG needs a reduced set"
        STAGE="$DIR/.wheels-retag"; rm -rf "$STAGE"; mkdir -p "$STAGE"
        for w in "$DIR"/wheels/*py313-none-any.whl; do
            [ -e "$w" ] || continue
            python3 - "$w" "$STAGE" <<'PY'
import sys, zipfile, os, re
src, out = sys.argv[1], sys.argv[2]
dst = os.path.join(out, os.path.basename(src).replace("py313-none-any", "py3-none-any"))
zin = zipfile.ZipFile(src)
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
    for it in zin.infolist():
        data = zin.read(it.filename)
        if it.filename.endswith(".dist-info/WHEEL"):
            data = re.sub(rb"Tag: py313-none-any", b"Tag: py3-none-any", data)
        z.writestr(it, data)
PY
        done
        $PIP install -q "${FL[@]}" capstone unicorn pefile python-registry \
             keystone-engine pyelftools termcolor >/dev/null 2>&1 || true
        $PIP install -q --no-index --find-links="$STAGE" --find-links="$DIR/wheels" \
             multiprocess >/dev/null 2>&1 && ok "multiprocess installed (retagged pure-python wheel)"
        $PIP install -q "${FL[@]}" --no-deps qiling
        ok "Qiling core installed (gevent-backed extras unavailable on $PYTAG)"
    fi
fi

# ---------------------------------------------------------------------------
say "Unpacking rootfs"
if [ -f "$DIR/qiling_x8664_rootfs.zip" ] && [ ! -d "$DIR/rootfs" ]; then
    mkdir -p "$DIR/rootfs"
    # unzip exits non-zero on harmless warnings (this archive uses backslash paths)
    unzip -qo "$DIR/qiling_x8664_rootfs.zip" -d "$DIR/rootfs" 2>/dev/null || true
    ok "rootfs unpacked"
else
    ok "rootfs already present"
fi

# ---------------------------------------------------------------------------
say "Verification"

check_runnable() {  # label, binary, [extra ldd targets...] -- then: args after --
    local label="$1" bin="$2"; shift 2
    local extra=() args=()
    while [ $# -gt 0 ]; do [ "$1" = "--" ] && { shift; args=("$@"); break; }; extra+=("$1"); shift; done

    if [ ! -e "$bin" ]; then err "$label: not installed"; RC=1; return; fi

    # Missing libs of the loader itself *and* of the modules it dlopens.
    # (Wine's own modules resolve each other via its private search path, so
    #  they are not real misses.)
    local miss targets=("$bin")
    [ ${#extra[@]} -gt 0 ] && targets+=("${extra[@]}")
    miss=$( { for t in "${targets[@]}"; do
                  [ -e "$t" ] || continue
                  ldd "$t" 2>/dev/null || true
              done; } | awk '/not found/{print $1}' \
            | grep -vxE 'ntdll\.so|win32u\.so|wow64.*\.so' \
            | sort -u | tr '\n' ' ' ) || true
    if [ -n "$miss" ]; then
        err "$label: installed but NOT runnable - missing amd64 libs: $miss"; RC=1; return
    fi

    local out; out=$("$bin" "${args[@]}" 2>&1 | head -1)
    case "$out" in
        *"could not load"*|*"cannot open shared object"*|*"error while loading"*)
            err "$label: installed but NOT runnable - $out"; RC=1 ;;
        *)  ok "$label: $out" ;;
    esac
}

check_runnable "wine64" /usr/lib/wine/wine64 \
    /lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so \
    /lib/x86_64-linux-gnu/wine/x86_64-unix/win32u.so -- --version
check_runnable "Xvfb  " /usr/bin/Xvfb -- -help

if command -v xauth >/dev/null; then
    ok "xauth: $(command -v xauth)"
else
    err "xauth: NOT bundled in debs/ and unobtainable offline - 'xvfb-run' will not work."
    warn "use the included xauth-free helper instead:  source $DIR/xvfb-env.sh"
    RC=1
fi

if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import qiling" 2>/dev/null; then
    ok "Qiling: $("$VENV/bin/python" -c 'import qiling;print("version",qiling.__version__)')  ($VENV/bin/python)"
    # Importing the package is not enough: each OS backend has its own deps.
    backends=$("$VENV/bin/python" - <<'PY'
import importlib
good, bad = [], []
for name in ("linux", "windows", "macos", "freebsd", "uefi", "dos", "blob"):
    try:
        importlib.import_module(f"qiling.os.{name}.{name}"); good.append(name)
    except Exception as e:
        bad.append(f"{name}({type(e).__name__.replace('ModuleNotFoundError','missing ')}{getattr(e,'name','') or ''})")
print("|".join(good)); print("|".join(bad))
PY
    )
    gb=$(echo "$backends" | sed -n 1p | tr '|' ' ')
    bb=$(echo "$backends" | sed -n 2p | tr '|' ' ')
    [ -n "$gb" ] && ok "  usable backends: $gb"
    if [ -n "$bb" ]; then
        err "  UNUSABLE backends: $bb"
        warn "  the Linux/Windows backends need gevent, whose bundled wheel is cp313-only"
        RC=1
    fi
else
    err "Qiling: import failed"; RC=1
fi

[ -d "$DIR/rootfs" ] && ok "rootfs: $DIR/rootfs" || { err "rootfs: missing"; RC=1; }

say "Summary"
if [ $RC -eq 0 ]; then
    echo "  All components installed and runnable."
else
    echo "  Some components are installed but not runnable on this host."
    echo "  See MISSING_AMD64_DEPS.md for the exact .deb files the bundle lacks."
fi
exit 0
