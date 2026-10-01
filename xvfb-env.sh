#!/bin/bash
# Start a headless X display WITHOUT xauth.
#
# 'xvfb-run' shells out to the xauth binary, which is not bundled in debs/ and
# cannot be fetched offline. Xvfb itself has no such dependency, so we start it
# directly and export DISPLAY. Usage:
#
#     source ./xvfb-env.sh
#     wine64 some.exe
#
# or non-interactively:  ./xvfb-env.sh wine64 some.exe

XVFB_DISPLAY="${XVFB_DISPLAY:-:99}"
XVFB_GEOMETRY="${XVFB_GEOMETRY:-1280x1024x24}"

if ! command -v Xvfb >/dev/null; then
    echo "Xvfb not found - run install.sh first." >&2
    return 1 2>/dev/null || exit 1
fi

if ! xdpyinfo -display "$XVFB_DISPLAY" >/dev/null 2>&1; then
    Xvfb "$XVFB_DISPLAY" -screen 0 "$XVFB_GEOMETRY" -nolisten tcp -noreset >/tmp/xvfb.log 2>&1 &
    XVFB_PID=$!
    export XVFB_PID
    for _ in $(seq 1 50); do
        [ -e "/tmp/.X11-unix/X${XVFB_DISPLAY#:}" ] && break
        sleep 0.1
    done
fi

export DISPLAY="$XVFB_DISPLAY"
echo "DISPLAY=$DISPLAY (Xvfb pid ${XVFB_PID:-already running})"

# If arguments were given, run them under this display.
if [ "$#" -gt 0 ]; then
    "$@"
fi
