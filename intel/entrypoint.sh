#!/bin/sh
# Runs the VirusTotal lookup loop, and the payload fetcher alongside it when it
# is enabled.
#
# The fetcher is backgrounded and vt.py stays in the foreground as PID 1's
# child, so container health still tracks the component that always runs. If
# the fetcher is disabled it prints why and exits within a second, which is the
# intended default and not an error.
set -eu

if [ "${FETCH_ENABLED:-false}" = "true" ]; then
    echo "[entrypoint] payload fetcher enabled" >&2
    python3 -u /app/fetcher.py &
fi

exec python3 -u /app/vt.py
