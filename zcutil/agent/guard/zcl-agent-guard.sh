#!/bin/sh
# PreToolUse hook entry: exec the C guard; a fresh clone without the binary allows the call.
d=$(dirname "$0")/../../bin
for b in "$d/zcl-agent-guard" "$d/zcl-agent-guard.exe"; do
    [ -x "$b" ] && exec "$b" "$@"
done
echo "zcl-agent-guard: binary missing, allowing this call; build it with: make -C zcutil" >&2
exit 0
