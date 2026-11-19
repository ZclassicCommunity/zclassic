#!/bin/sh
# PreToolUse hook entry. The guard must never be the reason work stops:
#   - binary missing (fresh clone, not built): allow, with a hint to build it
#   - guard exits 0 (allow) or 2 (refuse): pass that on, stdout and stderr untouched
#   - guard crashed, timed out (it sets a 4 s alarm) or exited any other way: allow, with a note
d=$(dirname "$0")/../../bin
for b in "$d/zcl-agent-guard" "$d/zcl-agent-guard.exe"; do
    [ -x "$b" ] || continue
    "$b" "$@"
    rc=$?
    case $rc in
        0 | 2) exit "$rc" ;;
    esac
    echo "zcl-agent-guard: the guard failed (exit $rc), allowing this call; report it, then rebuild with: make -C zcutil" >&2
    exit 0
done
echo "zcl-agent-guard: binary missing, allowing this call; build it with: make -C zcutil" >&2
exit 0
