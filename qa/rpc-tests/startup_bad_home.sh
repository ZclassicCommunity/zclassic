#!/bin/sh
# TEST-ONLY. A HOME that cannot hold the default data directory (unset, a file, read-only) makes zclassicd
# refuse to start with a clear error and exit status 1: no assertion failure / abort (status 134 on Linux).
# On macOS the default directory is ~/Library/Application Support/ZClassic, so the same cases cover a HOME
# without that directory.
#
# usage: sh qa/rpc-tests/startup_bad_home.sh <dir with zclassicd>
set -u
bin=${1:-}
[ -x "$bin/zclassicd" ] || { echo "usage: startup_bad_home.sh <dir with zclassicd>" >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/startup_bad_home.XXXXXX") || exit 2
trap "chmod -R u+rwx \"$work\"; rm -rf \"$work\"" EXIT INT TERM
mkdir "$work/ro" && chmod 555 "$work/ro"
failures=0
check() { # <label> <command...>
    label=$1; shift
    "$@" >"$work/out" 2>&1 </dev/null
    rc=$?
    if [ "$rc" -eq 1 ] && grep -q '^Error: ' "$work/out" && ! grep -qi 'assert' "$work/out"; then
        echo "startup_bad_home: PASS $label ($(head -1 "$work/out"))"
    else
        echo "startup_bad_home: FAIL $label rc=$rc"; sed 's/^/  /' "$work/out"; failures=$((failures + 1))
    fi
}
: >"$work/afile"
check "HOME is a file" env HOME="$work/afile" "$bin/zclassicd" -regtest
check "HOME unset" env -u HOME "$bin/zclassicd" -regtest
# a read-only HOME only fails for a user that is not root (root writes anywhere)
if [ "$(id -u)" -ne 0 ]; then
    check "HOME read-only" env HOME="$work/ro" "$bin/zclassicd" -regtest
fi
[ "$failures" -eq 0 ]
