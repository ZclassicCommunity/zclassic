#!/bin/sh
# A second zclassicd on a locked data directory must say who holds it.
#
# Node A runs on a datadir. Node B started on the same datadir must exit non-zero with
# "Cannot obtain a lock on data directory <dir>." followed by "ZClassic is already running as pid
# <A's pid>.", and must leave A's pid file in place (it used to delete it on the way out, so a third
# launch could no longer name the holder). A pid file naming a dead process gives the "lock is held
# but pid N is not running" text, and an unopenable lock file is reported as such, without the
# "already running" guess.
#
# usage: datadir_lock_message.sh --bin <dir> --work <dir> [--base port]
# Needs the Zcash parameters in ~/.zcash-params. Shell only, no Python.
B=""; W=""; P=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) B=$2; shift 2 ;; --work) W=$2; shift 2 ;; --base) P=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$B/zclassicd" ] && [ -n "$W" ] || { echo "usage: $0 --bin DIR --work DIR [--base port]" >&2; exit 2; }
P=${P:-$((20000 + ($$ % 20000)))}; R=0; F=0
rm -rf "$W"; mkdir -p "$W/d" "$W/e"; W=$(cd "$W" && pwd); D=$W/d; N=$D/regtest
trap '[ -f "$W/pid" ] && kill -9 "$(cat "$W/pid")" 2>/dev/null; chmod 600 "$W/e/regtest/.lock" 2>/dev/null' EXIT
printf "rpcuser=u\nrpcpassword=p\n" > "$D/zclassic.conf"; cp "$D/zclassic.conf" "$W/e/"
A0="-regtest -server=1 -listen=0 -showmetrics=0 -keypool=5 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -dnsseed=0 -discover=0 -listenonion=0"
cli() { "$B/zclassic-cli" -regtest -datadir="$D" -rpcport=$P -rpcuser=u -rpcpassword=p "$@"; }
ok() { echo "ok   $1"; R=$((R + 1)); }
no() { echo "FAIL $1"; F=$((F + 1)); }

"$B/zclassicd" $A0 -datadir="$D" -rpcport=$P > "$W/a.log" 2>&1 & echo $! > "$W/pid"; A=$(cat "$W/pid")
for k in $(seq 600); do cli getblockcount >/dev/null 2>&1 && break; kill -0 "$A" 2>/dev/null || break; sleep 0.1; done
cli getblockcount >/dev/null 2>&1 || { echo "node A did not start: $(tail -3 "$W/a.log")"; exit 1; }
PIDFILE=$N/zclassicd.pid
[ "$(cat "$PIDFILE" 2>/dev/null)" = "$A" ] || no "A's pid file does not hold $A"

# second <label> <expected text>: start B on A's datadir, expect a non-zero exit and the text
second() {
    "$B/zclassicd" $A0 -datadir="$D" -rpcport=$((P + 1)) > "$W/b.log" 2>&1; rc=$?
    if [ $rc != 0 ] && grep -qF "Cannot obtain a lock on data directory $N. $2" "$W/b.log"; then ok "$1: exit $rc, \"$2\""
    else no "$1: exit $rc, wanted \"$2\", got: $(grep -m1 -i 'lock' "$W/b.log")"; fi
}
second "second launch" "ZClassic is already running as pid $A."
[ "$(cat "$PIDFILE" 2>/dev/null)" = "$A" ] && ok "A's pid file kept after the refused launch" || no "A's pid file removed or changed by the refused launch"
second "third launch" "ZClassic is already running as pid $A."
kill -0 "$A" 2>/dev/null && [ "$(cli getblockcount)" = 0 ] && ok "A still serving" || no "A disturbed by the refused launches"

# A pid file that names a process that is gone
DEAD=$(sh -c 'echo $$'); while kill -0 "$DEAD" 2>/dev/null; do DEAD=$((DEAD + 7919)); done
cp "$PIDFILE" "$W/pid.keep"; echo "$DEAD" > "$PIDFILE"
second "pid file names a dead process" "The lock is held but pid $DEAD is not running"
echo "garbage" > "$PIDFILE"
second "unreadable pid file" "ZClassic is probably already running (pid unknown)."
cp "$W/pid.keep" "$PIDFILE"

# A lock file that cannot be opened (skip as root, which ignores the mode)
if [ "$(id -u)" != 0 ]; then
    mkdir -p "$W/e/regtest"; : > "$W/e/regtest/.lock"; chmod 000 "$W/e/regtest/.lock"
    "$B/zclassicd" $A0 -datadir="$W/e" -rpcport=$((P + 2)) > "$W/c.log" 2>&1; rc=$?
    if [ $rc != 0 ] && grep -qF "Cannot obtain a lock on data directory $W/e/regtest. Cannot create or open lock file" "$W/c.log" \
        && ! grep -q "already running" "$W/c.log"; then ok "unopenable lock file: exit $rc, reported without 'already running'"
    else no "unopenable lock file: exit $rc, got: $(grep -m1 -i 'lock' "$W/c.log")"; fi
    chmod 600 "$W/e/regtest/.lock"
fi

cli stop >/dev/null 2>&1; while kill -0 "$A" 2>/dev/null; do sleep 0.2; done
[ ! -e "$PIDFILE" ] && ok "A removed its own pid file on stop" || no "A's pid file left after stop"
echo "datadir-lock-message: $R ok, $F fail"
[ "$F" = 0 ] && [ "$R" -gt 0 ]
