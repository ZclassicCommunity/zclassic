#!/bin/sh
# TEST-ONLY. backupwallet / dumpwallet / z_exportwallet against a real regtest daemon:
# with no -exportdir they use <datadir>/regtest/backups, accept '.', '-' and '_' in the
# file name, refuse anything that could leave the directory, and an explicit -exportdir
# still wins.
#
# usage: sh qa/rpc-tests/backupwallet_default_dir.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "backupwallet-test: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: backupwallet_default_dir.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
. "$(dirname "$0")/../lib/isolation.sh"
iso_base base "$base" 16
[ -z "$(ls -A "$work")" ] || { echo "backupwallet-test: $work is not empty" >&2; exit 2; }

dd=$work/node
mkdir -p "$dd"
printf 'rpcuser=bw\nrpcpassword=bw%s\nrpcport=%s\n' "$$" "$((base + 1))" >"$dd/zclassic.conf"
cli() { "$bin/zclassic-cli" -regtest -datadir="$dd" "$@"; }
failures=0
ok() { echo "backupwallet-test: PASS $*"; }
bad() { echo "backupwallet-test: FAIL $*"; failures=$((failures + 1)); }
fsize() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; } # GNU stat, else BSD/macOS stat
start() { # [extra args]
    "$bin/zclassicd" -regtest -dnsseed=0 -upnp=0 -listenonion=0 -discover=0 -bind=127.0.0.1 -rpcbind=127.0.0.1 \
        -rpcallowip=127.0.0.1 -debuglogfile=1 -printtoconsole=0 -showmetrics=0 -bootstrap=0 \
        -datadir="$dd" -port=$base -listen=0 -connect=0 "$@" -daemon >/dev/null 2>&1 || return 1
    i=0
    while [ $i -lt 120 ]; do cli getblockcount >/dev/null 2>&1 && return 0; sleep 1; i=$((i + 1)); done
    return 1
}
stop() {
    cli stop >/dev/null 2>&1
    i=0
    while [ $i -lt 60 ] && [ -f "$dd/regtest/zclassicd.pid" ]; do sleep 1; i=$((i + 1)); done
}

start || { echo "backupwallet-test: node did not start"; exit 1; }
backups=$dd/regtest/backups
[ ! -e "$backups" ] && ok "no backups directory before first use" || bad "backups directory existed before first use"

# default directory, name with '.', '-' and '_'
out=$(cli backupwallet wallet-backup_1.dat 2>&1)
[ "$out" = "$backups/wallet-backup_1.dat" ] && ok "backupwallet returned $out" || bad "backupwallet returned: $out"
[ -s "$backups/wallet-backup_1.dat" ] && ok "backup file exists and is not empty" || bad "backup file missing or empty"
bsz=$(fsize "$backups/wallet-backup_1.dat"); wsz=$(fsize "$dd/regtest/wallet.dat")
[ "$bsz" -ge 1024 ] && [ "$bsz" -le $((wsz * 2)) ] && ok "backup is a plausible wallet copy ($bsz bytes, wallet.dat $wsz)" || bad "backup size $bsz vs wallet.dat $wsz"

# dumpwallet / z_exportwallet use the same directory and name rules
cli dumpwallet dump-1.txt >/dev/null 2>&1 && [ -s "$backups/dump-1.txt" ] && ok "dumpwallet wrote into the default directory" || bad "dumpwallet"
cli z_exportwallet zexport_1.txt >/dev/null 2>&1 && [ -s "$backups/zexport_1.txt" ] && ok "z_exportwallet wrote into the default directory" || bad "z_exportwallet"
out=$(cli dumpwallet dump-1.txt 2>&1)
case "$out" in *"Cannot overwrite"*) ok "dumpwallet still refuses to overwrite" ;; *) bad "dumpwallet overwrote: $out" ;; esac

# nothing that can leave the directory, no hidden or option-like names
for name in '../escape.dat' 'sub/dir.dat' '.hidden' '..' '-rf' 'a b' 'nul' 'x*'; do
    for rpc in backupwallet dumpwallet z_exportwallet; do
        out=$(cli "$rpc" "$name" 2>&1)
        case "$out" in *"Filename is invalid"*) ;; *) bad "$rpc accepted or mis-reported '$name': $out" ;; esac
    done
done
[ ! -e "$dd/regtest/escape.dat" ] && [ ! -e "$dd/escape.dat" ] && [ ! -e "$backups/dir.dat" ] && ok "rejected names created nothing" || bad "a rejected name created a file"
out=$(cli backupwallet '../escape.dat' 2>&1)
case "$out" in *"Try 'escape.dat' instead"*) ok "the error suggests a valid name" ;; *) bad "no suggestion in: $out" ;; esac

# an explicit -exportdir still wins
stop
start -exportdir="$work/elsewhere" || { echo "backupwallet-test: node did not restart (2)"; exit 1; }
out=$(cli backupwallet explicit.dat 2>&1)
[ "$out" = "$work/elsewhere/explicit.dat" ] && [ -s "$work/elsewhere/explicit.dat" ] && ok "explicit -exportdir used: $out" || bad "explicit -exportdir: $out"
[ ! -e "$backups/explicit.dat" ] && ok "default directory untouched when -exportdir is given" || bad "wrote into the default directory despite -exportdir"
out=$(cli backupwallet explicit.dat 2>&1)
case "$out" in *"Cannot overwrite"*) ok "backupwallet refuses to replace an existing backup" ;; *) bad "backupwallet replaced an existing file: $out" ;; esac
stop

# -exportdir may be the directory that holds wallet.dat: the live wallet and the
# node's other files must never be a destination (copy_file would truncate them)
start -exportdir="$dd/regtest" || { echo "backupwallet-test: node did not restart (3)"; exit 1; }
wsz=$(fsize "$dd/regtest/wallet.dat")
for victim in wallet.dat peers.dat; do
    [ -e "$dd/regtest/$victim" ] || continue
    vsz=$(fsize "$dd/regtest/$victim")
    out=$(cli backupwallet "$victim" 2>&1)
    case "$out" in *"Cannot overwrite"*) ok "backupwallet $victim refused: $out" ;; *) bad "backupwallet $victim answered: $out" ;; esac
    [ "$(fsize "$dd/regtest/$victim")" = "$vsz" ] && ok "$victim keeps its size ($vsz bytes)" || bad "$victim changed size"
done
[ "$(fsize "$dd/regtest/wallet.dat")" -ge $((wsz / 2)) ] && ok "wallet.dat intact" || bad "wallet.dat was truncated"
cli getbalance >/dev/null 2>&1 && ok "wallet still answers" || bad "wallet no longer answers"
stop

if [ $failures -eq 0 ]; then echo "backupwallet-test: ALL PASSED"; exit 0; fi
echo "backupwallet-test: $failures FAILURE(S)"
exit 1
