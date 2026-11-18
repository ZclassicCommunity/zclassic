#!/bin/sh
# TEST-ONLY. backupwallet is atomic and verified, against a real regtest daemon: the backup
# opens as the same wallet in a fresh datadir; a refused
# overwrite, an unwritable destination and the wallet file itself all fail cleanly, leave the
# old file (or the wallet) untouched and no *.tmp.* behind.
#
# usage: sh qa/rpc-tests/backupwallet_atomic.sh --bin <dir with zclassicd, zclassic-cli>
#            --work <empty scratch dir> [--port-base <n>]
set -u
bin=""; work=""; base=51100
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        *) echo "backupwallet-atomic: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -x "$bin/zclassic-cli" ] && [ -n "$work" ] || {
    echo "usage: backupwallet_atomic.sh --bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "backupwallet-atomic: $work is not empty" >&2; exit 2; }

dd=$work/node
mkdir -p "$dd" "$work/ro"
printf 'rpcuser=bw
rpcpassword=bw%s
rpcport=%s
' "$$" "$((base + 1))" >"$dd/zclassic.conf"
cp "$dd/zclassic.conf" "$work/restored.conf"
cli() { "$bin/zclassic-cli" -regtest -datadir="$dd" "$@"; }
failures=0
ok() { echo "backupwallet-atomic: PASS $*"; }
bad() { echo "backupwallet-atomic: FAIL $*"; failures=$((failures + 1)); }
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
ntmp() { find "$1" -name "*.tmp.*" | wc -l | tr -d " "; }
wallet_state() { # echo addresses + tx count of the node cli points at
    { cli getaddressesbyaccount "" | tr -d " \n[]\"" | tr "," "\n" | sort; cli z_listaddresses | tr -d " \n[]\"" | tr "," "\n" | sort
      cli getwalletinfo | grep -E "\"(txcount|balance)\""; }
}

export_dir=$work/export
mkdir -p "$export_dir"
start -exportdir="$export_dir" || { echo "backupwallet-atomic: node did not start"; exit 1; }
cli getnewaddress >/dev/null 2>&1; cli z_getnewaddress >/dev/null 2>&1
cli generate 1 >/dev/null 2>&1

# 1. new file, no temporary left (byte identity is covered by the BackupWalletTest gtest: a node rewrites wallet.dat on shutdown)
out=$(cli backupwallet first.dat 2>&1)
[ "$out" = "$export_dir/first.dat" ] && ok "backupwallet returned $out" || bad "backupwallet returned: $out"
[ "$(ntmp "$export_dir")" = 0 ] && ok "no temporary file after success" || bad "temporary file left after success"
wallet_state >"$work/state.orig"
[ -s "$work/state.orig" ] && ok "captured wallet state ($(wc -l <"$work/state.orig") lines)" || bad "empty wallet state"
stop

# 2. the backup opens as the same wallet in a fresh datadir
rd=$work/restored
mkdir -p "$rd/regtest"
cp "$work/restored.conf" "$rd/zclassic.conf"
cp "$export_dir/first.dat" "$rd/regtest/wallet.dat"
od=$dd; dd=$rd
start -port=$((base + 2)) -rpcport=$((base + 1)) || { echo "backupwallet-atomic: restored node did not start"; exit 1; }
wallet_state >"$work/state.restored"
stop
dd=$od
cmp -s "$work/state.orig" "$work/state.restored" && ok "restored wallet has the same addresses, tx count and balance" || { bad "restored wallet differs"; diff "$work/state.orig" "$work/state.restored"; }

# 3. existing backup is refused and left intact; unwritable destination fails clean
start -exportdir="$export_dir" || { echo "backupwallet-atomic: node did not restart"; exit 1; }
before=$(sha256sum "$export_dir/first.dat" | cut -d" " -f1)
out=$(cli backupwallet first.dat 2>&1)
case "$out" in *"Cannot overwrite"*) ok "existing backup refused" ;; *) bad "existing backup answered: $out" ;; esac
[ "$(sha256sum "$export_dir/first.dat" | cut -d" " -f1)" = "$before" ] && ok "existing backup untouched" || bad "existing backup changed"
stop

chmod 500 "$work/ro"
if [ -w "$work/ro" ]; then
    chmod 700 "$work/ro"; echo "backupwallet-atomic: SKIP read-only destination (permissions not enforced for this user)"
else
    start -exportdir="$work/ro" || { echo "backupwallet-atomic: node did not restart (2)"; exit 1; }
    out=$(cli backupwallet ro.dat 2>&1)
    case "$out" in *"backup failed"*) ok "read-only directory: $out" ;; *) bad "read-only directory answered: $out" ;; esac
    [ ! -e "$work/ro/ro.dat" ] && [ "$(ntmp "$work/ro")" = 0 ] && ok "nothing left in the read-only directory" || bad "file left in the read-only directory"
    stop
    chmod 700 "$work/ro"
fi

# 4. the wallet file itself is refused and unharmed
start -exportdir="$dd/regtest" || { echo "backupwallet-atomic: node did not restart (3)"; exit 1; }
out=$(cli backupwallet wallet.dat 2>&1)
case "$out" in *"Cannot overwrite"*) ok "backupwallet wallet.dat refused" ;; *) bad "backupwallet wallet.dat answered: $out" ;; esac
wallet_state >"$work/state.after"
cmp -s "$work/state.orig" "$work/state.after" && ok "wallet unharmed" || bad "wallet changed after refused backup"
[ "$(ntmp "$dd/regtest")" = 0 ] && ok "no temporary beside the wallet" || bad "temporary left beside the wallet"
stop

if [ $failures -eq 0 ]; then echo "backupwallet-atomic: ALL PASSED"; exit 0; fi
echo "backupwallet-atomic: $failures FAILURE(S)"
exit 1
