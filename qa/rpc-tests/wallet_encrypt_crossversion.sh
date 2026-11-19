#!/bin/sh
# TEST-ONLY. Wallet encryption on-disk compatibility across OpenSSL builds, against real regtest daemons.
# An encrypted wallet.dat made by the OLD build (--old-bin) must open in the NEW build (--bin): wrong
# passphrase refused, right one unlocks, keys/addresses/balances identical, transparent and Sapling
# sends succeed, walletpassphrasechange works, and the wallet then opens in the OLD build under the new
# passphrase. Node 1 (miner, old build) is an unencrypted peer; node 0 is the wallet under test.
#
# usage: sh qa/rpc-tests/wallet_encrypt_crossversion.sh --bin <new bindir> --old-bin <old bindir>
#            --work <empty scratch dir> [--port-base <n>]
set -u
BIN=""; PEER_BIN=""; work=""; BASE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --old-bin) PEER_BIN=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --port-base) BASE=$2; shift 2 ;;
        *) echo "wallet-encrypt-crossversion: unknown argument $1" >&2; exit 2 ;;
    esac
done
for b in "$BIN" "$PEER_BIN"; do
    [ -x "$b/zclassicd" ] && [ -x "$b/zclassic-cli" ] || { echo "usage: wallet_encrypt_crossversion.sh --bin <dir> --old-bin <dir> --work <dir> [--port-base <n>]" >&2; exit 2; }
done
[ -n "$work" ] || { echo "wallet-encrypt-crossversion: --work is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "wallet-encrypt-crossversion: jq is required" >&2; exit 2; }
mkdir -p "$work" || exit 2
SD=$(cd "$work" && pwd)
[ -z "$(ls -A "$SD")" ] || { echo "wallet-encrypt-crossversion: $SD is not empty" >&2; exit 2; }
SCN_LOG=$SD/scn.log; OBS_LOG=$SD/obs.log; SCN_ID=wec
: >"$SCN_LOG"; : >"$OBS_LOG"
here=$(cd "$(dirname "$0")" && pwd)
. "$here/wallet_matrix_lib.sh"
iso_base BASE "$BASE" 112
trap 'stop_all' EXIT INT TERM

P1=correct-horse-1; P2=battery-staple-2
keys() { # node: sorted t keys and sapling keys, one line each
    cli "$1" getaddressesbyaccount "" | jq -r '.[]' | sort | while read -r a; do cli "$1" dumpprivkey "$a"; done | tr '\n' ' '
    cli "$1" z_listaddresses | jq -r '.[]' | sort | while read -r a; do cli "$1" z_exportkey "$a"; done | tr '\n' ' '
}
addrs() { { cli "$1" getaddressesbyaccount "" | jq -r '.[]'; cli "$1" z_listaddresses | jq -r '.[]'; } | sort | tr '\n' ' '; }
state() { printf 'addrs=%s tbal=%s zbal=%s' "$(addrs "$1")" "$(cli "$1" getbalance)" "$(zbal "$1" "$2")"; }
unlock() { cli "$1" walletpassphrase "$2" 600 >/dev/null 2>&1; }

start 1 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 0)) || exit 1
start 0 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 1)) || exit 1
cli 1 generate 112 >/dev/null; sync_to 0

ta=$(give_t 0 10)
za=$(cli 0 z_getnewaddress sapling)
give_z 0 "$za" 5
sync_to 0
ck "old build: wallet unencrypted before encryptwallet" "$(cli 0 getwalletinfo | jq 'has("unlocked_until")')" false
st_plain=$(state 0 "$za"); keys_plain=$(keys 0)
obs plain.state "$st_plain"
ck "old build: shielded balance is 5" "$(zbal 0 "$za")" "5.00000000"

t0=$(now); cli 0 encryptwallet "$P1" >/dev/null 2>&1; t1=$(now)
obs encryptwallet_old_seconds "$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }')"
# encryptwallet shuts the daemon down
pid=$(cat "$SD/node0/pid"); t=0; while kill -0 "$pid" 2>/dev/null && [ $t -lt 120 ]; do t=$((t + 1)); sleep 1; done
kill -0 "$pid" 2>/dev/null && bad "old build did not exit after encryptwallet"

# ---- NEW build opens the OLD-build encrypted wallet -------------------------
say "-- new build opens old-encrypted wallet"
start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) || exit 1
sync_to 0
ck "new build: wallet reports locked" "$(cli 0 getwalletinfo | jq '.unlocked_until')" 0
ckerr "new build: dumpprivkey refused while locked" "locked|passphrase" 0 dumpprivkey "$ta"
ckerr "new build: wrong passphrase refused" "incorrect" 0 walletpassphrase "wrong-pass" 600
ckerr "new build: empty-ish passphrase refused" "incorrect" 0 walletpassphrase "$P1-" 600
t0=$(now); unlock 0 "$P1"; t1=$(now)
obs walletpassphrase_new_seconds "$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }')"
ck "new build: unlocked with the old-build passphrase" "$(cli 0 getwalletinfo | jq '.unlocked_until > 0')" true
ck "new build: addresses and balances identical" "$(state 0 "$za")" "$st_plain"
ck "new build: all transparent and Sapling keys identical" "$(keys 0)" "$keys_plain"

ra=$(cli 1 getnewaddress); rz=$(cli 1 z_getnewaddress sapling)
tx=$(cli 0 sendtoaddress "$ra" 1 2>&1); case $tx in [0-9a-f]*) pass "new build: transparent send $tx" ;; *) bad "transparent send: $tx" ;; esac
wait_mempool 1 "$tx"; mine 1
r=$(zsend 0 "$za" "[{\"address\":\"$rz\",\"amount\":1}]" 1 "$FEE")
case $r in success*) pass "new build: Sapling send ${r#success }"; wait_mempool 1 "${r#success }"; mine 1 ;; *) bad "Sapling send: $r" ;; esac
ck "new build: miner received the shielded 1" "$(zbal 1 "$rz")" "1.00000000"
ck "new build: sender shielded balance fell by 1 + fee" "$(zbal 0 "$za")" "3.99990000"

ckerr "new build: walletpassphrasechange with wrong old passphrase refused" "incorrect" 0 walletpassphrasechange "wrong-pass" "$P2"
cli 0 walletpassphrasechange "$P1" "$P2" >/dev/null 2>&1 && pass "new build: walletpassphrasechange" || bad "walletpassphrasechange failed"
cli 0 walletlock >/dev/null 2>&1
ckerr "new build: old passphrase refused after change" "incorrect" 0 walletpassphrase "$P1" 600
unlock 0 "$P2"
ck "new build: new passphrase unlocks" "$(cli 0 getwalletinfo | jq '.unlocked_until > 0')" true
st_after=$(state 0 "$za"); keys_after=$(keys 0)
ck "new build: keys unchanged after passphrase change" "$keys_after" "$keys_plain"
# Secrets the NEW build encrypts itself under the master key (not only the master key record):
# import a transparent and a Sapling key from the unencrypted miner; the old build must decrypt both.
imp_ta=$(cli 1 getnewaddress); imp_tk=$(cli 1 dumpprivkey "$imp_ta")
imp_za=$(cli 1 z_getnewaddress sapling); imp_zk=$(cli 1 z_exportkey "$imp_za")
[ -n "$imp_tk" ] && [ -n "$imp_zk" ] || bad "new build: miner keys to import are empty"
cli 0 importprivkey "$imp_tk" "" false >/dev/null 2>&1 || bad "new build: importprivkey failed"
cli 0 z_importkey "$imp_zk" no >/dev/null 2>&1 || bad "new build: z_importkey failed"
ck "new build: imported keys stored and exported back" \
    "$(cli 0 dumpprivkey "$imp_ta") $(cli 0 z_exportkey "$imp_za")" "$imp_tk $imp_zk"
st_after=$(state 0 "$za"); keys_imp=$(keys 0)
cli 0 walletlock >/dev/null 2>&1
ckerr "new build: imported transparent key refused while locked" "locked|passphrase" 0 dumpprivkey "$imp_ta"
ckerr "new build: imported Sapling key refused while locked" "locked|passphrase" 0 z_exportkey "$imp_za"
stop 0

# ---- OLD build opens the wallet the NEW build re-encrypted -----------------
say "-- old build opens the wallet again"
start 0 "$PEER_BIN" -connect=127.0.0.1:$((BASE + 1)) || exit 1
sync_to 0
ckerr "old build: previous passphrase refused" "incorrect" 0 walletpassphrase "$P1" 600
t0=$(now); unlock 0 "$P2"; t1=$(now)
obs walletpassphrase_old_seconds "$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }')"
ck "old build: unlocked with the new passphrase" "$(cli 0 getwalletinfo | jq '.unlocked_until > 0')" true
ck "old build: state identical to the new build's" "$(state 0 "$za")" "$st_after"
ck "old build: keys identical (original plus new-build imports)" "$(keys 0)" "$keys_imp"
ck "old build: decrypts the keys the new build encrypted" \
    "$(cli 0 dumpprivkey "$imp_ta") $(cli 0 z_exportkey "$imp_za")" "$imp_tk $imp_zk"
alive "old build" 0
stop 0

fails=$(grep -c '^FAIL' "$SCN_LOG"); passes=$(grep -c '^PASS' "$SCN_LOG")
cat "$OBS_LOG"
say "wallet-encrypt-crossversion: $passes pass, $fails fail"
[ "$fails" -eq 0 ]
