#!/bin/sh
# Platform transaction checks for zclassicd on regtest (macOS and Linux), exact balance assertions.
# Reuses the wallet_matrix.sh harness (helpers, PASS/FAIL accounting, observations).
#
# usage: wallet_platform_checks.sh --bin <dir> --work <dir> [--peer-bin <dir>] [--only a,b,..] [--base port]
#   env PT_LIST="1 4 0" prover-thread settings for the timing check (0 = default)
#   checks: timing   z_sendmany of 1/5/20/40 notes to 1 and 10 recipients at -proverthreads=1,4,default
#                    (wall time and peak RSS of the wallet node in <work>/timings.txt)
#           concurrent  two z_sendmany in flight at once from different addresses
#           merge    z_mergetoaddress of 100 notes
#           kill     kill -9 during proving, right after acceptance, and during generate
#           paths    datadir with spaces and accented / CJK names (NFC and NFD forms):
#                    backupwallet, z_exportwallet, dumpwallet, restart, importwallet
#           encrypt  encrypted wallet: lock/unlock, multi-note spend, kill -9, passphrase change
#           interop  >=20 varied shielded transactions (Sprout, Sapling, multi-note, memo, merge,
#                    shield coinbase); raw hex written to <work>/s*/interop_rawtx.txt, chain kept
#                    in <work>/sinterop/node1/regtest for replay on another node
# Needs jq and the Zcash parameters. POSIX sh; no Python.
BIN=""; WORK=""; PEER_BIN=""; ONLY=""; PORT_BASE=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin) BIN=$2; shift 2 ;; --work) WORK=$2; shift 2 ;; --peer-bin) PEER_BIN=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;; --base) PORT_BASE=$2; shift 2 ;; *) echo "bad arg $1" >&2; exit 2 ;;
    esac
done
[ -x "$BIN/zclassicd" ] && [ -n "$WORK" ] || { echo "usage: $0 --bin DIR --work DIR [--peer-bin DIR] [--only a,b]" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
PEER_BIN=${PEER_BIN:-$BIN}; ALT_BIN=$BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/wallet_matrix_lib.sh"
for f in "$HERE"/wallet_matrix_scn?.sh; do . "$f"; done
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS=$WORK/results.txt; OBS_LOG=$WORK/obs.txt; : >"$RESULTS"; : >"$OBS_LOG"; : >"$WORK/timings.txt"
BASE=${PORT_BASE:-$((20000 + ($$ % 20000)))}
trap 'stop_all' EXIT

# pid of node <n>'s daemon; rss_start/rss_stop bracket a peak-RSS (KiB) sample of it
rss_start() { RSS_FILE=$SD/rss.$1; rm -f "$RSS_FILE.stop"
    ( pid=$(cat "$SD/node$1/pid"); while [ ! -e "$RSS_FILE.stop" ] && kill -0 "$pid" 2>/dev/null; do ps -o rss= -p "$pid"; sleep 0.2; done |
        awk 'BEGIN { m = 0 } { if ($1 + 0 > m) m = $1 + 0 } END { print m }' >"$RSS_FILE" ) &
    RSS_PID=$!; }
rss_stop() { touch "$RSS_FILE.stop"; wait "$RSS_PID" 2>/dev/null; }   # then read $RSS_FILE (not in a subshell: wait needs the parent)

# fund_notes <node> <zaddr> <count> <amount>: <count> separate Sapling notes of <amount> on <zaddr>
# (miner makes <count> t addresses, then <count> concurrent t->z z_sendmany operations)
fund_notes() {
    local n=$1 zs=$2 cnt=$3 amt=$4 addrs json ops ta op r
    cli 1 generate 3 >/dev/null
    addrs=$(for i in $(seq 1 "$cnt"); do cli 1 getnewaddress; done)
    json=$(printf '%s\n' "$addrs" | jq -Rsc --argjson a "$(add "$amt" 0.001)" 'split("\n")[:-1]|map({key:.,value:$a})|from_entries')
    cli 1 sendmany "" "$json" >/dev/null; cli 1 generate 1 >/dev/null
    ops=""; for ta in $addrs; do op=$(cli 1 z_sendmany "$ta" "[{\"address\":\"$zs\",\"amount\":$amt}]" 1 0.001); ops="$ops $op"; done
    for op in $ops; do r=$(wait_op 1 "$op"); case $r in success*) ;; *) bad "fund_notes: $r" ;; esac; done
    cli 1 generate 1 >/dev/null; sync_to "$n"
}
nnotes() { cli "$1" z_listunspent 1 9999999 false "[\"$2\"]" | jq length; }
# recips of <count> fresh node-1 z addresses of <amount> each
zrecips() { for k in $(seq 1 "$1"); do cli 1 z_getnewaddress; done | jq -Rsc --argjson amt "$2" 'split("\n")[:-1]|map({address:.,amount:$amt})'; }
restart0() { stop 0; start 0 "$BIN" -connect=127.0.0.1:$((BASE + 1)) "$@"; }
tobs() { echo "$SCN_ID.$1 = $2" >>"$WORK/timings.txt"; say "  time $1 = $2"; }

# ------------------------------------------------------------------ timing
chk_timing() {
    setup2 || return
    for pt in ${PT_LIST:-1 4 0}; do
        restart0 -proverthreads=$pt || return
        for N in 1 5 20 40; do for R in 1 10; do
            zs=$(cli 0 z_getnewaddress); cli 1 generate 30 >/dev/null; sync_to 0
            fund_notes 0 "$zs" "$N" 1
            ck "pt=$pt N=$N R=$R: notes funded" "$(nnotes 0 "$zs")" "$N"
            total=$(add "$N" -0.5); per=$(awk -v t="$total" -v r="$R" 'BEGIN { printf "%.8f", t / r }')
            rec=$(zrecips "$R" "$per")
            rss_start 0; t0=$(now)
            r=$(zsend 0 "$zs" "$rec" 1 "$FEE"); t=$(elapsed "$t0"); rss_stop; rss=$(cat "$RSS_FILE")
            case $r in
                success*) tobs "pt${pt}_notes${N}_recips${R}" "${t}s peak_rss_kb=$rss"
                    wait_mempool 1 "${r#success }"; mine 1
                    ck "pt=$pt N=$N R=$R: change balance" "$(zbal 0 "$zs")" "$(add "$N" -"$total" -$FEE)"
                    ck "pt=$pt N=$N R=$R: recipients exact" "$(printf %s "$rec" | jq -r '.[].address' | while read -r a; do zbal 1 "$a"; done | sort -u)" "$(n8 "$per")" ;;
                *) bad "pt=$pt N=$N R=$R: z_sendmany: $r" ;;
            esac
        done; done
    done
    alive timing
}

# -------------------------------------------------------------- concurrent
chk_concurrent() {
    setup2 || return
    za=$(cli 0 z_getnewaddress); zb=$(cli 0 z_getnewaddress); cli 1 generate 20 >/dev/null; sync_to 0
    fund_notes 0 "$za" 10 1; fund_notes 0 "$zb" 10 1
    ra=$(zrecips 3 3); rb=$(zrecips 3 3)
    t0=$(now)
    oa=$(cli 0 z_sendmany "$za" "$ra" 1 "$FEE"); ob=$(cli 0 z_sendmany "$zb" "$rb" 1 "$FEE")
    sa=$(wait_op 0 "$oa"); sb=$(wait_op 0 "$ob"); tobs "two_concurrent_z_sendmany_10_notes_each" "$(elapsed "$t0")s"
    case $sa in success*) wait_mempool 1 "${sa#success }" ;; *) bad "concurrent A: $sa" ;; esac
    case $sb in success*) wait_mempool 1 "${sb#success }" ;; *) bad "concurrent B: $sb" ;; esac
    mine 1
    ck "concurrent A change" "$(zbal 0 "$za")" "$(add 10 -9 -$FEE)"; ck "concurrent B change" "$(zbal 0 "$zb")" "$(add 10 -9 -$FEE)"
    ck "concurrent A recipients" "$(printf %s "$ra" | jq -r '.[].address' | while read -r a; do zbal 1 "$a"; done | sort -u)" 3.00000000
    ck "concurrent B recipients" "$(printf %s "$rb" | jq -r '.[].address' | while read -r a; do zbal 1 "$a"; done | sort -u)" 3.00000000
    alive concurrent
}

# ------------------------------------------------------------------- merge
chk_merge() {
    setup2 || return
    zs=$(cli 0 z_getnewaddress); zd=$(cli 0 z_getnewaddress); cli 1 generate 60 >/dev/null; sync_to 0
    fund_notes 0 "$zs" 100 1
    ck "100 notes funded" "$(nnotes 0 "$zs")" 100
    t0=$(now); rss_start 0
    mg=$(cli 0 z_mergetoaddress "[\"$zs\"]" "$zd" 0.0001 0 100); op=$(printf %s "$mg" | jq -r .opid)
    ck "merge: remaining notes reported" "$(printf %s "$mg" | jq -r .remainingNotes)" 0
    r=$(wait_op 0 "$op"); t=$(elapsed "$t0"); rss_stop; rss=$(cat "$RSS_FILE")
    tobs "z_mergetoaddress_100_notes" "${t}s peak_rss_kb=$rss"
    case $r in success*) wait_mempool 1 "${r#success }"; mine 1
        ck "merge: destination exact" "$(zbal 0 "$zd")" "$(add 100 -0.0001)"; ck "merge: source empty" "$(zbal 0 "$zs")" 0.00000000
        ck "merge: one note" "$(nnotes 0 "$zd")" 1 ;;
        *) bad "merge: $r" ;;
    esac
    alive merge
}

# -------------------------------------------------------------------- kill
chk_kill() {
    setup2 || return
    R="-connect=127.0.0.1:$((BASE + 1))"; zs=$(cli 0 z_getnewaddress); cli 1 generate 30 >/dev/null; sync_to 0
    fund_notes 0 "$zs" 20 1
    rec=$(zrecips 1 19.5)
    # (a) kill -9 while the proof is being built
    op=$(cli 0 z_sendmany "$zs" "$rec" 1 "$FEE"); sleep 1; kill9 0; start 0 "$BIN" $R
    ck "kill during proving: notes intact" "$(zbal 0 "$zs")" 20.00000000
    ck "kill during proving: nothing in miner mempool" "$(cli 1 getrawmempool | jq length)" 0
    r=$(zsend 0 "$zs" "$rec" 1 "$FEE"); case $r in success*) wait_mempool 1 "${r#success }"; mine 1 ;; *) bad "kill during proving: respend: $r" ;; esac
    ck "kill during proving: respend exact" "$(zbal 0 "$zs")" "$(add 20 -19.5 -$FEE)"
    # (b) kill -9 right after acceptance (z_sendmany reported success), before it is mined
    fund_notes 0 "$zs" 5 1; b0=$(zbal 0 "$zs"); rec=$(zrecips 1 4.5)
    r=$(zsend 0 "$zs" "$rec" 1 "$FEE"); kill9 0; start 0 "$BIN" $R
    case $r in success*)
        w=0; until cli 1 getrawmempool | grep -q "${r#success }" || [ $w -ge 120 ]; do sleep 1; w=$((w + 1)); done
        obs "kill_after_accept_relayed_after_s" "$w"
        cli 1 getrawmempool | grep -q "${r#success }" && pass "kill after acceptance: tx reached the miner" || bad "kill after acceptance: tx not relayed within 120s"
        mine 1
        w=0; until [ "$(zbal 0 "$zs")" = "$(add "$b0" -4.5 -$FEE)" ] || [ $w -ge 60 ]; do sleep 1; w=$((w + 1)); done
        ck "kill after acceptance: exact balance" "$(zbal 0 "$zs")" "$(add "$b0" -4.5 -$FEE)" ;;
        *) bad "kill after acceptance: $r" ;;
    esac
    # (c) kill -9 during generate on the subject node
    s0=$(cli 0 getblockcount); ( cli 0 generate 400 >/dev/null 2>&1 ) & gp=$!; sleep 1; kill9 0; wait $gp
    start 0 "$BIN" $R; h=$(cli 0 getblockcount)
    obs "kill_during_generate_height_gain" "$((h - s0))"
    ck "kill during generate: verifychain" "$(cli 0 verifychain 4 0)" true
    # the restarted node keeps importing blocks from disk after RPC is up: compare both tips afresh until they agree
    w=0; until [ "$(cli 0 getbestblockhash)" = "$(cli 1 getbestblockhash)" ] || [ $w -ge 240 ]; do sleep 1; w=$((w + 1)); done; obs "kill_during_generate_converged_after_s" "$w"
    ck "kill during generate: same tip as peer" "$(cli 0 getbestblockhash)" "$(cli 1 getbestblockhash)"
    ck "kill during generate: wallet balance = spendable coins" "$(bal 0)" "$(cli 0 listunspent 1 | jq -r '[.[].amount]|add // 0' | f8)"
    ck "kill during generate: note balance survived" "$(zbal 0 "$zs")" "$(add "$b0" -4.5 -$FEE)"
    alive kill
}

# ------------------------------------------------------------------- paths
paths_flow() { # <label>: the whole flow with $SD already set to the odd path
    local zs ta s0 b
    setup2 || return
    R="-connect=127.0.0.1:$((BASE + 1))"
    zs=$(cli 0 z_getnewaddress); ta=$(give_t 0 3); give_z 0 "$zs" 2 4d656d6f
    s0=$(snap 0); ck "$1: funded" "$(zbal 0 "$zs")" 2.00000000
    b=backupfile   # file names must be alphanumeric (SanitizeFilename); the path under test is the -exportdir path
    cli 0 backupwallet "$b" >/dev/null; ls -l "$SD/export/" | sed 's/^/    /' >>"$SD/ls.txt"
    ck "$1: backup file exists" "$([ -s "$SD/export/$b" ] && echo yes)" yes
    cli 0 z_exportwallet "zexport" >/dev/null; ck "$1: z_exportwallet file has the key" "$(grep -c "$(cli 0 z_exportkey "$zs")" "$SD/export/zexport")" 1
    cli 0 dumpwallet "dumpfile" >/dev/null; ck "$1: dumpwallet file" "$([ -s "$SD/export/dumpfile" ] && echo yes)" yes
    stop 0; start 0 "$BIN" $R; sync_to 0
    ck "$1: restart identical" "$(snap 0)" "$s0"
    stop 0; start 0 "$BIN" $R -rescan; sync_to 0
    ck "$1: -rescan identical (no txs line)" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s0" | sed 's/txs=.*//')"
    fresh 2 -rescan || return
    cli 2 importwallet "$SD/export/dumpfile" >/dev/null; cli 2 z_importwallet "$SD/export/zexport" >/dev/null
    ck "$1: import into a fresh node: t" "$(bal 2)" 3.00000000
    ck "$1: import into a fresh node: z" "$(zbal 2 "$zs")" 2.00000000
    ck "$1: spend after the round trip" "$(zsend 0 "$zs" "[{\"address\":\"$(cli 1 getnewaddress)\",\"amount\":1}]" | cut -c1-7)" success
    alive "$1"
}
chk_paths() {
    local nfc nfd
    nfc=$(printf 'd\303\244t\303\244 n\303\266m \303\251 \345\220\215 spaced')          # precomposed (NFC)
    nfd=$(printf 'dat\303\251 cafe\314\201 u\314\210 n\314\203 \345\220\215 spaced')   # decomposed (NFD) accents
    SD_ROOT=$SD
    SD="$SD_ROOT/$nfc"; mkdir -p "$SD"; paths_flow "NFC path"; stop_all
    SD="$SD_ROOT/$nfd"; mkdir -p "$SD"; BASE=$((BASE + 7)); paths_flow "NFD path"; stop_all
    SD=$SD_ROOT
}

# ----------------------------------------------------------------- encrypt
chk_encrypt() {
    setup2 || return
    R="-connect=127.0.0.1:$((BASE + 1))"; zs=$(cli 0 z_getnewaddress); ta=$(give_t 0 2); cli 1 generate 20 >/dev/null; sync_to 0
    fund_notes 0 "$zs" 6 1; s0=$(snap 0); d=$(cli 1 z_getnewaddress); dt=$(cli 1 getnewaddress)
    cli 0 encryptwallet pw1 >/dev/null 2>&1
    w=0; while kill -0 "$(cat "$SD/node0/pid")" 2>/dev/null && [ $w -lt 60 ]; do sleep 1; w=$((w + 1)); done
    start 0 "$BIN" $R; sync_to 0
    ck "encrypt: balances identical after encryption" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s0" | sed 's/txs=.*//')"
    r=$(zsend 0 "$zs" "[{\"address\":\"$d\",\"amount\":1}]"); printf %s "$r" | grep -Eqi 'passphrase|locked|unlock' && pass "encrypt: locked wallet refuses z_sendmany" || bad "encrypt: locked wallet z_sendmany: $r"
    ckerr "encrypt: locked wallet refuses z_getnewaddress" 'passphrase|locked|unlock' 0 z_getnewaddress
    ckerr "encrypt: wrong passphrase" 'incorrect|passphrase' 0 walletpassphrase wrong 60
    cli 0 walletpassphrase pw1 600 >/dev/null
    r=$(zsend 0 "$zs" "[{\"address\":\"$d\",\"amount\":4.5},{\"address\":\"$dt\",\"amount\":0.4}]" 1 "$FEE")
    case $r in success*) wait_mempool 1 "${r#success }"; mine 1 ;; *) bad "encrypt: unlocked multi-note spend: $r" ;; esac
    ck "encrypt: change exact" "$(zbal 0 "$zs")" "$(add 6 -4.9 -$FEE)"; ck "encrypt: recipient exact" "$(zbal 1 "$d")" 4.50000000
    cli 0 walletlock; ckerr "encrypt: locked again" 'passphrase|locked|unlock' 0 z_getnewaddress
    cli 0 walletpassphrase pw1 600 >/dev/null; s1=$(snap 0); kill9 0; start 0 "$BIN" $R; sync_to 0
    ck "encrypt: kill -9 while unlocked: balances identical" "$(snap 0 | sed 's/txs=.*//')" "$(printf %s "$s1" | sed 's/txs=.*//')"
    r=$(zsend 0 "$zs" "[{\"address\":\"$d\",\"amount\":0.1}]"); printf %s "$r" | grep -Eqi 'passphrase|locked|unlock' && pass "encrypt: still locked after kill -9" || bad "encrypt: after kill -9: $r"
    ckerr "encrypt: change passphrase with the wrong old one" 'incorrect|passphrase' 0 walletpassphrasechange nope pw2
    cli 0 walletpassphrasechange pw1 pw2 >/dev/null
    ckerr "encrypt: old passphrase rejected" 'incorrect|passphrase' 0 walletpassphrase pw1 60
    cli 0 walletpassphrase pw2 600 >/dev/null
    # lock while a proof is being built: either outcome is fine, value must be conserved
    fund_notes 0 "$zs" 10 1; rec="[{\"address\":\"$d\",\"amount\":9.5}]"; b0=$(zbal 0 "$zs"); op=$(cli 0 z_sendmany "$zs" "$rec" 1 "$FEE"); sleep 0.3; cli 0 walletlock >/dev/null 2>&1
    r=$(wait_op 0 "$op"); obs "walletlock_during_proving" "$(printf %s "$r" | cut -c1-90)"
    case $r in success*) wait_mempool 1 "${r#success }"; mine 1; ck "encrypt: lock mid-proving spent exactly" "$(zbal 0 "$zs")" "$(add "$b0" -9.5 -$FEE)" ;;
        *) mine 1; ck "encrypt: lock mid-proving left balance untouched" "$(zbal 0 "$zs")" "$b0" ;; esac
    cli 0 walletpassphrase pw2 600 >/dev/null; b=$(zbal 0 "$zs"); cli 0 backupwallet encbackup >/dev/null; stop 0
    cp "$SD/export/encbackup" "$SD/node0/wallet.dat.enc"
    fresh 2 || return; stop 2; cp "$SD/export/encbackup" "$SD/node2/regtest/wallet.dat"; start 2 "$BIN" -connect=127.0.0.1:$((BASE + 1)) -rescan; sync_to 2
    ck "encrypt: restored encrypted backup balance" "$(zbal 2 "$zs")" "$b"
    r=$(zsend 2 "$zs" "[{\"address\":\"$d\",\"amount\":0.1}]"); printf %s "$r" | grep -Eqi 'passphrase|locked|unlock' && pass "encrypt: restored backup is locked" || bad "encrypt: restored backup spend without passphrase: $r"
    cli 2 walletpassphrase pw2 600 >/dev/null
    r=$(zsend 2 "$zs" "[{\"address\":\"$d\",\"amount\":0.1}]"); case $r in success*) pass "encrypt: restored backup spends with the passphrase" ;; *) bad "encrypt: restored backup spend: $r" ;; esac
    alive encrypt 2
}

# ----------------------------------------------------------------- interop
# >= 20 varied shielded transactions on a chain that crosses Sapling activation
chk_interop() {
    # Before Sapling a Sprout JoinSplit is PHGR13, which a current binary verifies but
    # cannot create: the miner/peer (a release that still carries libsnark) makes them.
    if [ "$PEER_BIN" = "$BIN" ]; then
        echo "needs a PHGR13-capable miner (--peer-bin <previous release>): the binary under test cannot create PHGR13 proofs" >"$SD/skip"
        return
    fi
    NU_ARGS="-nuparams=5ba81b19:230 -nuparams=76b809bb:240"
    setup2 || return
    TX=$SD/interop_txids; : >"$TX"; rec_tx() { printf '%s %s\n' "$1" "$2" >>"$TX"; }
    sp=$(cli 0 z_getnewaddress sprout); sp2=$(cli 0 z_getnewaddress sprout); ta=$(cli 0 getnewaddress)
    ck "chain before Sapling" "$([ "$(cli 0 getblockcount)" -lt 230 ] && echo yes)" yes
    give_z 0 "$sp" 4 48656c6c6f; rec_tx sprout_shield "$(cli 0 z_listreceivedbyaddress "$sp" | jq -r ".[0].txid")"
    # the peer spends its own Sprout notes with PHGR13 proofs; node 0 verifies them
    msp=$(cli 1 z_getnewaddress sprout); mta=$(cli 1 getnewaddress); cli 1 sendtoaddress "$mta" 5 >/dev/null; cli 1 generate 1 >/dev/null; sync_to 0
    t=$(zconfirm 1 "$mta" "[{\"address\":\"$msp\",\"amount\":3}]"); rec_tx peer_t_to_sprout "$t"; sync_to 0
    t=$(zconfirm 1 "$msp" "[{\"address\":\"$ta\",\"amount\":1}]"); rec_tx sprout_to_t "$t"; sync_to 0
    t=$(zconfirm 1 "$msp" "[{\"address\":\"$sp2\",\"amount\":1}]"); rec_tx sprout_to_sprout "$t"; sync_to 0
    ck "node 0 received the peer's PHGR13 sprout->sprout" "$(zbal 0 "$sp2")" 1.00000000
    r=$(zsend 0 "$sp" "[{\"address\":\"$ta\",\"amount\":1}]")
    ck "node 0 cannot create a PHGR13 spend before Sapling (clear error)" "$(printf %s "$r" | grep -c 'PHGR13 proofs can no longer be created')" 1
    cli 1 generate 135 >/dev/null; sync_to 0
    zs=$(cli 0 z_getnewaddress); zs2=$(cli 0 z_getnewaddress)
    t=$(zconfirm 0 "$sp" "[{\"address\":\"$ta\",\"amount\":0.5}]"); rec_tx sprout_to_t_2 "$t"   # Sprout and Sapling never mix in one z_sendmany: go through a t address
    t=$(zconfirm 0 "$ta" "[{\"address\":\"$zs\",\"amount\":0.9}]"); rec_tx t_to_sapling_after_sprout "$t"
    # sapling shield (coinbase and plain), memo, multi-recipient, multi-note
    ma=$(cli 1 getnewaddress); mz=$(cli 1 z_getnewaddress); cli 1 generate 5 >/dev/null
    op=$(cli 1 z_shieldcoinbase "*" "$mz" 0.0001 2>/dev/null | jq -r .opid); r=$(wait_op 1 "$op"); case $r in success*) rec_tx shieldcoinbase "${r#success }"; cli 1 generate 1 >/dev/null ;; *) bad "shieldcoinbase: $r" ;; esac
    sync_to 0
    cli 1 sendtoaddress "$ma" 20 >/dev/null; cli 1 generate 1 >/dev/null
    r=$(zsend 1 "$ma" "[{\"address\":\"$zs\",\"amount\":5,\"memo\":\"48656c6c6f2053617069\"}]"); rec_tx t_to_sapling_memo "${r#success }"; cli 1 generate 1 >/dev/null
    t=$(zconfirm 1 "$mz" "[{\"address\":\"$zs\",\"amount\":2},{\"address\":\"$zs2\",\"amount\":1},{\"address\":\"$ta\",\"amount\":1}]"); rec_tx sapling_multi_recipient "$t"
    sync_to 0
    t=$(zconfirm 0 "$zs" "[{\"address\":\"$mz\",\"amount\":1.5}]"); rec_tx sapling_z_to_z "$t"
    t=$(zconfirm 0 "$zs" "[{\"address\":\"$ma\",\"amount\":1}]"); rec_tx sapling_z_to_t "$t"
    t=$(zconfirm 0 "$zs" "[{\"address\":\"$mz\",\"amount\":0.1,\"memo\":\"6d656d6f\"},{\"address\":\"$ma\",\"amount\":0.1}]"); rec_tx sapling_mixed_memo "$t"
    fund_notes 0 "$zs2" 12 0.1; cli 1 generate 1 >/dev/null; sync_to 0
    t=$(zconfirm 0 "$zs2" "[{\"address\":\"$mz\",\"amount\":1.1}]"); rec_tx sapling_multi_note_spend "$t"
    mg=$(cli 0 z_mergetoaddress "[\"$zs2\"]" "$zs" 0.0001 0 50); r=$(wait_op 0 "$(printf %s "$mg" | jq -r .opid)"); case $r in success*) rec_tx merge_notes "${r#success }"; wait_mempool 1 "${r#success }"; mine 1 ;; *) bad "merge: $r" ;; esac
    mg=$(cli 0 z_mergetoaddress '["ANY_TADDR"]' "$zs2" 0.0001 50); r=$(wait_op 0 "$(printf %s "$mg" | jq -r .opid)"); case $r in success*) rec_tx merge_t_to_z "${r#success }"; wait_mempool 1 "${r#success }"; mine 1 ;; *) obs "merge_t_to_z" "$r" ;; esac
    for i in 1 2 3 4 5 6; do
        t=$(zconfirm 0 "$zs" "[{\"address\":\"$zs2\",\"amount\":0.0$i}]"); rec_tx "sapling_z_to_z_$i" "$t"
    done
    ck "interop: at least 20 shielded txs recorded" "$([ "$(grep -vc ' none$' "$TX")" -ge 20 ] && echo yes)" yes
    sync_to 0; : >"$SD/interop_rawtx.txt"
    while read -r name txid; do [ -n "$txid" ] && [ "$txid" != none ] || continue
        h=$(cli 1 getrawtransaction "$txid" 0 2>/dev/null); [ -n "$h" ] || { bad "getrawtransaction $name $txid"; continue; }
        printf '%s %s %s\n' "$name" "$txid" "$h" >>"$SD/interop_rawtx.txt"
    done <"$TX"
    ck "interop: raw tx lines" "$(wc -l <"$SD/interop_rawtx.txt" | tr -d ' ')" "$(grep -vc ' none$' "$TX")"
    ck "interop: verifychain on the producing node" "$(cli 0 verifychain 4 0)" true
    echo "$(cli 1 getblockcount) $(cli 1 getbestblockhash)" >"$SD/interop_tip.txt"
    obs "interop_tip" "$(cat "$SD/interop_tip.txt")"
    alive interop
}

run_chk() {
    id=$1; fn=$2
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$id,"*) ;; *) return 0 ;; esac; fi
    SCN_ID=$id; SCN_LOG=$WORK/chk_$id.log; SD=$WORK/s$id; : >"$SCN_LOG"
    rm -rf "$SD"; mkdir -p "$SD"
    say "== $id"
    t0=$(now); ( $fn ) 2>&1 | tee "$WORK/chk_$id.out" >/dev/null; stop_all
    np=$(grep -c '^PASS' "$SCN_LOG"); nf=$(grep -c '^FAIL' "$SCN_LOG")
    st=PASS; [ "$nf" = 0 ] && [ "$np" -gt 0 ] || st=FAIL
    # a check that cannot run with the given binaries says why in $SD/skip
    if [ -f "$SD/skip" ] && [ "$nf" = 0 ]; then st="SKIP ($(cat "$SD/skip"))"; fi
    echo "$id|$st|$np pass $nf fail|$(elapsed "$t0")s" >>"$RESULTS"; say "   -> $st ($np pass, $nf fail)"
    BASE=$((BASE + 17)); [ $BASE -lt 60000 ] || BASE=20000
}
run_chk timing chk_timing
run_chk concurrent chk_concurrent
run_chk merge chk_merge
run_chk kill chk_kill
run_chk paths chk_paths
run_chk encrypt chk_encrypt
run_chk interop chk_interop
say; say "check|result|asserts|time"; cat "$RESULTS"
! grep -q '|FAIL|' "$RESULTS"
