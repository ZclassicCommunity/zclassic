#!/bin/sh
# Turn a mainnet_crosscheck.sh run into the unit-test fixture src/test/data/zslp_mainnet.json:
# real mainnet SLP transactions (raw hex) of a few small tokens that together show every case
# (valid GENESIS/MINT/SEND, over-spend, wrong token id, mixed tokens, no baton, ordinary-spend burn,
# quantities that do not fit), with the answer the index gave on the full chain.
#
#   KEEP_NODE=1 mainnet_crosscheck.sh <datadir-copy> <bin-dir> <out-dir>      (node stays up)
#   zslp_make_fixtures.sh <out-dir> <zclassic-cli command with its -datadir/-rpc* options...> > zslp_mainnet.json
#   touch <out-dir>/stop                                                        (stops the node)
#
# The answers are the index's own, so this fixture pins what the index says today (and proves it parses
# and applies real bytes); the independent check is the census in doc/zslp.md.
# Needs: jq.
set -eu
OUT=$1; shift
CLI="$*"
MAXN=${MAXN:-16}

TXS=$OUT/txs.jsonl
TOK=$OUT/tokens.json

# per-token summary
SUM=$(jq -s -c --argjson maxn "$MAXN" '
  group_by(.token) | map({
    token: .[0].token, n: length,
    valid: ([.[] | select(.validity == "valid") | .type] | unique),
    reasons: ([.[] | .reason] | unique),
    burn: (any(.[]; .validity == "burn")),
    zero: (any(.[]; .validity == "valid" and (.mintedamount | test("^0(\\.0+)?$")) and (.type != "SEND"))
           or any(.[]; .type == "SEND" and .validity == "valid" and (.outputamount | test("^0(\\.0+)?$"))))
  }) | map(select(.n <= $maxn))' "$TXS")

pick() { # <jq filter on a summary entry>  -> smallest token id passing, else nothing
    printf '%s' "$SUM" | jq -r "[.[] | select($1)] | sort_by(.n, .token) | .[0].token // empty"
}
SEL=""
add() { [ -n "$1" ] && SEL="$SEL $1"; return 0; }
add "$(pick '(.valid | index("GENESIS")) and (.valid | index("MINT")) and (.valid | index("SEND")) and (.reasons | index("valid_mint"))')"
add "$(pick '.reasons | index("send_output_exceeds_input")')"
add "$(pick '.reasons | index("send_ancestry_invalid")')"
add "$(pick '.reasons | index("mixed_token_inputs")')"
add "$(pick '.reasons | index("mint_baton_lineage_invalid")')"
add "$(pick '.reasons | (index("quantity_unrepresentable") or index("output_quantity_overflow") or index("input_quantity_overflow"))')"
add "$(pick '.burn')"
add "$(pick '.zero')"
add "$(pick '(.valid | index("GENESIS")) and (.reasons | index("valid_genesis")) and .n == 1')"
SEL="$SEL ${EXTRA:-}"   # EXTRA: token ids to add (a few with decimals, a document URI, several sends)
SEL=$(printf '%s\n' $SEL | sort -u)

# closure: tokens whose outputs the selected transactions spend
CLOSED=$SEL
for t in $SEL; do
    more=$(jq -r --arg t "$t" 'select(.token == $t) | .inputs[]?.tokenid' "$TXS" | sort -u)
    CLOSED=$(printf '%s\n%s\n' "$CLOSED" "$more" | grep -v '^$' | sort -u)
done

printf '{\n"description": "Real ZClassic mainnet ZSLP transactions (raw hex, in chain order) with the index answer on the full chain",\n'
printf '"census": %s,\n' "$(jq -c '{genesismessages, mintmessages, sendmessages, unrepresentablequantities, overflowingquantities, validtransactions, invalidtransactions, unknowntransactions, burntransactions}' "$OUT/indexinfo.json")"
printf '"tokens": [\n'
first=1
for t in $CLOSED; do
    [ -n "$(jq -r --arg t "$t" 'select(.token == $t) | .txid' "$TXS" | head -1)" ] || continue
    # the transactions of this token, with their block and their position in it
    ROWS=$(jq -r --arg t "$t" 'select(.token == $t) | .txid' "$TXS" | sort -u | while read -r tx; do
        raw=$($CLI getrawtransaction "$tx" 1)
        bh=$(printf '%s' "$raw" | jq -r .blockhash)
        h=$($CLI getblock "$bh" | jq -c --arg tx "$tx" '{height: .height, pos: (.tx | index($tx))}')
        info=$(jq -c --arg tx "$tx" --arg t "$t" 'select(.txid == $tx and .token == $t)' "$TXS" | head -1)
        printf '%s' "$raw" | jq -c --argjson hp "$h" --arg tx "$tx" --argjson info "$info" \
            '{txid: $tx, height: $hp.height, pos: $hp.pos, hex: .hex, type: $info.type, validity: $info.validity, reason: $info.reason}'
    done | jq -s -c 'sort_by(.height, .pos)')
    TOKJ=$(jq -c --arg t "$t" '.[] | select(.tokenid == $t) | {ticker, decimals, totalminted, totalburned, burnedinsends, burnedbyspending, circulating, mintbaton, transactions}' "$TOK")
    HOLD=$($CLI zslp_gettoken "$t" 1000 | jq -c '.holders')
    [ $first = 1 ] || printf ',\n'
    first=0
    printf '{"tokenid": "%s", "token": %s, "holders": %s, "txs": %s}' "$t" "${TOKJ:-null}" "$HOLD" "$ROWS"
done
printf '\n]}\n'
