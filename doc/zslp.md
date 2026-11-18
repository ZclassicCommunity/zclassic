# ZSLP tokens: index, send, create, mint, burn

zclassicd can index ZSLP tokens (SLP Token Type 1) and answer questions about them:
which tokens exist, who holds how much, what a transaction did to the tokens. With the
index on, the wallet can also **create, send, mint and burn** tokens
([below](#sending-creating-minting-and-burning)). Tokens and names are an overlay in
`OP_RETURN` data: nothing here is consensus, a node that knows nothing about tokens
relays and mines these transactions as ordinary ones, and `wallet.dat` has no new
record. Everything is **off by default**; with `-zslpindex` off the daemon behaves as it
did before.

The rules that decide whether a token transaction is valid come from Z23, the owner's
C23 ZClassic node, which is also what the ZSLP tokens on mainnet were made with. The
transactions the wallet builds follow the layout Z23's own wallet writes.

## Turn it on

```
zclassicd -zslpindex=1
```

or `zslpindex=1` in `zclassic.conf`. On the first start the index is built from the
chain in a background thread; the node syncs, mines and serves RPC meanwhile.
`zslp_getindexinfo` shows progress. The index lives in `<datadir>/zslpindex` (LevelDB).
Deleting that directory while the node is stopped makes it rebuild from the chain.
Nothing else is touched.

| option | meaning |
|---|---|
| `-zslpindex=<0\|1>` | maintain the index (default 0) |
| `-zslpindexstart=<n>` | first block the index reads (default: the first block with a ZSLP transaction on mainnet, 0 on testnet and regtest) |

Needs the full block files: it is refused together with `-prune`. If a block file has
been pruned away or is damaged the index says so (`error` in `zslp_getindexinfo`) and
waits; it does not guess.

With the flag off, the eleven RPC commands below exist and answer
`The ZSLP token index is disabled...`; the daemon does nothing else differently, and no
`zslpindex` directory is created. The GUI (`wallet/`) shows a **Tokens** view only when
the daemon reports the index as enabled.

## What is indexed

Every connected block. For each transaction the index looks at the first output whose
script starts with `OP_RETURN` (on mainnet that is always `vout[0]`; the wallet's token
guard reads the same output) and parses it with Z23's own SLP parser:

| message | token outputs |
|---|---|
| GENESIS | `vout[1]` carries the initial quantity, `vout[mint_baton_vout]` the mint baton |
| MINT | `vout[1]` the new quantity, `vout[mint_baton_vout]` the new baton |
| SEND | quantity `i` rides on `vout[i+1]` (up to 19) |

A message is **valid** by Z23's rules (`zslp_validity.c`), reason codes included:

- GENESIS: the outputs it names exist. A quantity above 2^63-1 is *unknown*
  (`quantity_unrepresentable`), not valid, and creates no token.
- MINT: exactly one unspent mint baton of that token among the inputs, no invalid or
  unknown parent of the same token.
- SEND: at least one input token of that token, none of another token, every nonzero
  output exists, and the outputs add up to no more than the inputs. The difference is
  burned. The sums are exact 64-bit integers; a sum above 2^64-1 is invalid
  (`output_quantity_overflow`), above 2^63-1 unknown.
- Any other transaction that spends a token or baton output burns it. Invalid and
  unknown token transactions create no token outputs and burn their token inputs.

Three states: `valid`, `invalid`, `unknown`. `unknown` means the rules cannot decide
(an amount that does not fit a signed 64-bit number, or a parent that is itself
unknown); it is never silently turned into valid or invalid.

Per token: ticker, name, document URI and hash, decimals, genesis height, minted supply,
burned supply (in SENDs, and by spending), circulating supply, the mint baton location.
Per output: token, amount, holder. Per address: token balances. Per transaction: type,
validity, reason, and the token outputs it spent and created.

### Amounts

Always **decimal strings** with the token's decimals (`"1000.00"`, `"9223372036854775807"`),
computed from 64-bit integers. Never floating point, in the daemon or in the GUI.

### Reorgs and crashes

Every block is applied as one atomic LevelDB batch containing the changes, an undo
record and the new best block hash. A crash (including `kill -9`) leaves the index at
a block boundary. A reorg disconnects blocks one at a time by replaying the undo records
and returns the **exact** prior state; the worker compares its own best block with the
active chain on every step, so a missed or coalesced notification, a restart, or a
`-reindex` cannot leave it wrong. (Z23's own overlay tables do not unwind on a reorg;
this index does.)

### Holders

`P2PKH` and `P2PK` outputs are held by the public-key hash, `P2SH` by the script hash
(both shown as ordinary addresses); any other script is shown as `script:<hash160>`.

## RPC reference

All amounts are strings. All commands need `-zslpindex=1`. The first seven only read; the
four that change something are described in the next section.

| command | result |
|---|---|
| `zslp_getindexinfo` | `enabled`, `running`, `synced`, `startheight`, `indexedheight`, `indexedblock`, `chainheight`, `progress` (0..1), `error`, `tokens`, `validtransactions`, `invalidtransactions`, `unknowntransactions`, `burntransactions`, `unspentoutputs`, `genesismessages`, `mintmessages`, `sendmessages` (every parsed SLP message, valid or not), `unrepresentablequantities` (unknown: a quantity or sum above 2^63-1), `overflowingquantities` (invalid: a sum above 2^64-1) |
| `zslp_listtokens ( skip count )` | array of token objects ordered by token id (count 1..1000, default 100) |
| `zslp_gettoken "tokenid" ( holders )` | one token: `tokenid`, `ticker`, `name`, `decimals`, `documenturi`, `documenthash`, `genesisheight`, `totalminted`, `totalburned`, `burnedinsends`, `burnedbyspending`, `circulating`, `supplyoverflow`, `mintbaton`, `transactions`, and up to `holders` (max 1000) `{address, amount}` |
| `zslp_listtransactions "tokenid" ( skip count )` | the SLP transactions that name a token, valid or not, oldest first: `[{txid, height, type, validity}]` (count 1..1000, default 100) |
| `zslp_getbalances "address"` | `{address, synced, balances:[{tokenid, ticker, decimals, amount}]}` |
| `zslp_gettransaction "txid"` | `type` (GENESIS, MINT, SEND, or NONE for an ordinary transaction that burned tokens), `validity` (`valid`, `invalid`, `unknown`, `burn`), `reason`, `tokenid`, `height`, `inputamount`, `outputamount`, `mintedamount`, `burnedamount`, `inputs`, `outputs` |
| `zslp_listunspent ( minconf )` | the wallet's token outputs and batons: `{synced, outputs:[{txid, vout, address, tokenid, ticker, decimals, role, amount, confirmations, protected}], balances:[...]}` |

The token id is the GENESIS txid. The three existing token-guard behaviours are
unchanged: `listunspent` marks token outputs `tokenbearing`, and the wallet never uses
them as ordinary funds (see `src/c23/services/README.md`).

## Sending, creating, minting and burning

| command | what it does |
|---|---|
| `zslp_send "tokenid" [{"address":"t1..","amount":"1.50"},...] ( minconf fee dryrun )` | send to one or more transparent addresses; the token change returns to the address of the first token input |
| `zslp_genesis {"ticker","name","decimals","initialquantity", "documenturl", "documenthash", "batonaddress", "address", "fee", "dryrun"}` | create a token; the token id is the txid of this transaction. `batonaddress` absent: the baton goes to a fresh wallet address; `null`: **no baton**, the supply is fixed for good |
| `zslp_mint "tokenid" "amount" ( "batonaddress"\|null {"address","minconf","fee","dryrun"} )` | mint more; spends the wallet's baton and writes a new one at the old baton's address (or the one named; `null` closes the supply) |
| `zslp_burn "tokenid" "amount" confirm ( {"minconf","fee","dryrun"} )` | the **only** way this wallet destroys tokens; `confirm` must be `true` (a dry run does not need it) |

All four need the index on **and at the chain tip** (the index decides which outputs are
valid tokens), an unlocked wallet (the usual `walletpassphrase` error otherwise) and a
transparent wallet address; they refuse a z-address with a message that says why. Each
answers `{txid, tokenid, type, broadcast, amount, tokeninputs, fee, ...}` plus
`tokenchange`/`changeaddress`/`burned` where they apply and, for a dry run, the signed `hex`.
`dryrun=true` builds, signs and judges the transaction and returns it **without broadcasting
it or changing anything**; the GUI uses it to show the exact fee before the user confirms.

**Amounts** are decimal *strings* with at most the token's decimals (`"12.5"`, `"7"`), parsed
exactly into 64-bit base units: no floating point anywhere, nothing is rounded, a sign, an
exponent, a JSON number, `.5`, more decimals than the token has, zero, a value of 2^63 or more
(the token rules treat it as unknown) and any overflow are refused with a message. `fee` is
a ZCL amount (number or string) and must still meet the relay minimum.

### The transaction

```
vout[0]      OP_RETURN <SLP message>, value 0
vout[1..n]   token outputs, 546 zatoshi each (more if -minrelaytxfee makes 546 dust)
               GENESIS  vout[1] the initial quantity, vout[2] the mint baton (optional)
               MINT     vout[1] the new quantity,     vout[2] the new baton (optional)
               SEND     recipients in the order given, then the token change
vout[n+1]    the ZCL change, LAST (a token output is named by its position, so it must not shift)
```

This is Z23's layout (`contexts/market/services/src/zslp_command_service.c`: OP_RETURN at
vout[0], dust 546, token change to the first token input's address, baton at vout[2], the
SLP messages from the same builder) and the SLP Token Type 1 layout. The message bytes are
made by the vendored Z23 builders, never by new encoding code. A SEND carries 1 to 19
outputs including the change; more is refused, not split.

**Which coins.** Token inputs are this wallet's own outputs that the index lists as valid,
unspent, confirmed (`minconf` at least 1) outputs of that one token; a mint baton only for a
`zslp_mint`. Z23 spends only confirmed token outputs too, so a token output that is still in
the mempool (the change of a send in the same block, tokens just received) is **not** spent
until it has a confirmation: a second send needs the first one confirmed, or other confirmed
outputs. The ZCL for the fee and the dust outputs comes from ordinary coins through the
existing token guard; no other token's output and no baton can be taken as fee. A wallet with
tokens and no ordinary ZCL gets "not enough ordinary ZCL", not a burned token.

**Checked before anything is broadcast.** The signed transaction goes through the index's own
validity rules (`ZslpIndex::EvaluateTx`, the same rule function that indexes blocks) and must
be VALID, name the expected token, spend exactly the chosen token outputs and nothing else
the index knows, carry exactly the planned quantities, burn exactly what was asked (nothing,
except for `zslp_burn`), keep its first outputs byte for byte as planned with the ZCL change
last, and pass `IsStandardTx` (the data-carrier size limit included). Otherwise it is refused
with a message and nothing is sent. A full `zslp_burn` of the selected outputs sends `[0]`
and puts a real dust output in vout[1], because the wallet token guard protects every output
a message names, zero quantity included, and the ZCL change must not land there.

**Rules the creation keeps from Z23:** ticker 1-10 letters or digits, name 1-64 characters
(letters, digits, space and `- _ . /`), decimals 0-8, a positive first supply of at most
2,100,000,000,000,000 base units. Extra, beyond what Z23's wallet writes: an optional
document URL (visible ASCII, 255 bytes) and hash, no baton, and a baton or token address of
your choice.

## GUI

When the daemon reports the index as enabled, the wallet shows a **Tokens** button in the
left rail. It opens a window with the wallet's token balances and token outputs, the index
status, and a plain statement that those coins are protected from ordinary spending. From it:

- **Send tokens...** picks a token, a recipient and an amount (the token's decimals, a Max
  button), then a **review** page that shows what will happen, built from a daemon dry run:
  the exact ZCL fee, the token change that returns to you and where, that the recipient's
  output carries 0.00000546 ZCL taken from your ZCL, and that sending cannot be undone. Only
  then does **Send tokens** broadcast, and a result page shows the transaction id.
- **Create token... (advanced)** explains what a token and a mint baton are, takes the ticker,
  name, decimals, first supply and optional document, and goes through the same review and
  confirm steps.

Both buttons are enabled only when the index is at the tip; locked-wallet, missing-ZCL and
not-enough-tokens errors are shown in plain words with the daemon's message. The ZCL send
flow is not touched. With the index off the button is not there.

## Provenance, in three layers

| layer | what | where |
|---|---|---|
| **verbatim Z23** | the SLP wire parser and its codec, byte-identical, hashes pinned | `src/c23/services/vendor/**`, `Z23_SOURCE.tsv` |
| **glue (C)** | `zcl_slp_parse_message` forwards to the vendored parser. `zcl_slp_evaluate` carries the *decision rules* of Z23's `contexts/market/models/src/zslp_validity.c` (`validity_inputs_total`, `validity_validate_genesis/_mint/_send`, `validate_message`) with the SQLite reads and writes taken out; the reason strings are Z23's. This is a port, not a copy: Z23's file is welded to its SQL tables and cannot be vendored as it is | `src/c23/services/glue/zcl_slp_index.{h,c}` |
| **new C++** | the store, the per-block undo, the chain follower, the RPC; for sending: exact amount parsing, Z23's creation rules, the output order, the dry run (`ZslpIndex::EvaluateTx`), the wallet side (input choice, build, check, commit), the four RPCs, the GUI | `src/zslp/` (`zslpbuild.*`, `zslpindex.*`), `src/wallet/zslpsend.*`, `src/wallet/rpczslp.cpp`, `src/rpc/zslp.cpp`, `wallet/src/tokens*.{h,cpp}` |

Nothing new was vendored for sending: the message builders (`slp_build_genesis`, `_mint`,
`_send`) are in the `slp.c` that was already vendored and are reached through
`zcl_token_guard_build_*`. Z23's *transaction* construction (`zslp_command_service.c`) is welded to
its wallet and to its `struct wallet_tx`, so it is re-expressed in C++ on this wallet's
`CreateTransaction`, with its layout, dust value, change rule and confirmed-inputs rule kept;
the builder is checked against 8 real mainnet GENESIS, 2 MINT and 8 SEND transactions (the
message rebuilt from its parsed fields is byte for byte the one on the chain). The only edits to
existing wallet code are two off-by-default `CCoinControl` fields (`fChangeLast`, `nFixedFee`)
and the few lines of `CreateTransaction` that read them.

Differences from Z23 that are on purpose: the ancestry walk (depth 256, 1024
transactions) is not needed because blocks are applied in order and every parent is
settled before its child; and a spend by an *ordinary* transaction is recorded as a burn
and counted. Z23's input limit does apply: an SLP transaction with more than 4096 inputs
is `unknown` (`input_limit_exceeded`), as in Z23, so the two give the same answer.

A holder balance is exact even above 2^64-1 (possible only for a token whose supply
overflowed, `supplyoverflow`); the RPC shows it saturated at 2^64-1 base units.

Licence: Z23 files are Apache-2.0 (`src/c23/services/NOTICE`, `LICENSE.z23`); the rest is
MIT as zclassicd.

## Limits

- Token Type 1 only. NFT types (65, 129), ZNAM and messaging are not indexed.
- Transparent outputs only. Shielded transactions never carry ZSLP tokens.
- Sending, minting and burning use only **confirmed** token outputs of the wallet; a token
  output that is still unconfirmed waits for one confirmation (Z23's rule). One transaction
  per call, one token per transaction, at most 19 token outputs; a payment to many more
  addresses is several calls.
- No coin control for tokens (which output to spend), no NFT types, no document-hash or
  baton editing after creation, no shielded tokens.
- `-minrelaytxfee` above the default raises the token dust value with the node's own dust
  threshold, so that the outputs relay; at the default it is Z23's 546 zatoshi.
- Not compatible with `-prune`.
- The index trusts the node's own chain. It is a convenience view, not a proof: verify a
  token that matters against the chain.
- If a message is not at the first `OP_RETURN` output the answer follows that output;
  Z23's wallet code reads `vout[0]`. On mainnet the two are the same.

## Mainnet check

Measured on a copy of a full-history mainnet datadir (3,322,991 blocks, the copy had no peers
and no wallet) with `qa/zslp/mainnet_crosscheck.sh`:

| | |
|---|---|
| build from block 0 | 330 s (about 10,000 blocks/s, on a shared build host) |
| build from block 650,000 (the default) | 150 s; identical counters, tokens and transactions |
| size of `<datadir>/zslpindex` | 15 MB |
| SLP messages | 874 GENESIS, 34 MINT, 3,394 SEND = **4,302**, the same numbers as the census of the chain made before this work |
| valid / invalid / unknown | 4,273 / 0 / 29 |
| unknown | all 29 are `quantity_unrepresentable`: a quantity or sum of 2^63 or more (21 GENESIS, 8 SEND). That is the 29 transactions the census found with a quantity of 2^63 or more |
| zero-quantity messages | 2 (one GENESIS and one MINT of 0 units), both valid, as in the census |
| tokens (valid GENESIS) | 853 (the 21 other GENESIS are unknown, so they make no token) |
| ordinary transactions that burned token outputs | 56 |
| unspent token and baton outputs | 3,849 |
| first ZSLP message | block 652,947, a GENESIS |

There is no invalid ZSLP transaction on mainnet under these rules. Z23's own answer for
the same tokens could not be compared: the Z23 node reachable for this work had no ZSLP
rows (its `zslp_listtokens` returns an empty list), so the comparison is with the counts
of the chain, not with another implementation. `src/test/data/zslp_mainnet.json` pins real
transactions of eight tokens and what the index answered on the whole chain.

## Tests

```
make -C src test/test_bitcoin && src/test/test_bitcoin --run_test=zslp_tests    # rules, undo, atomicity, 2^63
sh qa/rpc-tests/zslp_index.sh src                                               # regtest end to end
BASELINE_SRC=<unmodified build dir> sh qa/rpc-tests/zslp_index.sh src           # also: flag-off RPC list
cd wallet/tests && qmake tokens.pro && make && QT_QPA_PLATFORM=offscreen ./tst_tokens   # GUI logic
cd wallet/tests && qmake tokenssend.pro && make && QT_QPA_PLATFORM=offscreen ./tst_tokenssend   # amounts, wording, both dialogs
src/test/test_bitcoin --run_test=zslpbuild_tests                                 # amounts, layout, mainnet messages, 120 varied transactions
sh qa/rpc-tests/zslp_send.sh src                                                 # regtest, three nodes, 138 checks
PEER_BIN=<dir of an older zclassicd> sh qa/rpc-tests/zslp_send.sh src            # the miner and relay know nothing about tokens
```

`zslp_send.sh` makes 66 token transactions (genesis with and without a baton, nine tokens of
0 to 8 decimals, mints, single, 3- and 18-recipient sends, a send of everything a wallet
holds, burns, a reorg, a restart, refusals) and requires exact token and ZCL balances after
every step, identical answers from three nodes' indexes, no invalid, unknown or burning
transaction at the end, the message bytes equal to the vendored Z23 builder's, and the whole
chain judged again by `src/c23/services/tools/slpverify.c`: a second implementation of the
block and transaction parser, the ledger and the per-transaction results around the vendored
rule function (`zcl_slp_evaluate`, the port of Z23's decision rules), compared with the
wallets' unspent token outputs and the index's totals. It is the vendored rule function, not
Z23's SQL-bound `zslp_validity.c`, that judges; see "Provenance".

`-zslpindexdelayms=<n>` (hidden, test aid only) slows the worker so a test can
interrupt it mid-build.
