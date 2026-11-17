# src/c23/services: the wallet token guard

ZSLP tokens are SLP Token Type 1 messages on the ZClassic chain: an `OP_RETURN`
output whose pushes start with the lokad id `SLP\0`. The token quantities and the
mint baton do not live in that output. They ride on ordinary 546 zatoshi outputs of
the same transaction:

| message | output that carries value |
|---|---|
| GENESIS, MINT | `vout[1]` carries the quantity, `vout[mint_baton_vout]` carries the baton |
| SEND | quantity `i` (0-based) rides on `vout[i+1]`, up to 19 of them |

To the wallet those outputs are plain coins. Before this change `sendtoaddress`,
`sendmany`, `z_sendmany` from a t-addr, `z_mergetoaddress`, `z_shieldcoinbase`,
`fundrawtransaction` and fee selection could all pick one as an ordinary input, and
the tokens were burned without a word. `z_sendmany` takes the smallest outputs first,
so the token dust was the first thing it spent.

The guard is compiled into every wallet build. There is no feature flag: the user who
never turned on a token service is exactly the user who needs it.

## The rule

An output is **token-bearing** when its own transaction carries a parseable SLP
message that assigns a token quantity (zero included) or the mint baton to that vout.

- Structural. No index, no lookups, no network. It does not ask whether the token
  lineage is valid: leaving 546 zatoshi alone is cheap, burning an asset is not.
- Which output may carry the message is not settled (only `vout[0]`, or the first
  `OP_RETURN` at any position). Until the owner decides, the **union** is protected:
  the message is taken from the first output whose script starts with `OP_RETURN`.
  The vout indices in the message are absolute in both readings.
- A token output with quantity zero IS protected, as in Z23: the message still assigns
  the output to the token (a zero-quantity SEND slot, or the vout[1] of a GENESIS or
  MINT of zero), and nothing is gained by spending it.
- A transaction whose `OP_RETURN` is not a valid SLP message is not affected.
- Parsed at most once per wallet transaction, and only if the transaction has an
  `OP_RETURN` output. The result is cached in memory on the `CWalletTx`, keyed by
  txid. Nothing is written to `wallet.dat`; a restart, a rescan or a restore from
  backup recomputes it from the transaction.

This is wallet coin selection only. It is not consensus, not mempool policy, not
relay.

## What changed for callers

| path | behaviour |
|---|---|
| `sendtoaddress`, `sendmany`, `sendfrom`, fee selection (`CWallet::SelectCoins`) | token-bearing outputs are not candidates |
| `z_sendmany` from a t-addr | token-bearing outputs are not gathered |
| `z_mergetoaddress` | token-bearing outputs are not merged |
| `z_shieldcoinbase` | a token-bearing coinbase output is not shielded |
| `fundrawtransaction` | inputs it adds are never token-bearing; a token-bearing input already in the transaction is an error unless `allowtokeninputs` (new optional 2nd argument) is `true` |
| coin control (`CCoinControl`), both "exactly these" and "these plus more" | a selected token-bearing input makes selection fail with an error naming it, unless `fAllowTokenOutputs` is set |
| `listunspent` | every entry gains `"tokenbearing": true|false` (additive, last field) |
| `getbalance`, `z_getbalance`, `z_gettotalbalance`, `listunspent` contents | unchanged: the dust is still listed and still counted |
| `createrawtransaction` + `signrawtransaction` + `sendrawtransaction` | unchanged: see below |
| `lockunspent` | unchanged, and irrelevant: the protection is not a lock and cannot be unlocked |

When funds run short and token dust was left out, the error says so, for example:

    Insufficient funds (2 token-bearing outputs holding 0.00001092 are protected and
    were not used: spending them as ordinary funds would burn the ZSLP tokens or mint
    baton they carry)

### Explicitly chosen inputs

- **Coin control and `fundrawtransaction` preset inputs: refused by default,
  allowed with an explicit flag.** Here the wallet builds the transaction, so it is
  the wallet that would burn the tokens, and a caller who lists a 546 zatoshi output
  among its inputs most likely took it for dust. Refusing (rather than dropping the
  input silently) keeps "every selected input is in the transaction" true. The flag
  only admits the inputs that were named; whatever the wallet adds is still ordinary.
- **`createrawtransaction` + `signrawtransaction`: allowed, unchanged.** This is the
  only way to move a token at all (a SEND must spend the token output), the caller
  names every input and every output, and `signrawtransaction` also signs for inputs
  the wallet does not own, so it cannot judge the transaction. A refusal there would
  freeze every token held by a zclassicd key. `listunspent` now shows which outputs
  are token-bearing, which is the warning this path gets.

`fundrawtransaction` inserts its change output at a random position. A token transfer
needs its `OP_RETURN` at `vout[0]` and its token outputs right after, so do not use
`fundrawtransaction` to fund one, with or without `allowtokeninputs`: add the fee
input and the change yourself, as `qa/rpc-tests/wallet_tokenguard.sh` does.

## Layout

```
vendor/     VERBATIM Z23 files at the pin in Z23_SOURCE.tsv. Never edit.
            Z23 relative paths are preserved.
              contexts/market/modules/zslp/{include/zslp/slp.h,src/slp.c}
              engine/modules/overlay/{include/overlay/overlay_codec.h,src/overlay_codec.c}
              core/modules/script/include/script/op_return_push.h
glue/       zclassicd-owned.
              zcl_token_guard.{h,c}     the C seam the wallet calls
              core/uint256.h            32-byte container
              primitives/transaction.h  the thinnest struct transaction that
                                        slp_classify_tx_output compiles against
              util/log_macros.h         LOG_* that compile as gnu11 and print nothing
tools/      check-vendor.sh, revendor.sh, vendor-files.txt,
            z23-vector-check.sh, z23_vector_shim.h, slpscript.c
Z23_SOURCE.tsv   one row per vendored file: zclassicd path, Z23 path, git blob,
                 Z23 commit, core/MANIFEST.sha3 SHA3-256 (or "unsealed")
LICENSE.z23, NOTICE
```

The layout and the manifest follow `src/c23` on branch `integration/c23-rust-removal`
(the C23 crypto core). This directory is self-contained so the two can merge without
touching each other's manifest.

## Build

`libzcl_tokenguard.a` (see `src/Makefile.am`) is plain C, compiled with `-std=gnu11`
and no `-march` flag, and is part of `$(LIBBITCOIN_WALLET)`: every target that links
the wallet links it.

The vendored `slp.c` includes `primitives/transaction.h`, a name zclassicd already
uses for a C++ header. The glue directory is therefore passed with `-iquote`, which
is searched before automake's `-I.`, and only to this C library. C++ code includes
`c23/services/glue/zcl_token_guard.h` by path and sees nothing else from here.

## Proofs and how to re-run them

```sh
# vendored bytes are the pinned Z23 bytes (Z23_REPO additionally asks Z23 itself)
Z23_REPO=<z23-repo> sh src/c23/services/tools/check-vendor.sh

# Z23's own SLP tests and its frozen reference parser, against the vendored copy
sh src/c23/services/tools/z23-vector-check.sh <cc> <z23-repo> [-std=gnu11]

# wallet unit tests
src/zcash-gtest --gtest_filter='TokenGuard*'

# regtest end to end, with the unguarded baseline as control
BASELINE_SRC=<dir-of-unguarded-build>/src sh qa/rpc-tests/wallet_tokenguard.sh
```

`qa/rpc-tests/wallet_tokenguard.sh` is a shell script, not a `test_framework` test,
because the framework needs Python 2.

## Re-vendoring

```sh
sh src/c23/services/tools/revendor.sh <z23-repo> <commit>   # rewrites vendor/ and Z23_SOURCE.tsv
sh src/c23/services/tools/check-vendor.sh                   # must print OK
```

Then re-run every proof above. Re-vendoring is a deliberate act: the parser decides
which of a user's outputs the wallet refuses to spend.
