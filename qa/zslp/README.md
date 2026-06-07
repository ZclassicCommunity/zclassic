# ZSLP NFT/token live regtest harness

`zslp-nft-regtest.sh` is the committed, repeatable end-to-end test of the ZSLP
write path: the live `zslp_genesis` / `zslp_mint` / `zslp_send` RPCs ->
`BuildAndCommitZSLP` (coin selection -> sign -> CommitTransaction) -> confirm ->
re-read (`zslp_gettoken` / `zslp_listmytokens` / `zslp_listtransfers`). This is
the loop the gtest unit suite explicitly disclaims (it needs a live CWallet,
keystore, chain and mempool); the gtests cover the pure decision pieces, this
covers the real broadcast/confirm path.

## What it proves (each step asserts on-chain evidence)

- NFT genesis: `txid == tokenid`, `decimals 0`, `totalminted 1`,
  `hasmintbaton false`.
- NFT transfer: the genesis token dust (`txid:1`) is pinned into the SEND `vin`
  (decoded from `getrawtransaction`), and the holding address moves.
- Anti-burn vs `sendtoaddress`: the NFT token dust is absent from `listunspent`
  and is never selected as a `vin` of an unrelated ZCL spend.
- Fungible genesis + mint baton, then re-mint (`100 -> 125`).
- 0-conf token-change protection: a concurrent `sendtoaddress` never selects an
  unconfirmed token-change output.
- Self-validate refusals (over-send / unknown token / mint-without-baton), each
  refused **without** broadcasting (mempool unchanged before/after).
- Anti-burn vs shielding (`z_sendmany`), when Sapling is active on the regtest.

Coin ticker in all user-facing strings is **ZCL**.

## Run it

Plain (binaries default to `<repo>/src/zclassicd` and `<repo>/src/zclassic-cli`,
params from `~/.zcash-params`):

```
qa/zslp/zslp-nft-regtest.sh
# or with explicit binaries:
qa/zslp/zslp-nft-regtest.sh /path/to/zclassicd /path/to/zclassic-cli
```

## proot build env (the params gotcha)

Under the unprivileged proot build env, `HOME` is `/root` and
`~/.zcash-params` is **not** auto-bound. Bind it (and `/tmp` for the unique
datadir) and point the script at the in-proot binary paths.

`prun` launches the in-proot command via `env -i` (it wipes the environment to
a fixed whitelist), so `ZCLASSICD=…`-style vars set *outside* `prun` never reach
the script. Pass the binaries as **positional args** and inject
`ZCASH_PARAMS_DIR` *inside* proot with `prun env`:

```
EXTRA_BINDS="-b /home/rhett/.zcash-params:/root/.zcash-params -b /tmp:/tmp" \
  /home/rhett/zclbuild/prun env ZCASH_PARAMS_DIR=/root/.zcash-params \
    bash /src/daemon/qa/zslp/zslp-nft-regtest.sh \
    /build/daemon/src/zclassicd /build/daemon/src/zclassic-cli
```

The harness uses a unique datadir + port per run and always tears the daemon
down and removes the datadir on exit (EXIT/INT/TERM trap), so it is safely
re-runnable and never touches a real node. Exit code `0` = all green.
