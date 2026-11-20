# src/zslp: ZSLP token index and builders

The read-only ZSLP token index (SLP Token Type 1 overlay in `OP_RETURN` data), the service that feeds it from connected blocks, and the script and layout builders the wallet uses to create, send, mint and burn tokens.

## What lives here

- `zslpindex.cpp`, `zslpindex.h`: `ZslpIndex` over a `KV` store (`LevelKV` on a `CDBWrapper`, `MemKV` for tests). Each block is one atomic batch with its undo record and the new best block, so a crash leaves the store at a block boundary and a disconnect restores the prior state.
- `zslpservice.cpp`, `zslpservice.h`: `ZslpService` (a `CValidationInterface`), `StartService`, `StopService`, `DefaultStartHeight` (mainnet starts at height 650000).
- `zslpbuild.cpp`, `zslpbuild.h`: `ValidateGenesis`, `BuildGenesisScript`, `BuildMintScript`, `BuildSendScript`, `LayoutSend`, `LayoutBurn`, `LayoutGenesis`, `LayoutMint` and the limits (`TOKEN_DUST`, `MAX_TICKER_LEN`, `MAX_SEND_OUTPUTS`).

The validity rules are Z23's, vendored under `src/c23/services/vendor`; fix a rule in Z23 first and re-vendor.

## Traps

- Nothing here is consensus; code in this directory never rejects a block or touches the coins view or `wallet.dat`.
- Off unless `-zslpindex=1`; the option refuses `-prune`. The index opens its own LevelDB store under the datadir, a third `CDBWrapper` that the LevelDB file-descriptor budget in `src/dbwrapper.cpp` does not count.
- Wallet spends must not burn tokens: `src/wallet/tokenguard.cpp` protects the dust outputs that carry quantities or a baton.
- Shared vectors in `src/test/data` match Z23's copies; do not edit them locally.

## Tests

Boost suites `zslp_tests`, `zslpbuild_tests`; qa scripts `qa/rpc-tests/zslp_index.sh`, `qa/rpc-tests/zslp_send.sh`, `qa/rpc-tests/zslp_send_adversarial.sh`, `qa/rpc-tests/zslp_stale_tip.sh`, `qa/rpc-tests/token_name_rules.sh`; CI step `zslp_index`.

## Related

Rules: [AGENTS.md](AGENTS.md). Design: [doc/zslp.md](../../doc/zslp.md). Names share these rules: [../znam/README.md](../znam/README.md). Facts: `zcutil/bin/zcl-dev know index-atomic-block-batch`.
