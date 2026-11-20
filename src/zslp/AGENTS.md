# zslp and znam agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md). Covers `src/zslp/`, `src/znam/`, `src/rpc/zslp.cpp`, `src/rpc/znam.cpp`, `src/wallet/rpczslp.cpp`, `src/wallet/zslpsend.cpp`. Design: [doc/zslp.md](../../doc/zslp.md), [doc/znam.md](../../doc/znam.md).

- Tokens and names are overlays in `OP_RETURN` data. Nothing here is consensus: these code paths never reject a block or a transaction and never touch the coins view or `wallet.dat`. Everything is off unless `-zslpindex=1` or `-znamindex=1`.
- The validity rules are Z23's, bug for bug; the parsers and validators come verbatim from `src/c23/services/vendor`. Do not re-implement or "improve" a rule here; fix it in Z23 first, then re-vendor ([../c23/AGENTS.md](../c23/AGENTS.md)).
- Each index keeps its own LevelDB store under the datadir (`zslpindex`); every block is one atomic batch with its undo record. Delete an index directory only with the node stopped and only in a datadir you created for a test.
- Wallet token spends must never burn tokens by accident: the token guard protects the dust outputs that carry quantities or a baton ([../wallet/AGENTS.md](../wallet/AGENTS.md)).
- Shared vectors (`src/test/data/token_name_rules.txt`, `zslp_mainnet.json`) match Z23's copies; do not edit them locally.

Tests: `src/test/test_bitcoin --run_test=zslp_tests,zslpbuild_tests,znam_tests`; `sh qa/rpc-tests/zslp_index.sh <dir-with-zclassicd>` and `znam_index.sh`; `zcutil/local-ci.sh --commit <sha> --only zslp_index,wallet_tokenguard,test_bitcoin-full test <outdir>`.
