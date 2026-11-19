# daemon wallet agent rules

Imports the root contract: [../../AGENTS.md](../../AGENTS.md). This is the daemon wallet (`wallet.dat`); the Qt GUI is [../../wallet/AGENTS.md](../../wallet/AGENTS.md). Durability design: [doc/wallet-crash-consistency.md](../../doc/wallet-crash-consistency.md).

- Custody: this code holds keys and spends funds. Never spend on a real network, export or log keys, seeds or passphrases, or open a real `wallet.dat` or datadir. Tests use isolated regtest datadirs and leased ports.
- Lock order is `cs_main`, then `cs_wallet`, then `mempool.cs`; take `LOCK2(cs_main, cs_wallet)` together. `SetBestChain` runs entirely under both locks: Berkeley DB has no deadlock detector here.
- Durability: the environment opens with `DB_TXN_WRITE_NOSYNC` (`db.cpp`), so a committed write is in the log buffer, not on disk. Anything that must survive a crash needs the explicit flush path (`CDB::Flush`, `ThreadFlushWalletDB`, the shutdown flush).
- Only cached witness data is ever dropped by start-up reconciliation; never drop a transaction or key to repair state. Do not write the witness checkpoint after a disconnect lost witnesses.
- Back up a wallet only through the existing atomic backup path (temp name, exclusive create, sync, SHA-256 compare, rename); never copy a live file.
- ZSLP spends go through `tokenguard.cpp` and `zslpsend.cpp`; a dust output carrying tokens is protected there. Add no second send path.
- A wallet write changes `wallet.dat` format or timing only with a crash test (`qa/rpc-tests/wallet_crash_*.sh`) in the same change.

Tests: `src/test/test_bitcoin --run_test=wallet_tests,rpc_wallet_tests`; `src/zcash-gtest --gtest_filter=*Wallet*` (cases in `gtest/`); `zcutil/local-ci.sh --commit <sha> --only wallet_matrix-1-9,wallet_tokenguard,wallet_tokenguard-sapling,test_bitcoin-full,zcash-gtest-full test <outdir>`.
