# TRAPS.md: guardrails for coding agents

**Verify fresh before trusting any line here; this file rots.** Line numbers shift; read 30-50 lines around any reference before acting. Each item is: what not to do, why, where. The live code is the only authority. `zcl-dev guide <path>` prints the section titles that match your paths (a `Paths:` line under each heading drives the match).

## (1) Consensus and chain state

Paths: src/main.cpp src/consensus/ src/chain.cpp src/pow.cpp src/script/ src/zcash/ src/coins.cpp

- **Do not change a rule, checkpoint, activation height or acceptance predicate to fix a bug or a speedup.** zclassicd is the reference and Z23 matches it bug-for-bug; a "cleaner" check forks the chain. Prove any rewrite accept/reject-identical on the same inputs, and fix divergences in both implementations. Where: `src/main.cpp`, `src/consensus/`. Verify fresh: run the differential and golden tests (`src/c23/test/run.sh`) before and after.
- **Do not "fix" the oversize-transaction grandfather table or the pinned Groth16 point-decode quirk.** They reproduce historical chain behaviour. Where: `src/consensus/oversize_grandfather.cpp`, [doc/oversize-grandfather.md](../oversize-grandfather.md), [src/c23/README.md](../../src/c23/README.md) ("Known pinned quirk"). Verify fresh: read both before touching.
- **Do not trust a block-file scan that deserializes cleanly.** A stale or misaligned header can parse into garbage; the record must consume exactly its declared length, else the scan resumes one byte past the magic. Where: `LoadExternalBlockFile` in `src/main.cpp`. Verify fresh: read the comment above the length check.
- **Do not count the 8-byte magic+length header twice for a known block position.** `FindBlockPos(..., fKnown=true)` ends the record at `pos.nPos + nAddSize - 8`; counting twice leaves an 8-byte hole in the file. Where: `FindBlockPos` in `src/main.cpp`.
- **Do not remove `ContextualCheckTransaction`'s IBD early return, or the `isInitBlockDownload() ? 0 : dosLevel` expressions below it.** The function returns true at once while `IsInitialBlockDownload()` holds, which makes those ternaries dead in that state; both reproduce historical behaviour and Z23 copies the gating. Where: `ContextualCheckTransaction` in `src/main.cpp`, its default argument in `src/main.h`. Verify fresh: read the first statement of the function. <!-- claim: symbol-present ContextualCheckTransaction src/main.h -->
- **Do not prove a verifier change by syncing mainnet.** `ConnectBlock` re-runs `CheckBlock` with `ProofVerifier::Disabled()` and skips script checks for every ancestor of the last checkpoint (`fCheckpointsEnabled`, default on), so a sync never re-verifies old proofs or scripts. Use the KAT replay, the PHGR13 gate or `MainnetBlocks` with `ZCL_MAINNET_BLK_FILES`. Where: `ConnectBlock` in `src/main.cpp`, [CONSENSUS_PARITY.md](CONSENSUS_PARITY.md). <!-- claim: symbol-present fCheckpointsEnabled src/main.cpp -->
- **Do not ship a tightening predicate without a full-history replay.** `MAX_TX_SIZE_AFTER_SAPLING` was lowered to 102,000 with no height gate; 413 transactions already in the chain exceeded it and a from-genesis sync stopped at block 478,543 until the grandfather table excused them. Where: `src/consensus/consensus.h`, [doc/oversize-grandfather.md](../oversize-grandfather.md). <!-- claim: symbol-present MAX_TX_SIZE_AFTER_SAPLING src/consensus/consensus.h -->
- **Do not "unify" `MAX_BLOCK_SIZE` and `GENEROUS_BLOCK_SIZE_LIMIT`.** `CheckBlock` and `LoadExternalBlockFile` use the 2,000,000 byte limit; the 200,000 byte `MAX_BLOCK_SIZE` is the miner and `getblocktemplate` default and a sanity bound in `CPartialMerkleTree::ExtractMatches`. Raising the first forks; lowering the second changes policy and merkle proofs. Where: `src/consensus/consensus.h`, `src/main.h` (`DEFAULT_BLOCK_MAX_SIZE`), `src/merkleblock.cpp`. <!-- claim: symbol-present ExtractMatches src/merkleblock.cpp -->
- **Do not trust a green `MainnetBlocks` run on its own.** `src/gtest/test_mainnet_blocks.cpp` does nothing unless `ZCL_MAINNET_BLK_FILES` names block files (the data is not in git), so a filter that selects it passes with zero blocks checked. Where: `ShieldedConsensusChecksAcceptRealBlocks`. <!-- claim: symbol-present ZCL_MAINNET_BLK_FILES src/gtest/test_mainnet_blocks.cpp -->

## (2) Wallet database and locks

Paths: src/wallet/ src/init.cpp doc/wallet-crash-consistency.md

- **Do not assume a committed wallet write is on disk.** The environment opens with `DB_TXN_WRITE_NOSYNC`, so a commit reaches the log buffer, not the platter; durability needs an explicit checkpoint/flush (`CDB::Flush`, `ThreadFlushWalletDB`, shutdown flush). Where: `src/wallet/db.cpp`, `src/wallet/walletdb.cpp`. Verify fresh: [wallet-crash-consistency.md](../wallet-crash-consistency.md) and the `wallet_crash_*` scripts.
- **Do not call `SetBestChain` (or write the checkpoint) holding only `cs_main`.** The whole checkpoint runs under `cs_main` then `cs_wallet`: Berkeley DB has no deadlock detector here, so a notifier-thread write racing the checkpoint waits forever (an `invalidateblock` never returned). Where: `CWallet::SetBestChain` in `src/wallet/wallet.cpp`.
- **Do not take wallet locks out of order.** The order is `cs_main` -> `cs_wallet` -> `mempool.cs`; take `LOCK2(cs_main, cs_wallet)` first. Where: `src/wallet/wallet.cpp` (the re-accept loop locks `mempool.cs` last). Verify fresh: the debug build runs lock-order checks (`DEBUG=1`).
- **Do not copy a live wallet file to back it up.** Backup copies to a temp name with exclusive create and a sync, compares SHA-256 with the source, then renames. Where: `src/wallet/walletdb.cpp` (backup path), `qa/rpc-tests/backupwallet_atomic.sh`.
- **Do not write the witness checkpoint after a disconnect lost witnesses, and never block shutdown on the rebuild.** The flag is memory-only; write nothing and let the next start repair. Where: `CWallet::SetBestChain`.

## (3) C23 core and vendored code

Paths: src/c23/ zcutil/tools/ src/Makefile.am THIRD-PARTY-LICENSES

- **Do not edit anything under a `vendor/` directory.** It is verbatim Z23; the checker fails on a changed blob or an unlisted file. Re-vendor, then check. Where: [src/c23/AGENTS.md](../../src/c23/AGENTS.md), `src/c23/tools/check-vendor.sh`.
- **Do not compile vendored C as C23-only.** Release builds use GCC 9, i.e. gnu17; `nullptr`, `constexpr`, attributes, `typeof` break the release. Where: `src/c23/test/run.sh` defaults `--std gnu17`; `src/c23/tools/build-check.sh`.
- **Do not add an unprefixed global to `libzcl_c23.a`.** It collides with libsodium or OpenSSL at link time. Where: `src/c23/tools/symbol-prefix.sh`, `src/c23/glue/zcl_c23_symbol_prefix.h`.
- **Do not use `%zu` in C built for MinGW without `__USE_MINGW_ANSI_STDIO=1`.** msvcrt printf misreads the arguments that follow. Where: `src/Makefile.am` (`libzcl_c23_a_CPPFLAGS`).
- **Do not remove the Groth16 infinity-flag check from the shim, and do not "fix" the vendored decoder instead.** The vendored Z23 point decode accepts the point at infinity; librustzcash refused a proof with bit 0x40 set in A, B or C, and the shim reproduces that refusal. Where: `proof_has_infinity_flag` in `src/c23/compat/librustzcash_compat.c`. <!-- claim: symbol-present proof_has_infinity_flag src/c23/compat/librustzcash_compat.c -->
- **Do not read a `c23-run-linked` SKIP as a pass.** Without a golden corpus (`ZCL_CI_GOLDEN`, mounted at `/golden`) the step returns 77 and runs nothing; the pre-push hook does not accept it. Where: `t_c23linked` in `zcutil/local-ci.sh`. <!-- claim: symbol-present t_c23linked zcutil/local-ci.sh --> <!-- doc-path-ok -->

## (4) Build, toolchain, release

Paths: zcutil/ depends/ configure.ac Makefile.am src/Makefile.am

- **Do not pass `HOST=` as an argument to `build.sh`.** It is an environment variable: as an argument it reaches only the `make` calls (depends may be built for it) while `configure` still uses `depends/<build triple>`, so you get a host or mixed build, not a cross build. Where: `zcutil/build.sh` (`HOST` defaults to `BUILD`; `DEPS_DIR` uses the shell variable).
- **Do not build a shipped Linux binary on a new host.** Newer glibc raises the symbol floor; the candidate must stay at `GLIBC_2.31`. Use `zcutil/local-ci.sh daemon-linux`. Where: `zcutil/local-ci.sh` (`inner_daemon_linux`).
- **Do not trust a build's exit status behind a pipe.** Check the artifact (footer, floor, `NEEDED`, hash sidecar). Where: [doc/building-quickstart.md](../building-quickstart.md).
- **Do not pass `-Wl,--start-group` to a link that must work on macOS.** Apple's ld64 does not accept it. `src/test/fuzz/build-fuzz.sh` links the fuzz targets with `--start-group ... --end-group` unconditionally, so it only works with GNU ld or lld on Linux; order archives or repeat them instead in portable links. Where: `src/test/fuzz/build-fuzz.sh`. <!-- claim: file-present src/test/fuzz/build-fuzz.sh -->
- **Do not add a line to `src/main.cpp` or `src/net.cpp`, or a branch to `ProcessMessage`, and expect lint to pass.** Both files sit exactly at their `filesize` baseline (`zcutil/lint/filesize.txt`), and `ProcessMessage` sits at its `complexity` and `long-functions` baselines; the ratchets only shrink. Put new message handling in a helper function, in a new file where it fits, and remove at least as much as you add. Where: `zcutil/lint/complexity.txt`, `zcutil/lint/long-functions.txt`. <!-- claim: symbol-present ProcessMessage zcutil/lint/complexity.txt --> <!-- claim: file-present zcutil/lint/filesize.txt -->

## (5) qa scripts and local CI

Paths: qa/ zcutil/local-ci.sh zcutil/local-ci-smoke.sh zcutil/dev/ src/c23/test/

- **Do not derive test ports from the PID.** `$((20000 + ($$ % 20000)))` collides between parallel runs; the failure looks like a random "address in use" or a node that talks to the wrong peer. Take an explicit base. Where: `qa/rpc-tests/wallet_matrix.sh` and others (`git grep -n '\$\$ %' qa`).
- **Do not read wallet state right after a hard kill.** A node killed before its first chainstate flush restarts from height 0; wait for the re-sync from the peer. Where: `qa/rpc-tests/wallet_platform_checks.sh`, `qa/rpc-tests/wallet_reaccept_bound.sh`.
- **Do not use `-testcrashpoint` outside regtest.** It is rejected there; it is the deterministic crash hook. Where: `src/init.cpp`, `src/util.cpp`.
- **Do not weaken a timeout, tolerance or assertion to turn a step green.** Steps have wall-clock limits and a log cap on purpose. Where: `step()` in `zcutil/local-ci.sh`.
- **Do not let host environment leak into the CI rootfs.** `--clearenv` is deliberate (a broker's `TMPDIR` is host-only); pass what a step needs explicitly. Where: `enter()` in `zcutil/local-ci.sh`.
- **Do not run sanitizer steps with full ASLR.** High `mmap` entropy makes the runtime loop on DEADLYSIGNAL; the step runs under `setarch -R`. Where: `noaslr()` in `zcutil/local-ci.sh`.
- **Do not use `ss` (or `nproc`, `sed -i`, `stat -c`, `readlink -f`, `date -d`, `grep -P`, `timeout`) in a qa or tooling script.** They are GNU/Linux-only and fail on macOS and Git Bash; `zcl-lint shellport` flags them. Lease ports through `qa/lib/isolation.sh` instead of probing with `ss` (`qa/rpc-tests/rpc_busy.sh` was moved off `ss` for this reason). Where: `zcutil/lint/rules/shellport.c`. <!-- claim: symbol-present lint_rule_shellport zcutil/lint/rules/shellport.c -->
- **Do not trust a focused test run that ran nothing.** googletest exits 0 when `--gtest_filter` matches no test, and Boost's `--list_content` ignores `--run_test`; `t-fast` fails a gtest run that reports "Running 0 tests" and confirms Boost suites from the `Entering test suite` lines. By hand, read the count. Where: `zcutil/dev/tests/zcl-dev-tests.c`, [TESTING.md](TESTING.md). <!-- claim: file-present zcutil/dev/tests/zcl-dev-tests.c -->
- **Do not assume a Boost case starts from clean globals.** `test_bitcoin` runs every suite in one process; `mapArgs`, the selected chain parameters and the mock time set by one case remain for the next unless the fixture resets them, so a case that passes alone can fail in the full run (or the reverse). Reset what you set (`SetMockTime(0)`, erase the `mapArgs` keys). Where: `BasicTestingSetup` in `src/test/test_bitcoin.cpp`, `mapArgs` in `src/util.h`. <!-- claim: symbol-present BasicTestingSetup src/test/test_bitcoin.cpp -->
- **Do not run `zcl-dev check-tests` on a new test file before `git add`.** It reads tracked files only, so an untracked test is invisible to the gate. Where: [TESTING.md](TESTING.md).

## (6) Wallet GUI, Windows, packaging

Paths: wallet/ zcutil/local-ci-macos.sh

- **Do not run the widget tests on stock Qt for Windows and expect `QMessageBox` to work.** It crashes under the offscreen platform; patched QtWidgets is needed (`KNOWN-CRASH` otherwise). Where: `wallet/tests/run-windows.sh`, `wallet/tests/qt-5.15.2-windows-offscreen.patch`.
- **Do not call `windeployqt` without `--debug` on kits whose release DLLs carry a debug link.** It reads the `.gnu_debuglink` as "debug", skips every plugin and stops with "Unable to find the platform plugin"; `--release` cannot work around it. Where: `wallet/contrib/release/build-windows.sh`, `wallet/docs/BUILDING.md`.
- **Do not change the daemon footer layout in one place.** Three writers and one reader must agree. Where: `wallet/src/embeddeddaemon.cpp` and the scripts under `wallet/contrib/`.
- **Do not rely on the wallet's cleanup to stop the embedded daemon.** A `taskkill /F` or a crash skips it; the Windows job object is the backstop. Where: `wallet/src/daemonjob.h`.

## (7) Bootstrap snapshots

Paths: src/bootstrap.cpp src/bootstrap.h doc/bootstrap-snapshots.md qa/bootstrap-resume/

- **Do not reason about snapshot serving with per-peer quotas alone.** The aggregate serve caps are process-wide and opt-in (default 0 = unlimited); an attacker across many address groups sums past a per-IP quota. Where: `src/bootstrap.cpp` ("S1: process-wide aggregate serve caps"), `src/bootstrap.h`. Verify fresh: read the comment and defaults.

## (8) P2P message handling

Paths: src/main.cpp src/net.cpp src/net.h src/protocol.cpp src/protocol.h src/rpc/net.cpp src/test/

- **Do not format a peer's `CInv` with `ToString()` (or `GetCommand()`) before checking its type.** Deserialization accepts any type number, and both throw `std::out_of_range` for an unknown one. `LogPrint` is an inline function, so its arguments are evaluated even with `-debug=net` off: the `inv` handler's `LogPrint("net", "got inv: %s ...", inv.ToString(), ...)` throws on the first unknown entry, the rest of that `inv` message is dropped, and `ProcessMessages` hands the exception to `PrintExceptionContinue`, which also sets `strMiscWarning`. Guard with `IsKnownType()`. Where: `CInv::GetCommand` in `src/protocol.cpp`, the `inv` branch of `ProcessMessage` in `src/main.cpp`. <!-- claim: symbol-present IsKnownType src/protocol.h -->
- **Do not treat `CNode::fPingQueued` as synchronized.** It is a plain `bool`: the `ping` RPC sets it under `LOCK2(cs_main, cs_vNodes)` while `SendMessages` reads and clears it on the message handler thread without either lock. It is a data race (benign today, flagged by a thread sanitizer); a new cross-thread flag uses `std::atomic` or one common lock. Where: `src/net.h`, `ping` in `src/rpc/net.cpp`, `SendMessages` in `src/main.cpp`. <!-- claim: symbol-present fPingQueued src/net.h --> <!-- claim: symbol-present fPingQueued src/rpc/net.cpp -->
- **Do not expect a header declaration of `ProcessMessage`.** It has external linkage but no prototype in any header; tests either declare it `extern` themselves (`src/test/addrv2_tests.cpp`) or push a `CNetMessage` onto `node->vRecvMsg` and call `ProcessMessages` (`src/test/p2p_message_limits_tests.cpp`). Only the second path exercises the magic, header, checksum and exception handling of `ProcessMessages`; choose it when those matter. <!-- claim: symbol-present vRecvMsg src/test/p2p_message_limits_tests.cpp --> <!-- claim: symbol-present ProcessMessage src/test/addrv2_tests.cpp -->
- **Do not rely on `ProcessMessages` to punish a malformed payload.** Its catch blocks log, send `reject` for a parse failure and continue, with no ban score; a handler that must score malformed input catches `std::ios_base::failure` itself and calls `Misbehaving`, as the bootstrap chunk request handlers do. Where: `ProcessMessages` in `src/main.cpp`.
- **Do not size-check a decoded list before the length cap has done its job.** `vRecv >> vInv` decodes the whole vector before the `MAX_INV_SZ` check; what bounds memory is the 2 MiB `MAX_PROTOCOL_MESSAGE_LENGTH` enforced in `CNode::ReceiveMsgBytes` and the 32 MiB `MAX_SIZE` in `ReadCompactSize`. A new message type that raises either cap reopens allocation attacks. Where: `src/net.cpp`, `src/serialize.h`. <!-- claim: symbol-present ReceiveMsgBytes src/net.cpp -->

## (9) Start-up, shutdown and threads

Paths: src/init.cpp src/shutdownmarker.cpp src/shutdownmarker.h src/util.cpp src/util.h src/timedata.cpp src/sync.h src/sync.cpp

- **Do not fingerprint LevelDB directories after opening them.** Opening a LevelDB database rewrites `CURRENT` and rolls a new `MANIFEST-*` and `.log`, so any digest taken after open differs from the one taken at the last clean stop. `AppInit2` consumes the shutdown marker and runs `ComputeFilesDigest` before any database is opened, and repeats the comparison after a bootstrap import; the snapshot server never opens a served chainstate for the same reason (it reads the tip from its marker instead). Where: `ConsumeCleanMarker` and `ComputeFilesDigest` in `src/shutdownmarker.cpp`, their call sites in `src/init.cpp`, `src/bootstrap.cpp`. <!-- claim: symbol-present ComputeFilesDigest src/init.cpp --> <!-- claim: symbol-present ConsumeCleanMarker src/shutdownmarker.h -->
- **Do not read a non-empty `strMiscWarning` as "a fatal error happened".** `AbortNode` and `PrintExceptionContinue` set it, but so do non-fatal warnings: the clock-offset warning in `src/timedata.cpp`, the abnormal block-rate alert and the obsolete-version notice in `src/main.cpp`. `MaybeWriteCleanShutdownMarker` skips the marker whenever it is non-empty, so any of these (or a malformed peer message, see section 8) makes the next start run the full check. Where: `strMiscWarning` in `src/util.cpp`, `MaybeWriteCleanShutdownMarker` in `src/init.cpp`. <!-- claim: symbol-present strMiscWarning src/timedata.cpp --> <!-- claim: symbol-present MaybeWriteCleanShutdownMarker src/init.cpp -->
- **Do not sleep with `std::this_thread` in a thread-group loop.** Only Boost sleeps and `boost::this_thread::interruption_point()` see `interrupt_all`; `ThreadNotifyRecentlyAdded` sleeps on `std::this_thread::sleep_until` and can delay shutdown by up to a second. Use `MilliSleep`. Where: `src/init.cpp`, `MilliSleep` in `src/utiltime.cpp`. <!-- claim: symbol-present ThreadNotifyRecentlyAdded src/init.cpp -->
- **Do not treat `AssertLockHeld` as a release-build check.** Without `DEBUG_LOCKORDER` (`./configure --enable-debug` defines it) `AssertLockHeldInternal` is an empty inline, so a missing lock is caught only by a debug build. Where: `src/sync.h`, `configure.ac`. <!-- claim: symbol-present AssertLockHeldInternal src/sync.h -->

## (10) Docs, lint and git

Paths: doc/ AGENTS.md zcutil/lint/ zcutil/dev/ zcutil/githooks/

- **Do not put a claim marker inside backticks or a code fence and expect it checked.** `zcl-lint doc-claims` ignores claims in code spans and fences (they are examples); a live claim is a bare HTML comment on one line. Where: `blank_code` in `zcutil/lint/rules/docclaims.c`. <!-- claim: symbol-present blank_code zcutil/lint/rules/docclaims.c -->
- **Do not exempt a backticked path with `doc-path-ok` to hide a typo.** `zcl-lint doc-paths` resolves every backticked path that looks like a repository path; the exemption is for paths outside this tree (Z23 paths, `~/...`). Where: `zcutil/lint/rules/docpaths.c`. <!-- claim: file-present zcutil/lint/rules/docpaths.c --> <!-- doc-path-ok -->
- **Do not treat a pushed receipt as proof of testing.** The pre-push hook trusts `receipts.jsonl` lines that anyone can append; `git push --no-verify` skips it, and git runs no pre-commit hook for a merge or cherry-pick. Re-run the step when it matters. Where: the header of `zcutil/dev/hooks/zcl-dev-hooks.c`.
- **Do not use bare `git stash` in a worktree.** All worktrees of a clone share one stash list, so a `stash pop` can apply another worktree's changes. Use a temporary commit, or a tagged `git stash push -m` applied by its hash.
- **Do not trust a rebase that resolved a conflict until you compare it.** Conflict resolution can drop an added hunk without a message. Compare with `git range-diff` and re-run the focused tests after any rebase or merge.
- **Do not expect `zcl-dev verify` to lint on Windows.** `zcl-lint` is not cross-built, so the lint step reports `UNAVAILABLE` (exit 2) there; run it on a POSIX host before landing. Where: `zcutil/dev/verify/zcl-verify.c`. <!-- claim: symbol-present UNAVAILABLE zcutil/dev/verify/zcl-verify.c -->
